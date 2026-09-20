//! The device as a Rust object: the framed protocol over USB-Serial/JTAG.
//!
//! The bytes themselves are defined once, in the firmware crate (`vaultkey_core::wire`),
//! and compiled here too. The same port also carries the firmware's log output, so
//! every read resynchronises on a magic word rather than assuming the next bytes belong
//! to a frame. Nothing here talks to a person; that is main.rs and shell.rs.

use std::fmt;
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serialport::{SerialPort, SerialPortType};
pub use vaultkey_core::item::{Category, Class, FieldKind, VALUE_MAX};
pub use vaultkey_core::oath::{AUTH_SECRET_LEN, Algo, Digits, NAME_MAX, Name, Params};
pub use vaultkey_core::store::MAX_ATTEMPTS;
pub use vaultkey_core::vault::{PASS_MIN, PIN_LEN, Passphrase, Pin};
pub use vaultkey_core::wire::{AUTH_CHALLENGE_LEN, AUTH_SIGNATURE_LEN, AUTH_SIGNED_PREFIX};
use vaultkey_core::wire::{
    BAD_LEN, Cmd, FLAG_REPLACE, Fail, HAS_SECRET, HAS_SEED, MAGIC, OK, REACH_OPEN, REACH_SECRET,
    REACH_SEED, frame_head, scan_magic,
};
pub use vaultkey_core::wire::{BackupHead, PinStatus};
use zeroize::Zeroizing;

use crate::item::Item;

/// How far into an item a request reaches, and therefore what the person at the board
/// has to do. Named here rather than in `wire` so the CLI reads as the person does:
/// "the login needs nothing, the password needs a tap, the seed needs two".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reach {
    /// The PIN alone: logins, URLs, account numbers.
    Open,
    /// A tap: passwords, notes, private keys.
    Secret,
    /// Two taps: the seeds as well - the whole item, as an export needs it.
    Seed,
}

impl Reach {
    const fn wire(self) -> u8 {
        match self {
            Reach::Open => REACH_OPEN,
            Reach::Secret => REACH_SECRET,
            Reach::Seed => REACH_SEED,
        }
    }
}

/// What an item holds, whether or not this request could see it: what exists, never
/// what it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Shape(u8);

impl Shape {
    /// Whether a code can be had from this item.
    #[must_use]
    pub const fn has_seed(self) -> bool {
        self.0 & HAS_SEED != 0
    }

    /// Whether a tap would bring anything back.
    #[must_use]
    pub const fn has_secret(self) -> bool {
        self.0 & HAS_SECRET != 0
    }
}

/// A TOTP code and the period it stays valid for, as returned by the key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Code {
    pub text: String,
    pub period: u8,
}

impl Deref for Code {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl PartialEq<str> for Code {
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for Code {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl PartialEq<String> for Code {
    fn eq(&self, other: &String) -> bool {
        &self.text == other
    }
}

impl PartialEq<Code> for &str {
    fn eq(&self, other: &Code) -> bool {
        *self == other.text
    }
}

impl PartialEq<Code> for String {
    fn eq(&self, other: &Code) -> bool {
        self == &other.text
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NoBoard,
    Permission(String),
    /// Another program holds the port exclusively.
    Busy(String),
    Io(String),
    Timeout,
    /// The user did not confirm. Distinct from a failure: nothing is wrong.
    Refused,
    Locked,
    WrongPin(u8),
    Wiped,
    NoPin,
    PinExists,
    Exists,
    NotFound,
    Full,
    BadArg,
    Incompatible,
    BadBackup,
    /// A status byte outside the protocol, or one that means the device is broken.
    Device(u8),
    Value(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoBoard => write!(f, "no board found - is it plugged in?"),
            Error::Permission(p) => write!(
                f,
                "cannot open {p}: no permission.\n  sudo usermod -aG dialout $USER    # then log out and back in"
            ),
            Error::Busy(p) => write!(
                f,
                "cannot open {p}: another program holds it. ModemManager does this for a while \
                 whenever the board is plugged in; `vkey install` shows the udev rule that stops it"
            ),
            Error::Io(e) | Error::Value(e) => write!(f, "{e}"),
            Error::Timeout => write!(f, "timed out waiting for a response"),
            Error::Refused => write!(f, "refused: the button was not pressed the way this needs"),
            Error::Locked => write!(f, "locked: PIN required"),
            Error::WrongPin(n) => write!(
                f,
                "wrong PIN, {n} attempt{} left",
                if *n == 1 { "" } else { "s" }
            ),
            Error::Wiped => write!(f, "too many wrong PINs - the device wiped all secrets"),
            Error::NoPin => write!(f, "no PIN set yet"),
            Error::PinExists => write!(f, "a PIN already exists"),
            Error::Exists => write!(f, "an entry with that name already exists"),
            Error::NotFound => write!(f, "no such entry"),
            Error::Full => write!(f, "device is full"),
            Error::BadArg => write!(f, "invalid argument"),
            Error::Incompatible => write!(
                f,
                "the vault on this key was written under a different key setup - wipe it and start over"
            ),
            Error::BadBackup => write!(
                f,
                "the passphrase is wrong, or the backup file changed since it was written"
            ),
            Error::Device(c) => match Fail::from_code(*c, &[]) {
                Some(Fail::Internal) => write!(f, "device error"),
                _ if *c == vaultkey_core::wire::BAD_CMD => write!(f, "unknown command"),
                _ if *c == BAD_LEN => write!(f, "bad payload length"),
                _ => write!(f, "error {c:#04x}"),
            },
        }
    }
}

impl From<Fail> for Error {
    fn from(f: Fail) -> Self {
        match f {
            Fail::Refused => Error::Refused,
            Fail::Internal => Error::Device(f.code()),
            Fail::NotFound => Error::NotFound,
            Fail::Full => Error::Full,
            Fail::BadArg => Error::BadArg,
            Fail::Locked => Error::Locked,
            Fail::WrongPin(left) => Error::WrongPin(left),
            Fail::Wiped => Error::Wiped,
            Fail::NoPin => Error::NoPin,
            Fail::PinExists => Error::PinExists,
            Fail::Exists => Error::Exists,
            Fail::Incompatible => Error::Incompatible,
            Fail::BadBackup => Error::BadBackup,
        }
    }
}

impl From<serialport::Error> for Error {
    fn from(e: serialport::Error) -> Self {
        match e.kind {
            serialport::ErrorKind::Io(std::io::ErrorKind::PermissionDenied) => {
                Error::Permission(String::new())
            }
            serialport::ErrorKind::Io(std::io::ErrorKind::ResourceBusy) => {
                Error::Busy(String::new())
            }
            _ => Error::Io(e.to_string()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// Opens a port with `attempt`, waiting out a busy port for a few seconds first:
/// `ModemManager` probes every new serial device and holds it exclusively meanwhile.
/// Errors come back naming `path`.
pub fn open_port<T>(
    path: &str,
    mut attempt: impl FnMut() -> serialport::Result<T>,
) -> Result<T, Error> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match attempt() {
            Ok(p) => return Ok(p),
            Err(e) => {
                let err = Error::from(e);
                if matches!(err, Error::Busy(_)) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(250));
                    continue;
                }
                return Err(match err {
                    Error::Permission(_) => Error::Permission(path.to_string()),
                    Error::Busy(_) => Error::Busy(path.to_string()),
                    other => other,
                });
            }
        }
    }
}

/// One stored item as the device lists it: name and category, no fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub name: String,
    pub category: Category,
}

/// The board's serial port, or None. Never hardcoded: the number changes after a reset.
/// Matching on the USB identity each board folder declares, rather than "first
/// ttyACM", keeps a second serial gadget - a Pico, a modem - from being mistaken for
/// the key.
pub fn find_port() -> Option<String> {
    if let Ok(ports) = serialport::available_ports() {
        for p in &ports {
            if let SerialPortType::UsbPort(u) = &p.port_type
                && crate::boards::BOARDS
                    .iter()
                    .any(|b| b.usb_vid == u.vid && b.usb_pid == u.pid)
            {
                return Some(p.port_name.clone());
            }
        }
    }
    None
}

/// `path` as given, or the board's port by USB identity.
pub fn port_or_find(path: Option<&str>) -> Result<String, Error> {
    match path {
        Some(p) => Ok(p.to_string()),
        None => find_port().ok_or(Error::NoBoard),
    }
}

/// What the firmware accepts as a PIN, checked here first so a typo costs nothing.
pub fn pin(text: &str) -> Result<Pin<'_>, Error> {
    Pin::new(text.as_bytes())
        .ok_or_else(|| Error::Value(format!("PIN must be exactly {PIN_LEN} digits")))
}

/// What the firmware accepts as a backup passphrase, checked here first.
pub fn passphrase(text: &str) -> Result<Passphrase<'_>, Error> {
    Passphrase::new(text.as_bytes()).ok_or_else(|| {
        Error::Value(format!(
            "the passphrase must be at least {PASS_MIN} characters, one line, no control \
             characters - five or six random words, not a password you invented"
        ))
    })
}

/// What the firmware accepts as a name, with the rule spelled out once.
pub fn name(text: &str) -> Result<Name<'_>, Error> {
    Name::new(text.as_bytes()).ok_or_else(|| {
        Error::Value(format!(
            "name must be 1..{NAME_MAX} printable bytes, not starting or ending with a space"
        ))
    })
}

/// What this side insists on for a `.env`: one `KEY=value` per line, nothing else, so a
/// stored `.env` is always the one shape `env $(vkey get ...)` can consume. It is an
/// item like any other now - one secret field - but the shape is still checked here.
pub struct EnvBlob(Zeroizing<Vec<u8>>);

impl EnvBlob {
    /// The one check, at the edge: whatever holds an `EnvBlob` holds a valid one.
    pub fn new(blob: Zeroizing<Vec<u8>>) -> Result<EnvBlob, Error> {
        if blob.is_empty() {
            return Err(Error::Value("the .env is empty".into()));
        }
        if blob.len() > VALUE_MAX {
            return Err(Error::Value(format!(
                "the .env is {} bytes; the limit is {VALUE_MAX}",
                blob.len()
            )));
        }
        let text =
            std::str::from_utf8(&blob).map_err(|_| Error::Value("the .env is not UTF-8".into()))?;
        // Split on LF alone, so a CR or a blank line inside is seen and refused; only
        // the newline that ends the file is forgiven.
        let body = text.strip_suffix('\n').unwrap_or(text);
        for (i, line) in body.split('\n').enumerate() {
            let key = line.split_once('=').map(|(k, _)| k);
            if !key.is_some_and(env_key) || line.chars().any(char::is_whitespace) {
                return Err(Error::Value(format!(
                    "line {}: expected KEY=value with no spaces, tabs or CR, the key of \
                     letters, digits and _ (no comments or blank lines)",
                    i + 1
                )));
            }
        }
        Ok(EnvBlob(blob))
    }

    /// The item a `.env` is stored as: one secret field, behind a tap like a password.
    #[must_use]
    pub fn item(&self) -> Item {
        Item::new(Category::Env).with(crate::item::OwnedField::new(
            Class::Secret,
            FieldKind::String,
            ".env",
            &self.0,
        ))
    }
}

/// A shell-style variable name: letters, digits and `_`, not starting with a digit.
fn env_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A `.env` file, whole, into memory that scrubs itself.
pub fn env_file(path: &Path) -> Result<EnvBlob, Error> {
    let blob = std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| Error::Value(format!("cannot read {}: {e}", path.display())))?;
    EnvBlob::new(blob)
}

/// A login item: the login open, the password and the note behind a tap. What `add`
/// builds, and what an import builds for every row that has a password.
pub fn login_item(login: &str, password: &str, note: &str) -> Result<Item, Error> {
    if password.is_empty() {
        return Err(Error::Value("the password must not be empty".into()));
    }
    if login.chars().any(char::is_control) {
        return Err(Error::Value(
            "the login must not contain control characters".into(),
        ));
    }
    if password.chars().any(char::is_control) {
        return Err(Error::Value(
            "the password must not contain control characters".into(),
        ));
    }
    let mut item = Item::new(Category::Login).with(crate::item::OwnedField::new(
        Class::Secret,
        FieldKind::Concealed,
        "password",
        password.as_bytes(),
    ));
    if !login.is_empty() {
        item.fields.insert(
            0,
            crate::item::OwnedField::new(
                Class::Open,
                FieldKind::String,
                "username",
                login.as_bytes(),
            ),
        );
    }
    if !note.is_empty() {
        item.fields.push(crate::item::OwnedField::new(
            Class::Secret,
            FieldKind::String,
            "notesPlain",
            note.as_bytes(),
        ));
    }
    // Packed once here and thrown away: an item that cannot be stored must be refused
    // where it is built, not half-way through a sync that has already written others.
    item.pack()?;
    Ok(item)
}

/// What the firmware accepts as a name, with the wire's length prefix in front.
fn name_bytes(name: &str) -> Result<Vec<u8>, Error> {
    let raw = self::name(name)?.as_bytes();
    let len = u8::try_from(raw.len()).map_err(|_| Error::BadArg)?;
    let mut v = Vec::with_capacity(raw.len() + 1);
    v.push(len);
    v.extend_from_slice(raw);
    Ok(v)
}

pub struct Device {
    port: Box<dyn SerialPort>,
    pub path: String,
    timeout: Duration,
}

impl Device {
    /// Opens the board; the port is found by USB identity unless given.
    pub fn open(path: Option<&str>) -> Result<Device, Error> {
        let path = port_or_find(path)?;
        let port = open_port(&path, || {
            serialport::new(&path, 115_200)
                .timeout(Duration::from_millis(100))
                .open()
        })?;
        let dev = Device {
            port,
            path,
            timeout: Duration::from_secs(40),
        };
        // The board may be mid-log when we attach; drop whatever is already buffered so
        // the first frame is not read out of a log line.
        std::thread::sleep(Duration::from_millis(200));
        let _ = dev.port.clear(serialport::ClearBuffer::Input);
        Ok(dev)
    }

    /// Firmware version, or None when whatever is on the board does not answer -
    /// a fresh board, or one running something else.
    pub fn probe(&mut self) -> Option<String> {
        let saved = self.timeout;
        self.timeout = Duration::from_secs(2);
        let r = self.info().ok();
        self.timeout = saved;
        r
    }

    fn request(&mut self, cmd: Cmd, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let len = u16::try_from(payload.len()).map_err(|_| Error::BadArg)?;
        let mut frame = Zeroizing::new(Vec::with_capacity(7 + payload.len()));
        frame.extend_from_slice(&frame_head(cmd.wire(), len));
        frame.extend_from_slice(payload);
        self.port.write_all(&frame)?;
        self.port.flush()?;

        let deadline = Instant::now() + self.timeout;
        // Scan for the magic word, byte by byte. Log output on the same port is plain
        // ASCII and cannot contain it.
        let mut matched = 0;
        while matched < MAGIC.len() {
            matched = scan_magic(matched, self.read_byte(deadline)?);
        }
        let status = self.read_byte(deadline)?;
        let len = usize::from(u16::from_le_bytes([
            self.read_byte(deadline)?,
            self.read_byte(deadline)?,
        ]));
        let mut body = Zeroizing::new(vec![0u8; len]);
        self.read_all(&mut body, deadline)?;
        if status == OK {
            return Ok(body);
        }
        Err(Fail::from_code(status, &body).map_or(Error::Device(status), Error::from))
    }

    /// The whole of `buf`, in as few reads as the port delivers it.
    fn read_all(&mut self, buf: &mut [u8], deadline: Instant) -> Result<(), Error> {
        let mut got = 0;
        while got < buf.len() {
            match self.port.read(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e.into()),
            }
            if got < buf.len() && Instant::now() > deadline {
                return Err(Error::Timeout);
            }
        }
        Ok(())
    }

    fn read_byte(&mut self, deadline: Instant) -> Result<u8, Error> {
        let mut b = [0u8; 1];
        self.read_all(&mut b, deadline)?;
        Ok(b[0])
    }

    pub fn info(&mut self) -> Result<String, Error> {
        Ok(String::from_utf8_lossy(&self.request(Cmd::Info, &[])?).into_owned())
    }

    // --- PIN ------------------------------------------------------------------

    pub fn pin_status(&mut self) -> Result<PinStatus, Error> {
        let b = self.request(Cmd::PinStatus, &[])?;
        let b: [u8; PinStatus::WIRE_LEN] = b
            .get(..PinStatus::WIRE_LEN)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Device(BAD_LEN))?;
        Ok(PinStatus::from_wire(b))
    }

    pub fn pin_set(&mut self, pin: Pin<'_>) -> Result<(), Error> {
        self.request(Cmd::PinSet, pin.as_bytes()).map(drop)
    }

    pub fn pin_unlock(&mut self, pin: Pin<'_>) -> Result<(), Error> {
        self.request(Cmd::PinUnlock, pin.as_bytes()).map(drop)
    }

    pub fn pin_change(&mut self, old: Pin<'_>, new: Pin<'_>) -> Result<(), Error> {
        let old = old.as_bytes();
        let mut p = Zeroizing::new(vec![u8::try_from(old.len()).map_err(|_| Error::BadArg)?]);
        p.extend_from_slice(old);
        p.extend_from_slice(new.as_bytes());
        self.request(Cmd::PinChange, &p).map(drop)
    }

    pub fn lock(&mut self) -> Result<(), Error> {
        self.request(Cmd::Lock, &[]).map(drop)
    }

    /// Factory reset. The device waits for the long hold; `Refused` if it never comes.
    pub fn wipe(&mut self) -> Result<(), Error> {
        self.request(Cmd::Wipe, &[]).map(drop)
    }

    // --- entries ---------------------------------------------------------------

    /// A whole item in; the PIN is enough, nothing comes out.
    pub fn put(&mut self, name: &str, item: &Item, replace: bool) -> Result<(), Error> {
        let packed = item.pack()?;
        let mut p = Zeroizing::new(name_bytes(name)?);
        p.push(item.category.wire());
        p.push(if replace { FLAG_REPLACE } else { 0 });
        p.extend_from_slice(&packed);
        self.request(Cmd::ItemPut, &p).map(drop)
    }

    /// The fields of an item that `reach` allows, and the gesture it costs: nothing for
    /// open fields, a tap for secrets, two taps for seeds.
    pub fn get(&mut self, name: &str, reach: Reach) -> Result<Item, Error> {
        self.get_with_shape(name, reach).map(|(item, _)| item)
    }

    /// The same, plus what the item holds beyond this reach: whether there is a secret
    /// and whether there is a seed. Knowing costs no gesture - it is what lets the
    /// shell offer a code for an item that has one and a password for one that does
    /// not, without asking the person to touch the board to find out.
    pub fn get_with_shape(&mut self, name: &str, reach: Reach) -> Result<(Item, Shape), Error> {
        let mut p = name_bytes(name)?;
        p.push(reach.wire());
        let body = self.request(Cmd::ItemGet, &p)?;
        let (&category, rest) = body.split_first().ok_or(Error::Device(BAD_LEN))?;
        let (&present, item) = rest.split_first().ok_or(Error::Device(BAD_LEN))?;
        let _ = Category::from_wire(category).ok_or(Error::Device(BAD_LEN))?;
        Ok((Item::unpack(item)?, Shape(present)))
    }

    /// Every item's name and category. Needs the PIN, like everything else.
    pub fn list(&mut self) -> Result<Vec<Stored>, Error> {
        let body = self.request(Cmd::List, &[])?;
        let mut out = Vec::new();
        let mut rest = body.as_slice();
        while let Some((n, tail)) = rest.split_first() {
            let n = usize::from(*n);
            let Some((name, tail)) = tail.split_at_checked(n) else {
                return Err(Error::Device(BAD_LEN));
            };
            let Some((&category, tail)) = tail.split_first() else {
                return Err(Error::Device(BAD_LEN));
            };
            let category = Category::from_wire(category).ok_or(Error::Device(BAD_LEN))?;
            out.push(Stored {
                name: String::from_utf8_lossy(name).into_owned(),
                category,
            });
            rest = tail;
        }
        Ok(out)
    }

    /// Current code, after the tap. The device has no clock; we send the time.
    pub fn code(&mut self, name: &str, at: Option<u64>) -> Result<Code, Error> {
        let t = at.unwrap_or_else(now);
        let mut p = name_bytes(name)?;
        p.extend_from_slice(&t.to_le_bytes());
        let body = self.request(Cmd::Code, &p)?;
        let (text, period) = if body.len() == 7 || body.len() == 9 {
            let (&period, code) = body.split_last().ok_or(Error::Device(BAD_LEN))?;
            (String::from_utf8_lossy(code).into_owned(), period)
        } else {
            (String::from_utf8_lossy(&body).into_owned(), 30)
        };
        Ok(Code { text, period })
    }

    /// `challenge` signed with the auth secret `name`, after a tap; no PIN needed.
    pub fn respond(
        &mut self,
        name: &str,
        challenge: &[u8; AUTH_CHALLENGE_LEN],
    ) -> Result<[u8; AUTH_SIGNATURE_LEN], Error> {
        let mut p = name_bytes(name)?;
        p.extend_from_slice(challenge);
        let body = self.request(Cmd::Respond, &p)?;
        body.as_slice()
            .try_into()
            .map_err(|_| Error::Device(BAD_LEN))
    }

    pub fn delete(&mut self, name: &str) -> Result<(), Error> {
        let p = name_bytes(name)?;
        self.request(Cmd::Delete, &p).map(drop)
    }

    /// The entry `from`, now called `to`. The key re-seals it itself; nothing comes out.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        let mut p = name_bytes(from)?;
        p.extend_from_slice(&name_bytes(to)?);
        self.request(Cmd::Rename, &p).map(drop)
    }

    // --- backup ----------------------------------------------------------------------

    /// Starts a backup, after two taps: what the device made the key from.
    pub fn export_begin(&mut self, pass: Passphrase<'_>) -> Result<BackupHead, Error> {
        let b = self.request(Cmd::ExportBegin, pass.as_bytes())?;
        let b: [u8; BackupHead::WIRE_LEN] = b
            .get(..BackupHead::WIRE_LEN)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Device(BAD_LEN))?;
        BackupHead::from_wire(b).ok_or(Error::Device(BAD_LEN))
    }

    /// The next sealed item, or None once the backup is complete.
    pub fn export_next(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let item = self.request(Cmd::ExportNext, &[])?;
        Ok((!item.is_empty()).then(|| item.to_vec()))
    }

    /// Starts a restore: the head the backup was written with, and its passphrase.
    pub fn import_begin(&mut self, pass: Passphrase<'_>, head: BackupHead) -> Result<(), Error> {
        let mut p = Zeroizing::new(head.wire().to_vec());
        p.extend_from_slice(pass.as_bytes());
        self.request(Cmd::ImportBegin, &p).map(drop)
    }

    /// One sealed item back in, in the order it came out.
    pub fn import_item(&mut self, item: &[u8]) -> Result<(), Error> {
        self.request(Cmd::ImportItem, item).map(drop)
    }

    /// The restored table written; the restore is over.
    pub fn import_end(&mut self) -> Result<(), Error> {
        self.request(Cmd::ImportEnd, &[]).map(drop)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
