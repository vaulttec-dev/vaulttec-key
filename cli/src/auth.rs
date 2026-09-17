//! `vkey auth`: `sudo` and the lock screen with a tap on the key, through `pam_exec`.
//!
//! ```text
//! sudo vkey auth enable     once: a secret on the key, its public key here, PAM told
//! vkey auth                 what PAM runs at every login
//! sudo vkey auth disable    all of it undone
//! ```
//!
//! The scheme of `pam_u2f`. The key holds an Ed25519 seed that never leaves it; this
//! host keeps only the public key, in `/etc/vkey/auth/<user>`, readable by anyone and
//! writable by root. A login sends a fresh random challenge, the key signs it after a
//! tap, and the signature is checked here. Nothing is written at login, so `sudo`,
//! which runs this as root, and a lock screen running as the user read the same file.
//! The key answers without its PIN - the seed is sealed under the chip key alone - so
//! the tap on this board is the whole proof. Anything that goes wrong is a refusal, and
//! PAM asks for the password as it always did.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::device::{
    AUTH_CHALLENGE_LEN, AUTH_SECRET_LEN, AUTH_SIGNATURE_LEN, AUTH_SIGNED_PREFIX, Device, Error,
    Kind,
};
use crate::prompt::with_unlock;

/// What an auth entry says when someone tries to use it like the others.
pub const USED_BY_AUTH: &str = "this entry answers `vkey auth` logins; it has nothing to show";

const KEY_DIR: &str = "/etc/vkey/auth";
/// Where PAM finds the binary: root's copy, never the user's `~/.local/bin`.
const INSTALLED: &str = "/usr/local/bin/vkey";
/// The one line `enable` adds. `sufficient`: a good signature lets the user in, anything
/// else falls through to the password. `seteuid`: under `sudo` the check runs as root,
/// out of reach of whatever runs as the user; for a lock screen that is the user
/// already, it changes nothing.
const PAM_LINE: &str = "auth sufficient pam_exec.so quiet stdout seteuid /usr/local/bin/vkey auth";
/// The PAM services that get the line, when this host has them: `sudo`, and the lock
/// screens of COSMIC, GNOME, KDE, sway and Hyprland.
const SERVICES: [&str; 6] = [
    "sudo",
    "cosmic-greeter",
    "gdm-password",
    "kde",
    "swaylock",
    "hyprlock",
];
/// A copy of each PAM file as it was before `enable` first touched it.
const BEFORE: &str = ".before-vkey";

/// A user's enrolment: the entry on the key, and its public key.
struct Enrolled {
    name: String,
    key: VerifyingKey,
}

impl Enrolled {
    fn path(user: &str) -> PathBuf {
        Path::new(KEY_DIR).join(user)
    }

    fn read(user: &str) -> Result<Enrolled, Error> {
        let path = Self::path(user);
        for p in path.ancestors() {
            root_owned(p)?;
        }
        let text = fs::read_to_string(&path)?;
        let bad = || Error::Value(format!("{} is malformed", path.display()));
        let mut lines = text.lines();
        let (Some(name), Some(key), None) = (lines.next(), lines.next(), lines.next()) else {
            return Err(bad());
        };
        let key: [u8; 32] = HEXLOWER
            .decode(key.as_bytes())
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(bad)?;
        Ok(Enrolled {
            name: name.to_string(),
            key: VerifyingKey::from_bytes(&key).map_err(|_| bad())?,
        })
    }

    fn write(&self, user: &str) -> Result<(), Error> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(KEY_DIR)?;
        let text = format!("{}\n{}\n", self.name, HEXLOWER.encode(self.key.as_bytes()));
        replace_file(&Self::path(user), text.as_bytes(), 0o644)
    }
}

/// What `pam_exec` runs for `PAM_USER`: exit 0 lets the user in.
pub fn verify(port: Option<&str>) -> Result<u8, Error> {
    let user = user_from("PAM_USER", "PAM_USER is not set: this runs from pam_exec")?;
    trusted(&std::env::current_exe()?)?;
    let enrolled = Enrolled::read(&user)?;
    let mut dev = Device::open(port)?;
    let challenge = random()?;
    println!("vkey: tap the key, or wait ten seconds for the password");
    let signature = dev.respond(&enrolled.name, &challenge)?;
    if !verifies(&enrolled.key, &challenge, &signature) {
        return Err(Error::Value("the key's signature does not verify".into()));
    }
    Ok(0)
}

/// Whether `signature` is the key's answer to `challenge`.
pub fn verifies(
    key: &VerifyingKey,
    challenge: &[u8; AUTH_CHALLENGE_LEN],
    signature: &[u8; AUTH_SIGNATURE_LEN],
) -> bool {
    let mut msg = AUTH_SIGNED_PREFIX.to_vec();
    msg.extend_from_slice(challenge);
    key.verify_strict(&msg, &Signature::from_bytes(signature))
        .is_ok()
}

/// `sudo vkey auth enable`: everything a tap-login needs, for the user who ran sudo.
pub fn enable(dev: &mut Device) -> Result<u8, Error> {
    let user = sudo_user()?;
    let name = format!("{user}@{}", hostname()?);
    crate::device::name(&name)?;

    install_self()?;

    // A fresh seed every time: its public key is kept here and the seed forgotten, so
    // one already on the key under this name could not be matched to a public key.
    let seed = Zeroizing::new(random()?);
    let key = SigningKey::from_bytes(&seed).verifying_key();
    with_unlock(dev, |d| d.add(&name, &*seed, Kind::Auth, true))?;
    drop(seed);

    let challenge = random()?;
    eprintln!("tap the key to check it...");
    let signature = dev.respond(&name, &challenge)?;
    if !verifies(&key, &challenge, &signature) {
        return Err(Error::Value(
            "the key's signature does not verify; nothing was enabled".into(),
        ));
    }
    Enrolled { name, key }.write(&user)?;

    let mut armed = Vec::new();
    let mut manual = Vec::new();
    for service in SERVICES {
        let path = Path::new("/etc/pam.d").join(service);
        if !path.exists() {
            continue;
        }
        if add_line(&path)? {
            armed.push(service);
        } else {
            manual.push(path);
        }
    }

    println!("a tap on this key now lets {user} in: {}", armed.join(", "));
    for path in manual {
        println!(
            "{} has no line vkey recognises to put its own above; add it by hand, above the\n\
             line that brings in the password check:\n  {PAM_LINE}",
            path.display()
        );
    }
    println!("without the key, or with no tap for ten seconds, the password works as before");
    Ok(0)
}

/// `sudo vkey auth disable`: the line out of every PAM file, the public key off this host,
/// the secret off the key.
pub fn disable(dev: &mut Device) -> Result<u8, Error> {
    let user = sudo_user()?;
    let name = format!("{user}@{}", hostname()?);
    for service in SERVICES {
        let path = Path::new("/etc/pam.d").join(service);
        if path.exists() {
            remove_line(&path)?;
        }
    }
    match fs::remove_file(Enrolled::path(&user)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    match with_unlock(dev, |d| d.delete(&name)) {
        Ok(()) | Err(Error::NotFound) => {}
        Err(e) => return Err(e),
    }
    println!("disabled: {user} logs in with the password alone, and '{name}' is off the key");
    Ok(0)
}

/// Whether `line` is the one that brings in the password check: `vkey` goes right above
/// it. Debian's `@include common-auth`, and the `include`/`substack` of Fedora and Arch.
fn is_anchor(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["@include", "common-auth"] => true,
        ["auth", "include" | "substack", stack, ..] => matches!(
            *stack,
            "common-auth" | "system-auth" | "password-auth" | "system-login" | "system-local-login"
        ),
        _ => false,
    }
}

/// A line `enable` put there, in this or an earlier form.
fn is_ours(line: &str) -> bool {
    line.contains("pam_exec.so") && line.contains("vkey auth")
}

/// The line added above the anchor, replacing any earlier form of it; the file as it was
/// kept once beside it. False when there is no anchor, and then nothing is written.
fn add_line(path: &Path) -> Result<bool, Error> {
    let text = fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().filter(|l| !is_ours(l)).collect();
    let Some(at) = lines.iter().position(|l| is_anchor(l)) else {
        return Ok(false);
    };
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i == at {
            out.push_str(PAM_LINE);
            out.push('\n');
        }
        out.push_str(line);
        out.push('\n');
    }
    if out != text {
        let mut before = path.as_os_str().to_owned();
        before.push(BEFORE);
        if !Path::new(&before).exists() {
            fs::copy(path, &before)?;
        }
        replace_file(path, out.as_bytes(), 0o644)?;
    }
    Ok(true)
}

fn remove_line(path: &Path) -> Result<(), Error> {
    let text = fs::read_to_string(path)?;
    if !text.lines().any(is_ours) {
        return Ok(());
    }
    let mut out = String::new();
    for line in text.lines().filter(|l| !is_ours(l)) {
        out.push_str(line);
        out.push('\n');
    }
    replace_file(path, out.as_bytes(), 0o644)
}

/// This binary copied to where PAM runs it, unless it already is that copy.
fn install_self() -> Result<(), Error> {
    let me = std::env::current_exe()?;
    if fs::canonicalize(&me)? == Path::new(INSTALLED) {
        return Ok(());
    }
    replace_file(Path::new(INSTALLED), &fs::read(&me)?, 0o755)
}

/// `path` replaced whole: written beside it and renamed over it, so a crash leaves the
/// old file or the new one - for a PAM file, never half of `sudo`'s configuration.
/// The source map in `sources.rs` is written the same way, for the same reason.
pub(crate) fn replace_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), Error> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".vkey-new");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    // The mode given at creation is narrowed by the umask; this is the mode meant.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// The user who ran sudo: the one whose logins the key will answer.
fn sudo_user() -> Result<String, Error> {
    if fs::metadata("/proc/self")?.uid() != 0 {
        return Err(Error::Value("this changes PAM: run it with sudo".into()));
    }
    user_from(
        "SUDO_USER",
        "run it through sudo as the user who logs in, not as root itself",
    )
}

/// A login name out of the environment, safe as a file name: no path, no hidden file.
fn user_from(var: &str, missing: &str) -> Result<String, Error> {
    let user = std::env::var(var).map_err(|_| Error::Value(missing.into()))?;
    let ok = !user.is_empty()
        && !user.starts_with('.')
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(user)
    } else {
        Err(Error::Value(format!(
            "'{user}' is not a login name vkey accepts"
        )))
    }
}

fn hostname() -> Result<String, Error> {
    Ok(fs::read_to_string("/proc/sys/kernel/hostname")?
        .trim()
        .to_string())
}

/// A challenge, or a seed: one random draw of this size.
fn random() -> Result<[u8; AUTH_CHALLENGE_LEN], Error> {
    const _: () = assert!(AUTH_SECRET_LEN == AUTH_CHALLENGE_LEN, "one draw fits both");
    let mut b = [0u8; AUTH_CHALLENGE_LEN];
    getrandom::getrandom(&mut b).map_err(|e| Error::Value(format!("no randomness: {e}")))?;
    Ok(b)
}

/// Owned by root and writable by nobody else.
fn root_owned(path: &Path) -> Result<(), Error> {
    let m = fs::metadata(path)?;
    if m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(Error::Value(format!(
            "{} must belong to root and be writable by root alone",
            path.display()
        )));
    }
    Ok(())
}

/// This binary and every directory above it root's alone: `sudo` runs it as root, and a
/// copy the user can replace would hand root to whatever runs as the user.
fn trusted(exe: &Path) -> Result<(), Error> {
    for p in exe.ancestors() {
        root_owned(p)?;
    }
    Ok(())
}
