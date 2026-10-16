//! Passkeys: Trussed and fido-authenticator (docs/roadmap.md, phase 6), in the main loop
//! like everything else. A CTAP request reaches `Passkeys::call` through the CTAPHID
//! dispatch, fido-authenticator turns it into Trussed requests, and `Syscall` serves each
//! of those on the spot by running the Trussed service inline: no interrupt, no runtime,
//! no second context.
//!
//! The keys live in Trussed's own littlefs at 0xC8000..0xF4000, apart from the vault and
//! not sealed under the PIN; docs/threat-model.md says what that costs.

use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use cortex_m::peripheral::SCB;
use critical_section::Mutex;
use ctaphid_dispatch::app::{self, App, Command};
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use fido_authenticator::{Authenticator, Config, TrussedRequirements, UserPresence};
use heapless_bytes::BytesView;
use littlefs2::consts::{U1, U256, U512};
use littlefs2::driver::Storage;
use littlefs2::fs::{Allocation, Filesystem};
use littlefs2::object_safe::DynFilesystem;
use littlefs2::{const_ram_storage, io, path};
use static_cell::{ConstStaticCell, StaticCell};
use trussed::backend::BackendId;
use trussed::pipe::{ServiceEndpoint, TrussedChannel};
use trussed::serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl};
use trussed::service::ServiceResources;
use trussed::types::{Context, CoreContext};
use trussed::{ClientImplementation, Platform, Service};
use trussed_core::api::{reply, request};
use trussed_core::types::reboot;
use trussed_core::{Error, InterruptFlag};
use trussed_fs_info::FsInfoExtension;
use trussed_hkdf::HkdfExtension;
use trussed_staging::{StagingBackend, StagingContext};
use vaultkey_core::hal::{Attachment, Clock, Ui};
use vaultkey_core::ui::{self, State};

use crate::{CTAP_MESSAGE, Entropy, FS_LEN, Panel, Region, Uptime, UsbStack};

/// authenticatorReset, the CTAP2 command that erases every passkey.
const AUTHENTICATOR_RESET: u8 = 0x07;

/// How long the hold that approves authenticatorReset lasts: the same five seconds as
/// the vault's wipe, because it is one.
const RESET_HOLD_MS: u64 = 5_000;

/// Trussed's flash: the 4 KiB sectors of `FS_LEN`, read and written in words.
struct Internal(Region);

impl Storage for Internal {
    const READ_SIZE: usize = 4;
    const WRITE_SIZE: usize = 4;
    const BLOCK_SIZE: usize = 4096;
    const BLOCK_COUNT: usize = FS_LEN as usize / 4096;
    /// A metadata block moves on after this many erases, so the files rewritten on every
    /// login - the signature counter, the RNG seed - do not wear one sector out.
    const BLOCK_CYCLES: isize = 500;
    /// Files up to this size sit in their directory's metadata instead of a 4 KiB block
    /// each, so a passkey costs part of its site's directory rather than a block.
    type CACHE_SIZE = U512;
    /// 8 bytes, a bit per block for 64 blocks: more than the 44 there are.
    type LOOKAHEAD_SIZE = U1;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> io::Result<usize> {
        let off = u32::try_from(off).map_err(|_| io::Error::IO)?;
        self.0.read(off, buf).map_err(|_| io::Error::IO)?;
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> io::Result<usize> {
        let off = u32::try_from(off).map_err(|_| io::Error::IO)?;
        self.0.write(off, data).map_err(|_| io::Error::IO)?;
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> io::Result<usize> {
        let from = u32::try_from(off).map_err(|_| io::Error::IO)?;
        let to = u32::try_from(off + len).map_err(|_| io::Error::IO)?;
        self.0.erase(from, to).map_err(|_| io::Error::IO)?;
        Ok(len)
    }
}

// What Trussed keeps only until the next reset - key agreement keys, public keys on
// their way out - in 4 KiB of RAM. littlefs makes no assumption about erased bytes, and
// zero keeps it out of the image.
const_ram_storage!(
    name = Volatile,
    erase_value = 0x00,
    read_size = 4,
    write_size = 4,
    cache_size_ty = U256,
    block_size = 256,
    block_count = 16,
    lookahead_size_ty = U1,
);

static INTERNAL: StaticCell<Internal> = StaticCell::new();
static INTERNAL_ALLOC: StaticCell<Allocation<Internal>> = StaticCell::new();
static INTERNAL_FS: StaticCell<Filesystem<'static, Internal>> = StaticCell::new();
static VOLATILE: ConstStaticCell<Volatile> = ConstStaticCell::new(Volatile::new());
static VOLATILE_ALLOC: StaticCell<Allocation<Volatile>> = StaticCell::new();
static VOLATILE_FS: StaticCell<Filesystem<'static, Volatile>> = StaticCell::new();

/// The filesystems Trussed asks for by location.
#[derive(Clone, Copy)]
struct Store {
    internal: &'static Filesystem<'static, Internal>,
    volatile: &'static Filesystem<'static, Volatile>,
}

impl trussed::store::Store for Store {
    fn ifs(&self) -> &dyn DynFilesystem {
        self.internal
    }

    // There is no external flash on this board. Nothing here asks for it, and whatever
    // would is kept like the rest rather than lost at the next reset.
    fn efs(&self) -> &dyn DynFilesystem {
        self.internal
    }

    fn vfs(&self) -> &dyn DynFilesystem {
        self.volatile
    }
}

/// What Trussed needs from the board: the chip's RNG, the filesystems and a clock.
struct Board {
    rng: Entropy,
    store: Store,
    ui: Clockwork,
}

impl Platform for Board {
    type R = Entropy;
    type S = Store;
    type UI = Clockwork;

    fn rng(&mut self) -> &mut Entropy {
        &mut self.rng
    }

    fn store(&self) -> Store {
        self.store
    }

    fn user_interface(&mut self) -> &mut Clockwork {
        &mut self.ui
    }
}

/// Trussed's user interface, reduced to the clock and the reset. User presence does not
/// go through Trussed: fido-authenticator asks `Touch`, which keeps the vault's rules.
struct Clockwork;

impl trussed::platform::UserInterface for Clockwork {
    fn uptime(&mut self) -> Duration {
        Duration::from_millis(Uptime.now_ms())
    }

    fn reboot(&mut self, _: reboot::To) -> ! {
        SCB::sys_reset()
    }
}

/// The custom backend: trussed-staging, for the two extensions fido-authenticator asks
/// for on top of Trussed's core.
enum Backend {
    Staging,
}

/// Those two extensions, numbered for the trip from client to service.
enum Extension {
    FsInfo,
    Hkdf,
}

impl From<Extension> for u8 {
    fn from(extension: Extension) -> u8 {
        match extension {
            Extension::FsInfo => 0,
            Extension::Hkdf => 1,
        }
    }
}

impl TryFrom<u8> for Extension {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self, Error> {
        match id {
            0 => Ok(Extension::FsInfo),
            1 => Ok(Extension::Hkdf),
            _ => Err(Error::FunctionNotSupported),
        }
    }
}

#[derive(Default)]
struct Extensions {
    staging: StagingBackend,
}

impl ExtensionId<FsInfoExtension> for Extensions {
    type Id = Extension;
    const ID: Extension = Extension::FsInfo;
}

impl ExtensionId<HkdfExtension> for Extensions {
    type Id = Extension;
    const ID: Extension = Extension::Hkdf;
}

impl ExtensionDispatch for Extensions {
    type BackendId = Backend;
    type Context = StagingContext;
    type ExtensionId = Extension;

    // Never inlined, like everything on the way to a Trussed request: inlined, its
    // buffers join the frame of the service loop, which every request pays for.
    #[inline(never)]
    fn extension_request<P: Platform>(
        &mut self,
        _: &Backend,
        extension: &Extension,
        ctx: &mut Context<StagingContext>,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        let staging = &mut self.staging;
        let (core, backend) = (&mut ctx.core, &mut ctx.backends);
        match extension {
            Extension::FsInfo => ExtensionImpl::<FsInfoExtension>::extension_request_serialized(
                staging, core, backend, request, resources,
            ),
            Extension::Hkdf => ExtensionImpl::<HkdfExtension>::extension_request_serialized(
                staging, core, backend, request, resources,
            ),
        }
    }
}

/// Extensions first, then Trussed's core for everything else.
static BACKENDS: [BackendId<Backend>; 2] = [BackendId::Custom(Backend::Staging), BackendId::Core];

/// The Trussed service and fido-authenticator's endpoint to it.
struct Runner {
    service: Service<Board, Extensions>,
    endpoint: ServiceEndpoint<'static, Backend, StagingContext>,
}

static RUNNER: StaticCell<RefCell<Runner>> = StaticCell::new();
static TRUSSED: TrussedChannel = TrussedChannel::new();

/// A Trussed request is answered as soon as it is made: the service runs right here,
/// inside the client's call.
struct Syscall(&'static RefCell<Runner>);

impl trussed::platform::Syscall for Syscall {
    fn syscall(&mut self) {
        let mut runner = self.0.borrow_mut();
        let Runner { service, endpoint } = &mut *runner;
        service.process(core::slice::from_mut(endpoint));
    }
}

type Client = ClientImplementation<'static, Syscall, Extensions>;

/// Set while the request being served is authenticatorReset.
static RESET: AtomicBool = AtomicBool::new(false);

/// Raised by the CTAPHID pipe when the host cancels the request being served; the
/// dispatch sets it working before each call and idle after.
static CANCEL: InterruptFlag = InterruptFlag::new();

/// User presence is the vault's own gesture on the same button and light: a fresh tap
/// while the light is amber, through `vaultkey_core::ui`, so a button already held when
/// the request arrives does not count. Erasing every passkey takes the wipe's hold
/// instead, because a tap never wipes. A request the host cancels ends the wait refused.
#[derive(Clone, Copy)]
struct Touch {
    panel: Panel,
    usb: &'static RefCell<UsbStack>,
}

impl UserPresence for Touch {
    fn user_present<T: TrussedRequirements>(
        self,
        _: &mut T,
        timeout_ms: u32,
    ) -> fido_authenticator::Result<()> {
        let mut panel = Cancellable(self.panel);
        let timeout_ms = u64::from(timeout_ms);
        self.usb.borrow_mut().awaiting_touch = true;
        let confirmed = if RESET.load(Ordering::Relaxed) {
            ui::await_hold(&mut panel, &Uptime, timeout_ms, RESET_HOLD_MS)
        } else {
            ui::await_confirmation(&mut panel, &Uptime, timeout_ms)
        };
        self.usb.borrow_mut().awaiting_touch = false;
        if confirmed {
            Ok(())
        } else if CANCEL.is_interrupted() {
            Err(fido_authenticator::Error::KeepaliveCancel)
        } else {
            Err(fido_authenticator::Error::UserActionTimeout)
        }
    }
}

/// The panel as a passkey's wait sees it: the same button and light, and a request the
/// host can withdraw.
struct Cancellable(Panel);

impl Ui for Cancellable {
    fn set(&mut self, state: State) {
        self.0.set(state);
    }

    fn pressed(&self) -> bool {
        self.0.pressed()
    }

    fn withdrawn(&self) -> bool {
        CANCEL.is_interrupted()
    }
}

/// fido-authenticator as the CTAPHID dispatch sees it: CTAP2 only. U2F's MSG is not
/// taken - it polls for presence every 250 ms, which a tap that must start after the
/// request cannot answer - so the dispatch refuses it as an unknown command.
pub(crate) struct Passkeys(Authenticator<Touch, Client>);

impl App<'static> for Passkeys {
    fn commands(&self) -> &'static [Command] {
        &[Command::Cbor]
    }

    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        Some(&CANCEL)
    }

    fn call(
        &mut self,
        command: Command,
        request: &[u8],
        response: &mut BytesView,
    ) -> Result<(), app::Error> {
        RESET.store(
            request.first() == Some(&AUTHENTICATOR_RESET),
            Ordering::Relaxed,
        );
        App::call(&mut self.0, command, request, response)
    }
}

static PASSKEYS: StaticCell<Passkeys> = StaticCell::new();

/// Mounts Trussed's filesystems and builds the authenticator over them. A filesystem
/// that does not mount is formatted: the region held the factory's stale staging bytes
/// before the first boot, and a damaged one has nothing left to save. One that will not
/// mount even then is broken flash, and the key resets rather than run half-built.
///
/// Never inlined: what it builds on the way would otherwise stay in `main`'s frame, and
/// so on the stack, for as long as the key runs.
#[inline(never)]
pub(crate) fn start(
    region: Region,
    rng: Entropy,
    panel: Panel,
    usb: &'static RefCell<UsbStack>,
) -> &'static mut Passkeys {
    let internal = Filesystem::mount_or_else(
        INTERNAL_ALLOC.init(Allocation::new()),
        INTERNAL.init(Internal(region)),
        |_, storage, _| Filesystem::format(storage),
    )
    .expect("Trussed's flash mounts once formatted");
    let volatile = Filesystem::mount_or_else(
        VOLATILE_ALLOC.init(Allocation::new()),
        VOLATILE.take(),
        |_, storage, _| Filesystem::format(storage),
    )
    .expect("RAM mounts once formatted");
    let board = Board {
        rng,
        store: Store {
            internal: INTERNAL_FS.init(internal),
            volatile: VOLATILE_FS.init(volatile),
        },
        ui: Clockwork,
    };

    let (requester, responder) = TRUSSED
        .split()
        .expect("the Trussed channel is split once, here");
    let runner = RUNNER.init(RefCell::new(Runner {
        service: Service::with_dispatch(board, Extensions::default()),
        endpoint: ServiceEndpoint::new(
            responder,
            CoreContext::new(path!("fido").into()),
            &BACKENDS,
        ),
    }));
    let client = Client::new(requester, Syscall(runner), None);
    let config = Config {
        max_msg_size: CTAP_MESSAGE,
        skip_up_timeout: None,
        max_resident_credential_count: None,
        large_blobs: None,
        nfc_transport: false,
    };
    PASSKEYS.init(Passkeys(Authenticator::new(
        client,
        Touch { panel, usb },
        config,
    )))
}

// --- the passkeys in a backup ----------------------------------------------------------

/// What a backup or a restore has done to Trussed's flash (`hal::Attachment`).
#[derive(Clone, Copy)]
enum Freeze {
    /// Trussed's own: passkeys are served.
    Thawed,
    /// A backup or a restore has it; `dirty` once a sector was rewritten.
    Frozen { dirty: bool },
    /// The host stopped talking mid-backup and the freeze was let go before anything
    /// was written: passkeys are served again, and the session's next read fails.
    Expired,
    /// Rewritten: Trussed's mounted filesystem and fido's cached state are stale, so the
    /// chip resets once the restore's answer has had time to leave.
    Restart { at: u64 },
}

static FREEZE: Mutex<Cell<Freeze>> = Mutex::new(Cell::new(Freeze::Thawed));

fn freeze_state() -> Freeze {
    critical_section::with(|cs| FREEZE.borrow(cs).get())
}

fn set_freeze(state: Freeze) {
    critical_section::with(|cs| FREEZE.borrow(cs).set(state));
}

/// How long a backup or a restore may leave the vkey line silent before its freeze is
/// let go: a session runs frame after frame, and a host that died must not leave
/// passkeys and `sudo` dead until a replug.
const FREEZE_MS: u64 = 10_000;
/// How long the restore's last answer gets to reach the host before the reset.
const RESTART_MS: u64 = 300;

/// Whether CTAP requests may be served now.
pub(crate) fn serving() -> bool {
    matches!(freeze_state(), Freeze::Thawed | Freeze::Expired)
}

/// Called on every look at the vkey line: lets a forgotten freeze go, and resets when
/// the region was rewritten. `last_rx` is when the last vkey byte came.
pub(crate) fn tend(now: u64, last_rx: u64) {
    match freeze_state() {
        Freeze::Frozen { dirty } if now - last_rx > FREEZE_MS => {
            if dirty {
                SCB::sys_reset();
            }
            set_freeze(Freeze::Expired);
        }
        Freeze::Restart { at } if now - at > RESTART_MS => SCB::sys_reset(),
        _ => {}
    }
}

/// Trussed's flash as a backup sees it: the same 4 KiB sectors littlefs uses, read and
/// written only while the freeze holds.
pub(crate) struct Backup(pub(crate) Region);

const SECTOR: usize = 4096;

impl Attachment for Backup {
    fn sectors(&self) -> u32 {
        FS_LEN / 4096
    }

    fn read(&mut self, i: u32, out: &mut [u8]) -> bool {
        matches!(freeze_state(), Freeze::Frozen { .. })
            && out.len() == SECTOR
            && i < self.sectors()
            && self.0.read(i * 4096, out).is_ok()
    }

    fn put(&mut self, i: u32, data: Option<&[u8]>) -> Option<bool> {
        let Freeze::Frozen { .. } = freeze_state() else {
            return None;
        };
        if data.is_some_and(|d| d.len() != SECTOR) || i >= self.sectors() {
            return None;
        }
        let at = i * 4096;
        if self.holds(at, data)? {
            return Some(false);
        }
        self.0.erase(at, at + 4096).ok()?;
        // Dirty from the erase on: a sector half done is a rewritten one.
        set_freeze(Freeze::Frozen { dirty: true });
        if let Some(data) = data {
            self.0.write(at, data).ok()?;
        }
        Some(true)
    }

    fn freeze(&mut self) {
        // A restart still owed - a restore rewrote the region just before - is carried
        // into this session, so its end resets rather than hand Trussed a stale region.
        let owed = matches!(
            freeze_state(),
            Freeze::Restart { .. } | Freeze::Frozen { dirty: true }
        );
        set_freeze(Freeze::Frozen { dirty: owed });
    }

    fn thaw(&mut self, changed: bool) {
        let dirty = matches!(freeze_state(), Freeze::Frozen { dirty: true });
        set_freeze(if changed || dirty {
            Freeze::Restart {
                at: Uptime.now_ms(),
            }
        } else {
            Freeze::Thawed
        });
    }
}

impl Backup {
    /// Whether the sector at `at` already holds `data`, or is blank when `data` is
    /// None: compared a little at a time, without a sector-sized buffer on the stack.
    fn holds(&mut self, at: u32, data: Option<&[u8]>) -> Option<bool> {
        let mut chunk = [0u8; 64];
        for (n, start) in (0..SECTOR).step_by(chunk.len()).enumerate() {
            let offset = at + u32::try_from(n * chunk.len()).ok()?;
            self.0.read(offset, &mut chunk).ok()?;
            let same = match data {
                Some(d) => chunk == d[start..start + chunk.len()],
                None => chunk.iter().all(|&b| b == 0xFF),
            };
            if !same {
                return Some(false);
            }
        }
        Some(true)
    }
}
