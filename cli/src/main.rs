//! The `vkey` command.
//!
//! ```text
//! vkey                                    # interactive: menu, completion, questions
//! vkey setup                              # flash a new board, set the PIN, self-test
//! vkey totp add github                    # the rest are one-shot commands for scripts
//! vkey pass add mail --login me           # a password
//! vkey env add myapp .env                 # a project's .env, whole
//! vkey import passwords.csv               # a password manager export, one question per row
//! vkey get github                         # a code, a login and a password, or a .env
//! vkey backup vault.vkb                   # everything into one file, sealed on the key; two taps
//! vkey restore vault.vkb                  # everything back, onto this or another key
//! vkey check --wipe-everything            # lifecycle test; ERASES the device
//! vkey install                            # copy this binary to ~/.local/bin
//! ```
//!
//! Secrets are encrypted on the device under a key derived from the PIN. Eight wrong
//! PINs wipe them. The device stays unlocked until `lock`, two idle minutes, or a power
//! cycle. Secrets and PINs are never taken from the command line: they are asked for,
//! or read from stdin when there is no terminal.

mod backup;
mod boards;
mod check;
mod device;
mod import;
mod install;
mod prompt;
mod setup;
mod shell;
mod totp;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use zeroize::Zeroizing;

use device::{Device, Error, Kind, describe, passphrase, password_blob, pin};
use prompt::{
    confirm, copy_secret, copy_to_clipboard, prompt_secret, unlock_interactive, with_unlock,
};

#[derive(Parser)]
#[command(name = "vkey", version, about = "vaulttecdev hardware key: TOTP codes and passwords", long_about = None)]
struct Cli {
    /// Serial port; autodetected by default
    #[arg(long, global = true)]
    port: Option<String>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Flash a new board with the built-in firmware, then set a PIN
    Setup {
        /// Erase the whole flash first (all secrets and the PIN)
        #[arg(long)]
        erase: bool,
        /// Which board folder to flash; needed only when several fit the detected chip
        #[arg(long)]
        board: Option<String>,
    },
    /// Firmware version and lock state
    Info,
    /// Use an entry: a TOTP code after a tap, the login and - after a tap - the
    /// password, or a whole .env after a tap; PIN if locked
    Get {
        name: String,
        /// A password goes to the clipboard too, for thirty seconds
        #[arg(long)]
        copy: bool,
    },
    /// Every stored entry; PIN if locked
    List,
    /// Delete an entry; its secret cannot be recovered
    Rm {
        name: String,
        /// Do not ask
        #[arg(short, long)]
        yes: bool,
    },
    /// Forget the PIN-derived key until next unlock
    Lock,
    /// Factory reset: every secret and the PIN; the button is held five seconds
    Wipe {
        /// Do not ask
        #[arg(short, long)]
        yes: bool,
    },
    /// PIN management
    Pin {
        #[command(subcommand)]
        cmd: PinCmd,
    },
    /// TOTP credentials
    Totp {
        #[command(subcommand)]
        cmd: TotpCmd,
    },
    /// Stored passwords
    Pass {
        #[command(subcommand)]
        cmd: PassCmd,
    },
    /// Stored .env files: a project's environment, whole, after a tap
    Env {
        #[command(subcommand)]
        cmd: EnvCmd,
    },
    /// Passwords and TOTP codes from a Google Password Manager or 1Password 8 CSV
    /// export; asks about every row, so it needs a terminal
    Import {
        /// The CSV file the manager exported
        file: PathBuf,
    },
    /// Every entry and .env into one file, sealed on the key under a passphrase it
    /// asks for; the button is tapped twice
    Backup {
        /// Where to write the backup
        file: PathBuf,
    },
    /// Every entry and .env out of a backup file onto this key, replacing entries of
    /// the same name; PIN and the passphrase, no button
    Restore {
        /// A file `vkey backup` wrote
        file: PathBuf,
    },
    /// Lifecycle test of a development board; ERASES everything
    #[command(long_about = "vkey check --wipe-everything\n\n\
        THIS ERASES EVERY SECRET ON THE DEVICE. It exists for development boards and for\n\
        proving a firmware build before it goes anywhere near real credentials. Every step\n\
        is a PASS/FAIL line; the exit code is non-zero if any failed. It says when to tap\n\
        the button and when to hold it. The device is left wiped: no PIN, no entries.")]
    Check {
        #[arg(long)]
        wipe_everything: bool,
    },
    /// Copy this binary to ~/.local/bin/vkey
    Install,
}

#[derive(Subcommand, Clone, Copy)]
enum PinCmd {
    Status,
    /// First-time setup
    Set,
    /// Unlock for this session
    Unlock,
    Change,
}

#[derive(Subcommand)]
enum TotpCmd {
    /// Store a credential: the otpauth URI or base32 secret is asked for, never typed
    /// on the command line
    Add {
        /// Required with a bare secret; derived from the URI otherwise
        name: Option<String>,
        /// 6 or 8; default 6, or whatever the URI says
        #[arg(long)]
        digits: Option<u8>,
        /// Default 30, or whatever the URI says
        #[arg(long)]
        period: Option<u8>,
        /// Most services use SHA-1
        #[arg(long)]
        sha256: bool,
        /// Overwrite an entry with the same name
        #[arg(long)]
        replace: bool,
    },
    /// One live code against an independent HMAC; one tap
    Selftest,
}

#[derive(Subcommand)]
enum EnvCmd {
    /// Store a .env file - or stdin, when no file is given - under a project name;
    /// up to 8000 bytes, as is
    Add {
        /// Project name
        name: String,
        /// The .env file; stdin when absent (wl-paste | vkey env add myapp)
        file: Option<PathBuf>,
        /// Overwrite a .env with the same name
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Subcommand)]
enum PassCmd {
    /// Store a password; it is asked for twice, never typed on the command line
    Add {
        /// Site or account name
        name: String,
        /// The login that goes with it; shown without the button
        #[arg(long)]
        login: Option<String>,
        /// Overwrite an entry with the same name
        #[arg(long)]
        replace: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(Error::Refused) => {
            eprintln!("{}", Error::Refused);
            ExitCode::from(3)
        }
        Err(Error::Wiped) => {
            eprintln!("{}", Error::Wiped);
            ExitCode::from(5)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<u8, Error> {
    match cli.cmd {
        Some(Cmd::Install) => return install::install().map(|()| 0),
        Some(Cmd::Setup { erase, board }) => {
            return cmd_setup(cli.port.as_deref(), board.as_deref(), erase);
        }
        _ => {}
    }

    let mut dev = Device::open(cli.port.as_deref())?;
    let version = dev.probe();
    let Some(cmd) = cli.cmd else {
        return shell::run(dev, version);
    };
    let Some(version) = version else {
        return Err(Error::Value(format!(
            "the board on {} does not answer - not vkey firmware?\n  vkey setup    # flashes it",
            dev.path
        )));
    };

    match cmd {
        Cmd::Install | Cmd::Setup { .. } => unreachable!("handled above"),

        Cmd::Info => run_info(&mut dev, &version),

        Cmd::List => {
            let entries = with_unlock(&mut dev, Device::list)?;
            if entries.is_empty() {
                println!("(nothing stored)");
            }
            for e in entries {
                let what = match e.kind {
                    Kind::Totp(_) => format!("totp {}", describe(e.kind)),
                    Kind::Password | Kind::Env => describe(e.kind),
                };
                println!("{:<34} {}", e.name, what.trim_end());
            }
            Ok(0)
        }

        Cmd::Rm { name, yes } => {
            if !confirm(
                &format!("remove '{name}'? Its secret cannot be recovered."),
                yes,
            )? {
                println!("kept");
                return Ok(0);
            }
            with_unlock(&mut dev, |d| d.delete(&name))?;
            println!("removed '{name}'");
            Ok(0)
        }

        Cmd::Lock => {
            dev.lock()?;
            println!("locked");
            Ok(0)
        }

        Cmd::Wipe { yes } => {
            if !confirm("wipe every secret and the PIN from this key?", yes)? {
                println!("kept");
                return Ok(0);
            }
            eprintln!(
                "hold {} on the board down for five seconds - the light turns red...",
                boards::button(Some(&version))
            );
            dev.wipe()?;
            println!("wiped: no PIN, no credentials - run  vkey pin set  or /pin");
            Ok(0)
        }

        Cmd::Check { wipe_everything } => {
            if !wipe_everything {
                // The flag is the consent; without it, the help says what it consents to.
                if let Some(c) = Cli::command().find_subcommand_mut("check") {
                    println!("{}", c.render_long_help());
                }
                return Ok(2);
            }
            check::run(&mut dev)
        }

        Cmd::Pin { cmd } => run_pin(&mut dev, cmd),
        Cmd::Get { name, copy } => run_get(&mut dev, &version, &name, copy),
        Cmd::Totp { cmd } => run_totp(&mut dev, &version, cmd),
        Cmd::Pass { cmd } => run_pass(&mut dev, cmd),
        Cmd::Env { cmd } => run_env(&mut dev, cmd),
        Cmd::Import { file } => run_import(&mut dev, &file),
        Cmd::Backup { file } => run_backup(&mut dev, &version, &file),
        Cmd::Restore { file } => run_restore(&mut dev, &file),
    }
}

fn run_info(dev: &mut Device, version: &str) -> Result<u8, Error> {
    let st = dev.pin_status()?;
    println!("port:    {}", dev.path);
    println!("device:  {version}");
    println!(
        "pin:     {}, {}, {} attempts left",
        if st.has_pin { "set" } else { "NOT SET" },
        if st.unlocked { "unlocked" } else { "locked" },
        st.retries_left
    );
    println!(
        "key:     {}",
        if st.chip_bound {
            "chip-bound (a copy of the flash is useless without this chip)"
        } else {
            "PIN only"
        }
    );
    Ok(0)
}

fn run_backup(dev: &mut Device, version: &str, file: &Path) -> Result<u8, Error> {
    let file = backup::target(file)?;
    let pass = twice("backup passphrase (12+ characters)", "passphrases")?;
    passphrase(&pass)?;
    let button = boards::button(Some(version));
    let n = with_unlock(dev, |d| {
        eprintln!("tap {button} on the board twice - the light turns blue...");
        backup::export(d, &file, passphrase(&pass)?)
    })?;
    println!(
        "{n} item{} sealed into {} - it opens only with the passphrase, on any vkey",
        if n == 1 { "" } else { "s" },
        file.display()
    );
    Ok(0)
}

fn run_restore(dev: &mut Device, file: &Path) -> Result<u8, Error> {
    let file = backup::source(file)?;
    let pass = prompt_secret("backup passphrase")?;
    passphrase(&pass)?;
    let n = with_unlock(dev, |d| backup::import(d, &file, passphrase(&pass)?))?;
    println!(
        "{n} item{} restored from {}",
        if n == 1 { "" } else { "s" },
        file.display()
    );
    Ok(0)
}

fn run_env(dev: &mut Device, cmd: EnvCmd) -> Result<u8, Error> {
    let EnvCmd::Add {
        name,
        file,
        replace,
    } = cmd;
    let blob = match file {
        Some(f) => device::env_file(&f)?,
        None if prompt::is_tty() => {
            return Err(Error::Value("give the .env as a file or on stdin".into()));
        }
        None => {
            let mut blob = Zeroizing::new(Vec::new());
            std::io::stdin().lock().read_to_end(&mut blob)?;
            device::EnvBlob::new(blob)?
        }
    };
    with_unlock(dev, |d| d.env_put(&name, &blob, replace))?;
    println!("stored '{name}' - it comes back whole after a tap:  vkey get {name}");
    Ok(0)
}

fn run_import(dev: &mut Device, file: &Path) -> Result<u8, Error> {
    if !prompt::is_tty() {
        return Err(Error::Value(
            "import needs a terminal: it asks about every row".into(),
        ));
    }
    let parsed = import::read(file)?;
    println!("{}", parsed.summary());
    for s in &parsed.skipped {
        println!("  skipped: {s}");
    }
    let done = with_unlock(dev, |d| {
        import::run(d, &parsed.rows, &mut |s| println!("{s}"))
    });
    eprintln!("{}", import::reminder(file));
    println!("{}", done?.line());
    Ok(0)
}

/// A hidden secret asked for twice, since it cannot be read back; `what` names it in
/// the mismatch message ("PINs", "passwords").
fn twice(label: &str, what: &str) -> Result<Zeroizing<String>, Error> {
    let a = prompt_secret(label)?;
    if a != prompt_secret("again")? {
        return Err(Error::Value(format!("{what} do not match")));
    }
    Ok(a)
}

fn new_pin() -> Result<Zeroizing<String>, Error> {
    let a = twice("new PIN (6-8 digits)", "PINs")?;
    pin(&a)?;
    Ok(a)
}

fn run_pin(dev: &mut Device, cmd: PinCmd) -> Result<u8, Error> {
    match cmd {
        PinCmd::Status => {
            let st = dev.pin_status()?;
            println!(
                "has_pin: {}\nunlocked: {}\nretries_left: {}\nchip_bound: {}",
                st.has_pin, st.unlocked, st.retries_left, st.chip_bound
            );
        }
        PinCmd::Set => {
            if dev.pin_status()?.has_pin {
                eprintln!("a PIN already exists; use 'pin change'");
                return Ok(2);
            }
            let a = new_pin()?;
            dev.pin_set(pin(&a)?)?;
            println!("PIN set; device unlocked");
        }
        PinCmd::Unlock => {
            unlock_interactive(dev)?;
            println!("unlocked");
        }
        PinCmd::Change => {
            let old = prompt_secret("current PIN")?;
            let a = new_pin()?;
            dev.pin_change(pin(&old)?, pin(&a)?)?;
            println!("PIN changed; all entries re-encrypted");
        }
    }
    Ok(0)
}

fn run_totp(dev: &mut Device, version: &str, cmd: TotpCmd) -> Result<u8, Error> {
    match cmd {
        TotpCmd::Add {
            name,
            digits,
            period,
            sha256,
            replace,
        } => {
            let source = prompt_secret("otpauth URI or base32 secret")?;
            let r = totp::resolve(&source, name.as_deref(), digits, period, sha256)?;
            with_unlock(dev, |d| {
                d.add(&r.name, &r.secret, Kind::Totp(r.params), replace)
            })?;
            println!("stored '{}' - codes need a tap on the button", r.name);
        }
        TotpCmd::Selftest => {
            println!("device: {version}");
            let button = boards::button(Some(version));
            let ok = with_unlock(dev, |d| {
                totp::selftest(d, &button, |line| println!("{line}"))
            })?;
            if !ok {
                eprintln!("\nSELFTEST FAILED - the device's TOTP math is wrong");
                return Ok(4);
            }
            println!("\nselftest passed");
        }
    }
    Ok(0)
}

fn run_pass(dev: &mut Device, cmd: PassCmd) -> Result<u8, Error> {
    match cmd {
        PassCmd::Add {
            name,
            login,
            replace,
        } => {
            let a = twice("password", "passwords")?;
            let blob = password_blob(&name, login.as_deref().unwrap_or(""), &a, "")?;
            with_unlock(dev, |d| d.add(&name, &blob, Kind::Password, replace))?;
            println!("stored '{name}' - the password comes out after a tap");
        }
    }
    Ok(0)
}

/// What an entry does when used: its kind decides.
fn run_get(dev: &mut Device, version: &str, name: &str, copy: bool) -> Result<u8, Error> {
    let button = boards::button(Some(version));
    let stored = with_unlock(dev, |d| {
        d.list()?
            .into_iter()
            .find(|e| e.name == name)
            .ok_or(Error::NotFound)
    })?;
    match stored.kind {
        Kind::Totp(p) => {
            eprintln!("tap {button} on the board...");
            let code = dev.code(name, None)?;
            let remaining = totp::seconds_left(p);
            println!(
                "{code}   ({remaining}s left){}",
                if copy_to_clipboard(&code, None) {
                    "  copied"
                } else {
                    ""
                }
            );
        }
        Kind::Password => {
            let login = dev.login(name)?;
            if !login.is_empty() {
                println!("login: {}", String::from_utf8_lossy(&login));
            }
            eprintln!("tap {button} on the board...");
            let entry = dev.reveal(name)?;
            let text = String::from_utf8_lossy(entry.password_bytes().unwrap_or_default());
            println!("{text}");
            if copy {
                match copy_secret(&text) {
                    Some(notice) => eprintln!("{notice}"),
                    None => eprintln!("no clipboard tool found (wl-copy, xclip, pbcopy)"),
                }
            }
            // The note - recovery codes, usually - after a blank line, so the first
            // line of stdout is always the password alone.
            let note = entry.note().unwrap_or_default();
            if !note.is_empty() {
                println!("\n{}", String::from_utf8_lossy(note));
            }
        }
        Kind::Env => {
            // Whole and as is, to stdout only: `vkey get myapp > .env`, or
            // `env $(vkey get myapp) cmd` with nothing on disk at all.
            if copy {
                eprintln!("a .env is not copied to the clipboard; redirect stdout instead");
            }
            eprintln!("tap {button} on the board...");
            let blob = dev.env_get(name)?;
            let mut out = std::io::stdout().lock();
            out.write_all(&blob)?;
            out.flush()?;
        }
    }
    Ok(0)
}

fn cmd_setup(port: Option<&str>, board: Option<&str>, erase: bool) -> Result<u8, Error> {
    // Open the port once ourselves first: that is where a missing dialout membership
    // surfaces with a useful message. The bootloader talk would only say "timeout".
    Device::open(port)?;
    println!(
        "setting up a new board (firmware built in for: {})",
        boards::names()
    );
    let mut log = |s: &str| println!("{s}");
    let mut dev = setup::flash_new_board(port, board, erase, &mut log)?;
    let button = boards::button(dev.probe().as_deref());
    if !setup::provision(&mut dev, &button, &mut TerminalSetup)? {
        eprintln!("SELFTEST FAILED");
        return Ok(4);
    }
    println!("ready - store your first credential:  vkey totp add   or just  vkey");
    Ok(0)
}

/// Provisioning's questions on a plain terminal. Without one (scripts), an existing
/// PIN is kept.
struct TerminalSetup;

impl setup::ProvisionUi for TerminalSetup {
    fn say(&mut self, line: &str) {
        println!("{line}");
    }

    fn keep_existing(&mut self) -> bool {
        !prompt::is_tty()
            || prompt::choose(
                "this board already has a PIN and maybe credentials",
                &[
                    (true, "keep them", ""),
                    (false, "wipe them", "the button held five seconds"),
                ],
            ) != Some(false)
    }

    fn set_pin(&mut self, dev: &mut Device) -> Result<(), Error> {
        let a = new_pin()?;
        dev.pin_set(pin(&a)?)?;
        println!("  PIN set");
        Ok(())
    }

    fn unlock(&mut self, dev: &mut Device) -> Result<(), Error> {
        unlock_interactive(dev)
    }
}
