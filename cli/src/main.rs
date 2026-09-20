//! The `vkey` command.
//!
//! ```text
//! vkey                                    # interactive: menu, completion, questions
//! vkey setup                              # flash a new board, set the PIN, self-test
//! vkey totp add github                    # the rest are one-shot commands for scripts
//! vkey pass add mail --login me           # a password
//! vkey env add myapp .env                 # a project's .env, whole
//! vkey import passwords.csv               # a password manager export, mirrored onto the key
//! vkey get github                         # a code, a login and a password, or a .env
//! vkey backup vault.vkb                   # everything into one file, sealed on the key; two taps
//! vkey restore vault.vkb                  # everything back, onto this or another key
//! vkey check --wipe-everything            # lifecycle test; ERASES the device
//! sudo vkey auth enable                   # sudo and the lock screen with a tap
//! vkey install                            # copy this binary to ~/.local/bin
//! ```
//!
//! Secrets are encrypted on the device under a key derived from the PIN. Eight wrong
//! PINs wipe them. The device stays unlocked until `lock`, two idle minutes, or a power
//! cycle. Secrets and PINs are never taken from the command line: they are asked for,
//! or read from stdin when there is no terminal.

mod auth;
mod backup;
mod boards;
mod check;
mod device;
mod import;
mod install;
mod item;
mod op;
mod prompt;
mod setup;
mod shell;
mod sources;
mod totp;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use zeroize::Zeroizing;

use device::{Category, Class, Device, Error, Reach, login_item, passphrase, pin};
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
    List {
        /// Tab-separated: name, category, login, what a gesture would bring back
        /// (secret, seed). One request per item, no gesture - what a script checks a
        /// sync against.
        #[arg(long)]
        long: bool,
    },
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
    /// export; existing entries are skipped, and entries an earlier import of the same
    /// file left behind but it no longer offers are deleted
    Import {
        /// The CSV file the manager exported
        file: PathBuf,
        /// Replace existing entries without asking
        #[arg(short, long)]
        replace: bool,
    },
    /// Pull passwords, TOTP codes and .env files directly from 1Password via 'op'.
    /// A whole-vault run also deletes what 1Password no longer has; narrowing it with
    /// an item, --tag or --vault makes it a selection, which only adds
    #[command(alias = "1password")]
    Op {
        /// Specific item or document to pull; syncs all items if omitted
        item: Option<String>,
        /// Filter items by 1Password tag
        #[arg(long)]
        tag: Option<String>,
        /// Filter items by 1Password vault
        #[arg(long)]
        vault: Option<String>,
        /// 1Password Developer Environment to import (name:id or name=id)
        #[arg(short = 'E', long = "environment")]
        environments: Vec<String>,
        /// Replace existing entries without asking
        #[arg(short, long)]
        replace: bool,
    },
    /// Every entry and .env into one file, sealed on the key under a passphrase it
    /// asks for; the button is tapped twice
    Backup {
        /// Where to write the backup
        file: PathBuf,
    },
    /// One item back into 1Password, as the item it was: every field, its sections and
    /// its type. An item with a one-time password costs the double tap, because its
    /// seed leaves the key in the clear - see docs/threat-model.md
    Export {
        /// The item on the key
        name: String,
        /// Which 1Password vault to write it to
        #[arg(long)]
        vault: Option<String>,
    },
    /// Every entry and .env out of a backup file, CSV export, or 1Password API onto this key
    Restore {
        /// A .vkb backup file, a CSV export, or 'op' (interactive choice when omitted)
        file: Option<PathBuf>,
        /// Restore directly from 1Password API via 'op'
        #[arg(long, alias = "1password")]
        op: bool,
        /// 1Password Developer Environment to import (name:id or name=id)
        #[arg(short = 'E', long = "environment")]
        environments: Vec<String>,
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
    /// sudo and the lock screen with a tap: `sudo vkey auth enable`; bare, what PAM runs
    Auth {
        #[command(subcommand)]
        cmd: Option<AuthCmd>,
    },
    /// Copy this binary to ~/.local/bin/vkey
    Install,
}

#[derive(Subcommand, Clone, Copy)]
enum AuthCmd {
    /// A login secret on the key, its public key here, and the PAM lines for sudo and
    /// the lock screen; PIN and a tap
    Enable,
    /// The PAM lines out, the public key and the login secret gone
    Disable,
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
    /// up to 8128 bytes, as is
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
        // What PAM runs: straight to the key, no probing, no shell on the way.
        Some(Cmd::Auth { cmd: None }) => return auth::verify(cli.port.as_deref()),
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
        Cmd::Install | Cmd::Setup { .. } | Cmd::Auth { cmd: None } => {
            unreachable!("handled above")
        }
        Cmd::Auth {
            cmd: Some(AuthCmd::Enable),
        } => auth::enable(&mut dev),
        Cmd::Auth {
            cmd: Some(AuthCmd::Disable),
        } => auth::disable(&mut dev),

        Cmd::Info => run_info(&mut dev, &version),

        Cmd::List { long } => run_list(&mut dev, long),

        Cmd::Rm { name, yes } => {
            if !confirm(
                &format!("remove '{name}'? Its secret cannot be recovered."),
                yes,
            )? {
                println!("kept");
                return Ok(0);
            }
            with_unlock(&mut dev, |d| d.delete(&name))?;
            sources::forget(&name);
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
            sources::forget_all();
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
        Cmd::Import { file, replace } => run_import(&mut dev, &file, replace),
        Cmd::Op {
            item,
            tag,
            vault,
            environments,
            replace,
        } => run_op(
            &mut dev,
            item.as_deref(),
            tag.as_deref(),
            vault.as_deref(),
            &environments,
            replace,
        ),
        Cmd::Backup { file } => run_backup(&mut dev, &version, &file),
        Cmd::Export { name, vault } => run_export(&mut dev, &name, vault.as_deref()),
        Cmd::Restore {
            file,
            op,
            environments,
        } => run_restore(&mut dev, file.as_deref(), op, &environments),
    }
}

fn run_list(dev: &mut Device, long: bool) -> Result<u8, Error> {
    let entries = with_unlock(dev, Device::list)?;
    if entries.is_empty() && !long {
        println!("(nothing stored)");
    }
    for e in entries {
        if !long {
            println!("{:<34} {}", e.name, item::category_name(e.category));
            continue;
        }
        // The open reach costs the PIN and no gesture, so a whole vault can be listed
        // this way; an auth item refuses to be read at all and is reported as it lists.
        let Ok((open, shape)) = dev.get_with_shape(&e.name, Reach::Open) else {
            println!("{}\t{}\t\t", e.name, item::category_name(e.category));
            continue;
        };
        let login = open
            .by_label("username")
            .or_else(|| open.by_label("email"))
            .map(|f| f.text().as_str().to_owned())
            .unwrap_or_default();
        let mut holds = Vec::new();
        if shape.has_secret() {
            holds.push("secret");
        }
        if shape.has_seed() {
            holds.push("seed");
        }
        println!(
            "{}\t{}\t{login}\t{}",
            e.name,
            item::category_name(e.category),
            holds.join(",")
        );
    }
    Ok(0)
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

/// One item back into 1Password. The gesture is the item's own: a seed costs the double
/// tap, and that is the whole of the secret leaving the key - the same act as a backup,
/// and the same gesture, so it cannot be mistaken for the tap that reveals a password.
fn run_export(dev: &mut Device, name: &str, vault: Option<&str>) -> Result<u8, Error> {
    let mut ui = prompt::CliUi;
    let id = with_unlock(dev, |d| op::export_item(d, name, vault, &mut ui))?;
    println!("wrote '{name}' to 1Password as {id}");
    Ok(0)
}

fn run_backup(dev: &mut Device, version: &str, file: &Path) -> Result<u8, Error> {
    let file = backup::target(file)?;
    let pass = twice(
        "backup passphrase (five or six random words)",
        "passphrases",
    )?;
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

#[derive(Clone, Copy)]
enum RestoreSource {
    OnePassword,
    Csv,
    Backup,
}

fn run_restore(
    dev: &mut Device,
    file: Option<&Path>,
    op: bool,
    environments: &[String],
) -> Result<u8, Error> {
    if op {
        return run_op(dev, None, None, None, environments, false);
    }
    let file = match file {
        Some(f) if f.to_str() == Some("op") || f.to_str() == Some("1password") => {
            return run_op(dev, None, None, None, environments, false);
        }
        Some(f)
            if f.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("csv")) =>
        {
            return run_import(dev, f, false);
        }
        Some(f) => f.to_path_buf(),
        None if prompt::is_tty() => {
            let choice = prompt::choose(
                "restore from: ",
                &[
                    (
                        RestoreSource::OnePassword,
                        "1password",
                        "1Password API via 'op' in memory",
                    ),
                    (
                        RestoreSource::Csv,
                        "csv",
                        "Google Password Manager or 1Password CSV export",
                    ),
                    (
                        RestoreSource::Backup,
                        "backup",
                        "a .vkb backup file written by 'vkey backup'",
                    ),
                ],
            );
            match choice {
                Some(RestoreSource::OnePassword) => {
                    return run_op(dev, None, None, None, environments, false);
                }
                Some(RestoreSource::Csv) => {
                    let path_str = prompt_secret("path to CSV export")?;
                    return run_import(dev, Path::new(path_str.as_str()), false);
                }
                Some(RestoreSource::Backup) => {
                    let path_str = prompt_secret("path to .vkb backup file")?;
                    PathBuf::from(path_str.as_str())
                }
                None => return Ok(0),
            }
        }
        None => {
            return Err(Error::Value(
                "give a backup file, a CSV export, or --op".into(),
            ));
        }
    };
    let file = backup::source(&file)?;
    let pass = prompt_secret("backup passphrase")?;
    passphrase(&pass)?;
    let done = with_unlock(dev, |d| backup::import(d, &file, passphrase(&pass)?))?;
    println!(
        "{} item{} restored from {}",
        done.count,
        if done.count == 1 { "" } else { "s" },
        file.display()
    );
    for line in &done.skipped {
        eprintln!("  left in the file: {line}");
    }
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
    let item = blob.item();
    with_unlock(dev, |d| d.put(&name, &item, replace))?;
    println!("stored '{name}' - it comes back whole after a tap:  vkey get {name}");
    Ok(0)
}

fn run_import(dev: &mut Device, file: &Path, replace: bool) -> Result<u8, Error> {
    let parsed = import::read(file)?;
    println!("{}", parsed.summary());
    for s in &parsed.skipped {
        println!("  skipped: {s}");
    }
    let mut ui = prompt::CliUi;
    let done = with_unlock(dev, |d| import::run(d, &parsed, file, replace, &mut ui));
    eprintln!("{}", import::reminder(file));
    println!("{}", done?.line());
    Ok(0)
}

fn run_op(
    dev: &mut Device,
    item: Option<&str>,
    tag: Option<&str>,
    vault: Option<&str>,
    environments: &[String],
    replace: bool,
) -> Result<u8, Error> {
    let mut env_pairs = Vec::new();
    let saved = op::load_saved_envs();

    for spec in environments {
        if let Some(pair) = op::parse_env_spec(spec) {
            env_pairs.push(pair);
        } else if let Some(id) = saved.get(spec) {
            println!("  using stored ID for '{spec}' ({id})");
            env_pairs.push((spec.clone(), id.clone()));
        } else {
            eprintln!(
                "ignoring invalid environment specification '{spec}'; expected 'name:id' or a saved environment name"
            );
        }
    }

    if item.is_none() && env_pairs.is_empty() && prompt::is_tty() {
        println!("  ● 1Password Developer Environments (.env)");
        if !saved.is_empty() {
            println!("    Saved environments:");
            for (name, id) in &saved {
                println!("      • {name} (ID: {id})");
            }
            if prompt::yes_no("update saved environments?") {
                env_pairs.extend(saved);
            }
        }

        if env_pairs.is_empty() {
            println!(
                "    (in 1Password: Developer -> View Environments -> View environment -> Manage environment -> Copy environment ID)"
            );
            loop {
                let line =
                    prompt::prompt_line("add Environment (name or name:ID, Enter to finish)")?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break;
                }
                let (name, id) = if let Some(pair) = op::parse_env_spec(trimmed) {
                    pair
                } else if let Some(stored_id) = op::load_saved_envs().get(trimmed) {
                    println!("  using stored ID for '{trimmed}' ({stored_id})");
                    (trimmed.to_string(), stored_id.clone())
                } else {
                    let id_line =
                        prompt::prompt_line(&format!("ID for '{trimmed}' (copy from 1Password)"))?;
                    let id_trimmed = id_line.trim().to_string();
                    if id_trimmed.is_empty() {
                        continue;
                    }
                    (trimmed.to_string(), id_trimmed)
                };
                env_pairs.push((name, id));
            }
        }
    }

    let env_refs: Vec<(&str, &str)> = env_pairs
        .iter()
        .map(|(n, i)| (n.as_str(), i.as_str()))
        .collect();
    let mut ui = prompt::CliUi;
    let summary = with_unlock(dev, |d| match item {
        Some(name) => op::pull_item(d, name, replace, &mut ui),
        None => op::sync(d, tag, vault, &env_refs, replace, &mut ui),
    })?;
    println!("{}", summary.line());
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
    let a = twice("new PIN (8 digits)", "PINs")?;
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
            let item = r.item();
            with_unlock(dev, |d| d.put(&r.name, &item, replace))?;
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
            let item = login_item(login.as_deref().unwrap_or(""), &a, "")?;
            with_unlock(dev, |d| d.put(&name, &item, replace))?;
            println!("stored '{name}' - the password comes out after a tap");
        }
    }
    Ok(0)
}

/// What an item does when used: what it holds decides. The shape comes back with the
/// open fields and costs no gesture, so nothing is asked of the person until it is
/// known what they asked for.
fn run_get(dev: &mut Device, version: &str, name: &str, copy: bool) -> Result<u8, Error> {
    let button = boards::button(Some(version));
    let stored = with_unlock(dev, |d| {
        d.list()?
            .into_iter()
            .find(|e| e.name == name)
            .ok_or(Error::NotFound)
    })?;
    if stored.category == Category::Auth {
        return Err(Error::Value(auth::USED_BY_AUTH.into()));
    }

    let (open, shape) = dev.get_with_shape(name, Reach::Open)?;

    if stored.category == Category::Env {
        // Whole and as is, to stdout only: `vkey get myapp > .env`, or
        // `env $(vkey get myapp) cmd` with nothing on disk at all.
        if copy {
            eprintln!("a .env is not copied to the clipboard; redirect stdout instead");
        }
        eprintln!("tap {button} on the board...");
        let item = dev.get(name, Reach::Secret)?;
        let blob = item
            .by_label(".env")
            .ok_or_else(|| Error::Value("this item holds no .env".into()))?;
        let mut out = std::io::stdout().lock();
        out.write_all(&blob.value)?;
        out.flush()?;
        return Ok(0);
    }

    if shape.has_seed() {
        eprintln!("tap {button} on the board...");
        let code = dev.code(name, None)?;
        let remaining = totp::seconds_left(device::Params::DEFAULT);
        println!(
            "{code}   ({remaining}s left){}",
            if copy_to_clipboard(&code, None) {
                "  copied"
            } else {
                ""
            }
        );
        return Ok(0);
    }

    for f in &open.fields {
        eprintln!("{}: {}", f.label, f.text().as_str());
    }
    if !shape.has_secret() {
        return Ok(0);
    }
    eprintln!("tap {button} on the board...");
    let shown = dev.get(name, Reach::Secret)?;
    let secret = shown
        .first(Class::Secret)
        .ok_or_else(|| Error::Value("nothing behind the tap in this item".into()))?;
    let text = secret.text();
    println!("{}", text.as_str());
    if copy {
        match copy_secret(&text) {
            Some(notice) => eprintln!("{notice}"),
            None => eprintln!("no clipboard tool found (wl-copy, xclip, pbcopy)"),
        }
    }
    // Whatever else the tap brought - recovery codes, usually - after a blank line, so
    // the first line of stdout is always the password alone.
    for f in shown
        .fields
        .iter()
        .filter(|f| f.class == Class::Secret && f.label != secret.label)
    {
        println!("\n{}:\n{}", f.label, f.text().as_str());
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
