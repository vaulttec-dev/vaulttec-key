//! Talking to the person on a plain terminal: secret prompts, choices, clipboard.

use std::io::{self, BufRead, IsTerminal, Write};
use std::process::{Command, Stdio};

use crossterm::cursor::{MoveToColumn, MoveUp};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::queue;
use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::terminal::{self, Clear, ClearType};
use zeroize::Zeroizing;

use crate::device::{Device, Error, pin};

// The palette Claude Code uses: one warm accent, everything else grey or semantic.
pub const ACCENT: Color = Color::Rgb {
    r: 0xd9,
    g: 0x77,
    b: 0x57,
};
pub const DIM: Color = Color::Rgb {
    r: 0x8a,
    g: 0x8a,
    b: 0x8a,
};

pub fn is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Reads something secret without echo. Without a terminal - scripts, editor consoles -
/// it is one line of stdin: nothing lands in the environment or the process list.
pub fn prompt_secret(label: &str) -> Result<Zeroizing<String>, Error> {
    if !is_tty() {
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        let len = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(len);
        if line.is_empty() {
            return Err(Error::Value(format!("no {label} on stdin")));
        }
        return Ok(line);
    }
    rpassword::prompt_password(format!("{label}: "))
        .map(Zeroizing::new)
        .map_err(|_| Error::Value(format!("no {label} entered")))
}

/// How long a generated password is. Sites cap passwords at 64 or so and choke on
/// exotic symbols, so this is long and plain rather than short and strange.
const GENERATED_LEN: usize = 24;
/// Letters, digits and the symbols every site accepts.
const ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";

/// A fresh password from the OS random source, each character drawn uniformly by
/// rejection: a plain `byte % len` would favour the front of the alphabet.
pub fn generate_password() -> Result<Zeroizing<String>, Error> {
    // Bytes at or past this would wrap unevenly onto the alphabet: drawn again.
    let limit = 256 - 256 % ALPHABET.len();
    let mut out = Zeroizing::new(String::with_capacity(GENERATED_LEN));
    let mut pool = Zeroizing::new([0u8; 64]);
    while out.len() < GENERATED_LEN {
        getrandom::getrandom(&mut *pool)
            .map_err(|e| Error::Value(format!("no random source: {e}")))?;
        for b in pool.iter().map(|b| usize::from(*b)).filter(|b| *b < limit) {
            if out.len() == GENERATED_LEN {
                break;
            }
            out.push(char::from(ALPHABET[b % ALPHABET.len()]));
        }
    }
    Ok(out)
}

/// A question with a few answers, picked with the arrow keys, starting on the first:
/// each option is (what it means, its name, a description), and what it means is what
/// comes back - so a caller never maps an index. None on Esc or Ctrl-C. Only the
/// answer stays on screen. Works inside the shell's raw mode and on a plain terminal.
pub fn choose<T: Copy>(label: &str, options: &[(T, &str, &str)]) -> Option<T> {
    if options.is_empty() {
        return None;
    }
    let was_raw = terminal::is_raw_mode_enabled().unwrap_or(false);
    if !was_raw && terminal::enable_raw_mode().is_err() {
        return None;
    }
    let chosen = pick(label, options);
    if !was_raw {
        let _ = terminal::disable_raw_mode();
    }
    chosen
}

fn pick<T: Copy>(label: &str, options: &[(T, &str, &str)]) -> Option<T> {
    let count = options.len();
    let mut so = io::stdout();
    let _ = queue!(
        so,
        SetForegroundColor(ACCENT),
        Print("  ▸ "),
        ResetColor,
        Print(label),
        Print("\r\n")
    );
    let name_w = options
        .iter()
        .map(|(_, name, _)| name.chars().count())
        .max()
        .unwrap_or(0);
    let width = terminal::size()
        .map_or(80, |(c, _)| usize::from(c))
        .saturating_sub(1);
    let rows = u16::try_from(count).unwrap_or(u16::MAX);
    let draw = |so: &mut io::Stdout, sel: usize| {
        for (i, (_, name, desc)) in options.iter().enumerate() {
            let line: String = format!("    {name:<name_w$}  {desc}")
                .chars()
                .take(width)
                .collect();
            let _ = queue!(
                so,
                Clear(ClearType::CurrentLine),
                SetForegroundColor(if i == sel { ACCENT } else { DIM }),
                SetAttribute(if i == sel {
                    Attribute::Bold
                } else {
                    Attribute::Reset
                }),
                Print(line),
                SetAttribute(Attribute::Reset),
                ResetColor,
                Print("\r\n")
            );
        }
        let _ = so.flush();
    };
    let mut sel = 0;
    draw(&mut so, sel);
    let chosen = loop {
        let Ok(Event::Key(key)) = event::read() else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match (key.code, key.modifiers) {
            (KeyCode::Enter, _) => break Some(sel),
            (KeyCode::Esc, _) | (KeyCode::Char('c' | 'd'), KeyModifiers::CONTROL) => {
                break None;
            }
            (KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k'), _) => {
                sel = (sel + count - 1) % count;
            }
            (KeyCode::Down | KeyCode::Tab | KeyCode::Char('j'), _) => {
                sel = (sel + 1) % count;
            }
            _ => {}
        }
        let _ = queue!(so, MoveUp(rows));
        draw(&mut so, sel);
    };
    let _ = queue!(
        so,
        MoveUp(rows + 1),
        MoveToColumn(0),
        Clear(ClearType::FromCursorDown),
        SetForegroundColor(ACCENT),
        Print("  ▸ "),
        ResetColor,
        Print(label),
        Print(" "),
        SetForegroundColor(DIM),
        Print(chosen.map_or("never mind", |i| options[i].1)),
        ResetColor,
        Print("\r\n")
    );
    let _ = so.flush();
    chosen.map(|i| options[i].0)
}

/// A yes/no question that starts on "no": destructive answers take a keystroke.
/// Without a terminal there is no asking; `--yes` says it up front.
pub fn confirm(question: &str, assume_yes: bool) -> Result<bool, Error> {
    if assume_yes {
        return Ok(true);
    }
    if !is_tty() {
        return Err(Error::Value(
            "this needs confirmation; pass --yes when there is no terminal".into(),
        ));
    }
    Ok(yes_no(question))
}

/// A yes/no question that starts on "no": destructive answers take a keystroke.
pub fn yes_no(question: &str) -> bool {
    choose(question, &[(false, "no", ""), (true, "yes", "")]) == Some(true)
}

/// How long a copied password stays in the clipboard.
pub const CLIPBOARD_SECS: u32 = 30;

/// A password into the clipboard for `CLIPBOARD_SECS`: what to tell the person, or
/// None when no clipboard tool was found.
pub fn copy_secret(text: &str) -> Option<String> {
    copy_to_clipboard(text, Some(CLIPBOARD_SECS))
        .then(|| format!("copied; the clipboard is cleared in {CLIPBOARD_SECS} s"))
}

/// Best effort: Wayland, then X11, then the Mac. Quietly does nothing elsewhere. With
/// `clear_after` seconds, a detached shell empties the clipboard again: a password is
/// not something to leave lying around in it.
pub fn copy_to_clipboard(text: &str, clear_after: Option<u32>) -> bool {
    const TOOLS: [(&str, &[&str], &str); 3] = [
        ("wl-copy", &[], "wl-copy --clear"),
        (
            "xclip",
            &["-selection", "clipboard"],
            "xclip -selection clipboard </dev/null",
        ),
        ("pbcopy", &[], "pbcopy </dev/null"),
    ];
    for (cmd, args, clear) in TOOLS {
        let Ok(mut child) = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        if !child.wait().is_ok_and(|s| s.success()) {
            return false;
        }
        if let Some(secs) = clear_after {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!("sleep {secs}; {clear}"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
        return true;
    }
    false
}

/// Attempts left at which the PIN prompt starts warning about the wipe.
pub const WARN_AT: u8 = 2;

/// Where a PIN prompt talks to the person: the plain terminal, or the shell's frame.
pub trait PinPrompt {
    /// The PIN, hidden; None when the person gives up.
    fn ask_pin(&mut self) -> Option<Zeroizing<String>>;
    /// A warning or a refusal, one line.
    fn say(&mut self, line: &str);
}

/// Asks for the PIN until the device unlocks, the person gives up, or it wipes. The
/// one place that knows the retry policy: a wrong PIN and a malformed one both ask
/// again; anything else is the device's answer and comes back as is.
pub fn unlock_loop(dev: &mut Device, ui: &mut dyn PinPrompt) -> Result<(), Error> {
    let st = dev.pin_status()?;
    if !st.has_pin {
        return Err(Error::Value("no PIN set yet: run 'pin set' first".into()));
    }
    let mut left = st.retries_left;
    loop {
        if left <= WARN_AT {
            ui.say(&format!(
                "{left} attempt{} left before the device wipes itself",
                if left == 1 { "" } else { "s" }
            ));
        }
        let Some(text) = ui.ask_pin() else {
            return Err(Error::Value("no PIN entered".into()));
        };
        let unlocked = match pin(&text) {
            Ok(p) => dev.pin_unlock(p),
            Err(e) => Err(e),
        };
        match unlocked {
            Ok(()) => return Ok(()),
            Err(Error::WrongPin(n)) => {
                ui.say(&Error::WrongPin(n).to_string());
                left = n;
            }
            Err(Error::Value(m)) => ui.say(&m), // not even 6-8 digits: nothing was sent
            Err(e) => return Err(e),
        }
    }
}

/// The plain terminal's PIN prompt: hidden input, warnings on stderr. A piped PIN
/// that is wrong cannot be corrected: the second ask finds stdin empty and gives up.
struct Terminal;

impl PinPrompt for Terminal {
    fn ask_pin(&mut self) -> Option<Zeroizing<String>> {
        prompt_secret("PIN").ok()
    }

    fn say(&mut self, line: &str) {
        eprintln!("{line}");
    }
}

pub fn unlock_interactive(dev: &mut Device) -> Result<(), Error> {
    unlock_loop(dev, &mut Terminal)
}

/// Unlocks first if the device is locked, then runs `f`. Checking status up front keeps
/// the order sane: the PIN prompt comes before any "press the button" hint, and a key
/// without a PIN yet says so instead of "locked".
pub fn with_unlock<T>(
    dev: &mut Device,
    f: impl FnOnce(&mut Device) -> Result<T, Error>,
) -> Result<T, Error> {
    let st = dev.pin_status()?;
    if !st.has_pin {
        return Err(Error::Value("no PIN set yet: run 'pin set' first".into()));
    }
    if !st.unlocked {
        unlock_interactive(dev)?;
    }
    f(dev)
}
