//! Interactive mode: what `vkey` does when given no arguments.
//!
//! An input line between two rules with the board's state right under it, a command
//! menu that opens as you type `/`, arrow keys to pick, questions instead of flags.
//! Drawn directly with crossterm: the frame is always exactly as tall as it needs to
//! be, the transcript scrolls above it, and a resize is handled by erasing the old
//! frame from a known geometry and drawing it again - nothing is left to a widget
//! library's guesses.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::cursor::{MoveDown, MoveToColumn, MoveUp};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::terminal::{self, Clear, ClearType};
use crossterm::{execute, queue};

use zeroize::Zeroizing;

use crate::device::{
    Device, Entry, EnvBlob, Error, Kind, MAX_ATTEMPTS, Stored, describe, find_port, passphrase,
    password_blob, pin,
};
use crate::prompt::{ACCENT, DIM, PinPrompt, WARN_AT, copy_secret, copy_to_clipboard};
use crate::{backup, import, prompt, setup, totp};

/// Commands live behind `/`; a bare word is the name of an entry to use.
const COMMANDS: &[(&str, &str)] = &[
    (
        "list",
        "the stored entries, a tab per kind: ← → switch, Enter uses, typing searches, a adds, e edits, d deletes, i imports",
    ),
    ("unlock", "enter the PIN now"),
    ("lock", "forget the key until the next PIN"),
    ("pin", "set or change the PIN"),
    (
        "wipe",
        "factory reset - every secret and the PIN; the button is held, not tapped",
    ),
    (
        "setup",
        "flash a new board with the built-in firmware, set its PIN, self-test",
    ),
    (
        "selftest",
        "one live code against an independent HMAC; one tap",
    ),
    (
        "backup",
        "every entry and .env into one file, sealed on the key under a passphrase; two taps",
    ),
    (
        "restore",
        "every entry and .env out of a backup file onto this key; PIN and the passphrase",
    ),
];
/// Reached from the list with a, e, d and i, never offered as commands: an entry has
/// one place, and the list is it. They still resolve when typed, so the transcript's
/// `❯ /rm name` is a line that would work.
const LIST_COMMANDS: &[&str] = &["add", "edit", "rm", "import"];
const SETTLE: Duration = Duration::from_millis(120);

// The palette Claude Code uses: one warm accent (ACCENT and DIM live in prompt.rs),
// everything else grey or semantic.
const RULE: Color = Color::Rgb {
    r: 0x5f,
    g: 0x5f,
    b: 0x5f,
};
const PLACEHOLDER: Color = Color::Rgb {
    r: 0x6c,
    g: 0x6c,
    b: 0x6c,
};

/// After a `.env` is sealed: the shell never saw where it was pasted from, so it can
/// only say that the place still has it.
const PLAIN_TEXT_LEFT: &str =
    "  wherever it was pasted from - the file, the clipboard - still holds it in plain text";

/// What an inline field shows back: the text, stars, or stars with Ctrl-G on offer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Plain,
    Hidden,
    NewPassword,
}

/// What came out of a field: typed, or generated on Ctrl-G - which is shown in clear
/// and needs no second typing.
enum Answer {
    Typed(Zeroizing<String>),
    Generated(Zeroizing<String>),
}

impl Answer {
    fn text(&self) -> &str {
        match self {
            Answer::Typed(t) | Answer::Generated(t) => t,
        }
    }

    fn into_text(self) -> Zeroizing<String> {
        match self {
            Answer::Typed(t) | Answer::Generated(t) => t,
        }
    }
}

/// Bytes off the device as text that scrubs itself; a stray byte becomes U+FFFD
/// rather than an error, since it is only shown.
fn lossy(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(String::from_utf8_lossy(bytes).into_owned())
}

/// One character of text being typed or pasted, on the indented lines of `ask_lines`.
/// A CR is kept in the text but not echoed: on screen it would rewind the line.
fn echo_env(so: &mut io::Stdout, c: char) {
    let _ = match c {
        '\n' => queue!(so, Print("\r\n    ")),
        '\r' => Ok(()),
        c => queue!(so, Print(c)),
    };
}

/// A rule across `w` columns with `label` dim near its right end, clipped so the row
/// never wraps.
fn rule(so: &mut io::Stdout, w: usize, label: &str) {
    let label: String = label.chars().take(w.saturating_sub(3)).collect();
    let dashes = w.saturating_sub(label.chars().count() + 3);
    let _ = queue!(
        so,
        SetForegroundColor(RULE),
        Print("─".repeat(dashes)),
        SetForegroundColor(DIM),
        Print(label),
        SetForegroundColor(RULE),
        Print("───"),
        ResetColor,
        Print("\r\n")
    );
}

/// Raw mode for as long as this lives; restored even on early return or panic.
struct RawMode;

impl RawMode {
    fn enter() -> io::Result<RawMode> {
        terminal::enable_raw_mode()?;
        Ok(RawMode)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn resolve_command(word: &str) -> Option<&'static str> {
    let w = word.to_ascii_lowercase();
    if let Some(n) = LIST_COMMANDS
        .iter()
        .copied()
        .chain(COMMANDS.iter().map(|(n, _)| *n))
        .find(|n| *n == w)
    {
        return Some(n);
    }
    let hits: Vec<&str> = COMMANDS
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| n.starts_with(&w))
        .collect();
    if hits.len() == 1 { Some(hits[0]) } else { None }
}

/// A terminal column or row count; the terminal cannot be wider than this anyway.
fn cell(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Greedy word wrap to `width` columns. A single word longer than the width keeps its
/// own line and is clipped where it is printed.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split(' ') {
        let line = lines.last_mut().expect("starts with one line");
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(word.to_string());
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    lines
}

struct Menu {
    items: Vec<(String, String)>, // text to complete to, description
    selected: Option<usize>,
    /// The first item shown: the window scrolls so the selection stays visible.
    first: usize,
    kind: MenuKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MenuKind {
    /// `/` and a prefix: commands to complete.
    Commands,
    /// A typed prefix: entry names to complete.
    Names,
    /// `/list`: one tab of entries, where a, e and d act even with nothing highlighted.
    List(Tab),
}

#[derive(Clone, Copy)]
enum Dir {
    Next,
    Prev,
}

/// The tabs of `/list`, in the order ← and → walk them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Totp,
    Password,
    Env,
}

const TABS: [Tab; 3] = [Tab::Totp, Tab::Password, Tab::Env];

impl Tab {
    fn of(kind: Kind) -> Tab {
        match kind {
            Kind::Totp(_) => Tab::Totp,
            Kind::Password => Tab::Password,
            Kind::Env => Tab::Env,
        }
    }

    fn what(self) -> &'static str {
        match self {
            Tab::Totp => "a TOTP code",
            Tab::Password => "a password",
            Tab::Env => "a .env",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Tab::Totp => "TOTP",
            Tab::Password => "Passwords",
            Tab::Env => "ENV",
        }
    }

    /// The neighbour in `TABS`, wrapping at either end.
    fn shift(self, dir: Dir) -> Tab {
        let i = TABS
            .iter()
            .position(|&t| t == self)
            .expect("every tab is in TABS");
        let n = TABS.len();
        TABS[match dir {
            Dir::Next => (i + 1) % n,
            Dir::Prev => (i + n - 1) % n,
        }]
    }
}

/// One frame row from coloured pieces, never wider than `w`: a wrapped row pushes the
/// rules apart, and `MoveUp` by frame rows then lands on the wrong line.
fn print_row(so: &mut io::Stdout, w: usize, parts: &[(Color, String)]) {
    let mut left = w;
    for (color, text) in parts {
        let t: String = text.chars().take(left).collect();
        left -= t.chars().count();
        let _ = queue!(so, SetForegroundColor(*color), Print(t));
        if left == 0 {
            break;
        }
    }
    let _ = queue!(so, ResetColor);
}

/// What a keypress did to the input line.
enum Key {
    Quit,
    Redraw,
    Submit(String),
    /// `a` on a tab of the list: the tab already says what to store.
    Add(Tab),
}

pub struct Shell {
    dev: Option<Device>,
    port: String,
    version: Option<String>,
    entries: Vec<Stored>,
    unlocked: bool,
    has_pin: bool,
    retries: u8,
    input: String,
    cursor: usize,
    history: Vec<String>,
    hist_pos: Option<usize>,
    menu: Option<Menu>,
    /// Rows of the frame on screen, and the terminal width it was drawn for.
    frame_rows: u16,
    drawn_width: u16,
}

pub fn run(dev: Device, version: Option<String>) -> Result<u8, Error> {
    let port = dev.path.clone();
    let mut shell = Shell {
        dev: Some(dev),
        port,
        version,
        entries: Vec::new(),
        unlocked: false,
        has_pin: true,
        retries: MAX_ATTEMPTS,
        input: String::new(),
        cursor: 0,
        history: Vec::new(),
        hist_pos: None,
        menu: None,
        frame_rows: 0,
        drawn_width: 0,
    };
    shell.main_loop()
}

impl PinPrompt for Shell {
    fn ask_pin(&mut self) -> Option<Zeroizing<String>> {
        self.ask("PIN: ", Field::Hidden)
    }

    fn say(&mut self, line: &str) {
        self.line(Color::Red, &format!("  {line}"));
    }
}

impl setup::ProvisionUi for Shell {
    fn say(&mut self, line: &str) {
        self.line(DIM, line);
    }

    fn keep_existing(&mut self) -> bool {
        self.choose(
            "this board already has a PIN and maybe credentials",
            &[
                (true, "keep them", ""),
                (false, "wipe them", "the button held five seconds"),
            ],
        ) != Some(false)
    }

    fn set_pin(&mut self, dev: &mut Device) -> Result<(), Error> {
        self.line(DIM, "  now choose a PIN; 8 digits is the sensible length");
        self.pin_flow(dev)
    }

    fn unlock(&mut self, dev: &mut Device) -> Result<(), Error> {
        prompt::unlock_loop(dev, self)?;
        self.unlocked = true;
        Ok(())
    }
}

impl Shell {
    // --- terminal primitives ------------------------------------------------------

    /// One column less than the terminal, and every frame row is clipped to it: a row
    /// that reaches the last column leaves the cursor in the terminal's pending-wrap
    /// state, and a longer one wraps, so `MoveUp` by frame rows lands on the wrong
    /// line and each status tick leaks a row. The floor is what the rule tails need.
    fn width() -> usize {
        terminal::size().map_or(80, |(c, _)| usize::from(c)).max(4) - 1
    }

    fn rows() -> usize {
        terminal::size().map_or(24, |(_, r)| usize::from(r))
    }

    /// Transcript line, printed above the frame (raw mode wants explicit \r\n).
    fn out(&mut self, parts: &[(Color, &str)]) {
        let mut so = io::stdout();
        if self.frame_rows > 0 {
            self.erase_frame(&mut so);
        }
        for (color, text) in parts {
            let _ = queue!(so, SetForegroundColor(*color), Print(text));
        }
        let _ = queue!(so, ResetColor, Print("\r\n"));
        let _ = so.flush();
        if self.frame_rows > 0 {
            self.draw_frame(&mut so);
        }
    }

    fn line(&mut self, color: Color, text: &str) {
        self.out(&[(color, text)]);
    }

    /// From the caret on the input row up to the frame's top, then clear downwards.
    fn erase_frame(&mut self, so: &mut io::Stdout) {
        let _ = queue!(
            so,
            MoveUp(1),
            MoveToColumn(0),
            Clear(ClearType::FromCursorDown)
        );
        self.frame_rows = 0;
    }

    /// The menu as physical lines: the name column, then the description wrapped to
    /// what is left of the width, continuation lines indented under it. Nothing is cut
    /// off; a terminal too short for the whole menu shows a window that scrolls with
    /// the arrow keys so the selected item is always in it.
    fn menu_lines(&mut self, w: usize) -> Vec<(bool, String)> {
        let cap = Self::rows().saturating_sub(5 + usize::from(self.tab().is_some()));
        let Some(m) = self.menu.as_mut() else {
            return Vec::new();
        };
        let name_w = m
            .items
            .iter()
            .map(|(t, _)| t.chars().count())
            .max()
            .unwrap_or(0);
        let indent = 3 + name_w + 2;
        let room = w.saturating_sub(indent).max(10);
        let wrapped: Vec<Vec<String>> = m.items.iter().map(|(_, d)| wrap(d, room)).collect();

        // Scroll the window just enough for the selection to be inside it.
        if let Some(sel) = m.selected {
            m.first = m.first.min(sel);
            let height = |from: usize| wrapped[from..=sel].iter().map(Vec::len).sum::<usize>();
            while m.first < sel && height(m.first) > cap {
                m.first += 1;
            }
        } else {
            m.first = 0;
        }

        let mut lines = Vec::new();
        for (i, (text, _)) in m.items.iter().enumerate().skip(m.first) {
            let selected = m.selected == Some(i);
            for (n, chunk) in wrapped[i].iter().enumerate() {
                let line = if n == 0 {
                    format!("   {text:<name_w$}  {chunk}")
                } else {
                    format!("{:indent$}{chunk}", "")
                };
                lines.push((selected, line));
                if lines.len() >= cap {
                    return lines;
                }
            }
        }
        lines
    }

    /// Draws the frame at the cursor and leaves the cursor on the caret.
    fn draw_frame(&mut self, so: &mut io::Stdout) {
        let w = Self::width();
        self.drawn_width = cell(w + 1);
        let fit = |s: &str, n: usize| -> String { s.chars().take(n).collect() };

        // Top rule with the firmware label near the right end.
        let label = format!(" {} ", self.version.as_deref().unwrap_or("no firmware"));
        let _ = queue!(so, MoveToColumn(0));
        rule(so, w, &label);

        // Input line.
        let _ = queue!(
            so,
            SetForegroundColor(ACCENT),
            SetAttribute(Attribute::Bold),
            Print("❯ "),
            SetAttribute(Attribute::Reset),
            ResetColor
        );
        let room = w.saturating_sub(2);
        if self.input.is_empty() {
            let _ = queue!(
                so,
                SetForegroundColor(PLACEHOLDER),
                SetAttribute(Attribute::Italic),
                Print(fit("a name to use it, / for commands", room)),
                SetAttribute(Attribute::Reset),
                ResetColor
            );
        } else {
            let _ = queue!(so, Print(fit(&self.input, room)));
        }
        let _ = queue!(so, Print("\r\n"));

        // The list's tabs, one row: the open one in the accent, the rest dim.
        let tab = self.tab();
        if let Some(open) = tab {
            let mut parts = vec![(Color::Reset, "   ".to_string())];
            for (i, t) in TABS.iter().enumerate() {
                if i > 0 {
                    parts.push((DIM, " · ".into()));
                }
                parts.push((if *t == open { ACCENT } else { DIM }, t.label().into()));
            }
            print_row(so, w, &parts);
            let _ = queue!(so, Print("\r\n"));
        }

        // Menu rows.
        let menu = self.menu_lines(w);
        for (selected, line) in &menu {
            let _ = queue!(
                so,
                SetForegroundColor(if *selected {
                    ACCENT
                } else {
                    Color::Rgb {
                        r: 0xc0,
                        g: 0xc0,
                        b: 0xc0,
                    }
                }),
                SetAttribute(if *selected {
                    Attribute::Bold
                } else {
                    Attribute::Reset
                }),
                Print(fit(line, w)),
                SetAttribute(Attribute::Reset),
                ResetColor,
                Print("\r\n")
            );
        }

        // Bottom rule; with the list open it carries the key legend, near the right end
        // like the firmware label above, so the keys show whatever the status row's
        // width leaves.
        let legend = match (self.letters_act(), tab.is_some()) {
            (true, true) => {
                " Enter use · type to search · a add · e edit · d delete · i import · ← → tab "
            }
            (true, false) => " Enter use · a add · e edit · d delete · i import ",
            (false, _) => "",
        };
        rule(so, w, legend);
        self.draw_status(so, w);

        self.frame_rows = cell(4 + usize::from(tab.is_some()) + menu.len());
        let caret = 2 + self.input[..self.cursor].chars().count();
        let _ = queue!(
            so,
            MoveUp(self.frame_rows - 2),
            MoveToColumn(cell(caret.min(w)))
        );
        let _ = so.flush();
    }

    fn connected(&self) -> bool {
        Path::new(&self.port).exists()
    }

    fn draw_status(&self, so: &mut io::Stdout, w: usize) {
        let mut parts: Vec<(Color, String)> = Vec::new();
        if self.connected() {
            parts.push((Color::Green, "  ● ".into()));
            parts.push((Color::Reset, format!("connected {}", self.port)));
            parts.push((DIM, "   │   ".into()));
            if self.version.is_none() {
                parts.push((Color::Yellow, "no firmware - /setup".into()));
            } else {
                parts.push((
                    if self.unlocked {
                        Color::Green
                    } else {
                        Color::Yellow
                    },
                    if self.unlocked { "unlocked" } else { "locked" }.into(),
                ));
                if self.unlocked {
                    let n = self.entries.len();
                    parts.push((
                        Color::Reset,
                        format!(" · {n} entr{}", if n == 1 { "y" } else { "ies" }),
                    ));
                }
                if !self.has_pin {
                    parts.push((Color::Yellow, " · no PIN - run /pin".into()));
                } else if self.retries < MAX_ATTEMPTS {
                    parts.push((
                        if self.retries <= WARN_AT {
                            Color::Red
                        } else {
                            Color::Yellow
                        },
                        format!(" · {} PIN attempts left", self.retries),
                    ));
                }
            }
        } else {
            parts.push((Color::Red, "  ○ ".into()));
            parts.push((Color::Reset, "board disconnected - plug it back in".into()));
        }
        let used: usize = parts.iter().map(|(_, t)| t.chars().count()).sum();
        // The list's keys live on the rule above, where width cannot push them out.
        let hint = "/ commands · Ctrl-D quits";
        if !self.letters_act() && w > used + hint.len() + 2 {
            parts.push((DIM, format!("{}{hint}", " ".repeat(w - used - hint.len()))));
        }
        print_row(so, w, &parts);
    }

    /// Re-paints only the status row (the liveness tick), leaving the caret alone. The
    /// device locks itself after two idle minutes, so the row asks it first: `PinStatus`
    /// is the one request that does not count as activity there.
    fn refresh_status(&mut self) {
        if self.frame_rows == 0 {
            return;
        }
        self.poll_lock();
        let mut so = io::stdout();
        let down = self.frame_rows - 2;
        let w = Self::width();
        let _ = queue!(
            so,
            MoveDown(down),
            MoveToColumn(0),
            Clear(ClearType::CurrentLine)
        );
        self.draw_status(&mut so, w);
        let caret = 2 + self.input[..self.cursor].chars().count();
        let _ = queue!(so, MoveUp(down), MoveToColumn(cell(caret.min(w))));
        let _ = so.flush();
    }

    /// The lock state as the device sees it now, into the status row; with `relist`,
    /// the names too. A flip of the lock re-lists on its own: a lock empties them. A
    /// device that does not answer is the disconnect case, drawn as such.
    fn sync(&mut self, relist: bool) {
        if self.version.is_none() {
            return;
        }
        let Some(dev) = self.dev.as_mut() else {
            return;
        };
        let Ok(st) = dev.pin_status() else {
            return;
        };
        let flipped = st.unlocked != self.unlocked;
        self.unlocked = st.unlocked;
        self.has_pin = st.has_pin;
        self.retries = st.retries_left;
        if relist || flipped {
            // Names need the PIN too: while locked there is nothing to show or complete.
            self.entries = dev.list().unwrap_or_default();
        }
    }

    fn poll_lock(&mut self) {
        self.sync(false);
    }

    /// After a resize burst: the terminal may have re-wrapped the old top rule, so
    /// count how many physical lines it takes now and erase from its real top.
    fn redraw_after_resize(&mut self) {
        let mut so = io::stdout();
        if self.frame_rows > 0 {
            let new_w = terminal::size().map_or(80, |(c, _)| usize::from(c)).max(1);
            let old_rule = usize::from(self.drawn_width).saturating_sub(1).max(1);
            let lines_of_rule = cell(old_rule.div_ceil(new_w));
            let _ = queue!(
                so,
                MoveUp(lines_of_rule),
                MoveToColumn(0),
                Clear(ClearType::FromCursorDown)
            );
            self.frame_rows = 0;
        }
        self.menu = None;
        self.draw_frame(&mut so);
    }

    // --- device state ---------------------------------------------------------------

    fn refresh(&mut self) {
        self.sync(true);
    }

    fn dev(&mut self) -> Result<&mut Device, Error> {
        self.dev.as_mut().ok_or(Error::NoBoard)
    }

    /// How to name the button on the board in front of the user; the board says what is
    /// printed on it.
    fn button(&self) -> String {
        crate::boards::button(self.version.as_deref())
    }

    /// After an unplug the port is gone and the board rebooted locked; come back on
    /// whatever port it has now.
    fn reconnect(&mut self) -> bool {
        self.dev = None;
        let Some(port) = find_port() else {
            return false;
        };
        let Ok(mut d) = Device::open(Some(&port)) else {
            return false;
        };
        self.version = d.probe();
        self.port = port;
        self.dev = Some(d);
        self.refresh();
        true
    }

    // --- questions --------------------------------------------------------------------

    /// One inline question below the transcript. Empty answer or Ctrl-C means "never mind".
    /// The answer scrubs itself when dropped: PINs and secrets come through here.
    fn ask(&mut self, label: &str, kind: Field) -> Option<Zeroizing<String>> {
        self.field(label, kind).map(Answer::into_text)
    }

    /// `ask` with the field's kind spelled out; a `NewPassword` field answers at once
    /// on Ctrl-G with a generated password, shown in clear - it has to be read off
    /// the screen to reach the site.
    fn field(&mut self, label: &str, kind: Field) -> Option<Answer> {
        let mut so = io::stdout();
        if self.frame_rows > 0 {
            self.erase_frame(&mut so);
        }
        let _ = queue!(
            so,
            SetForegroundColor(ACCENT),
            Print("  ▸ "),
            ResetColor,
            Print(label)
        );
        let _ = so.flush();
        let mut buf = Zeroizing::new(String::new());
        let answer = loop {
            let Ok(Event::Key(k)) = event::read() else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match (k.code, k.modifiers) {
                (KeyCode::Enter, _) => {
                    // A shown answer is a name or a login, where a stray space is a
                    // slip; a hidden one is a PIN or a password, taken as typed.
                    let text = if kind == Field::Plain {
                        buf.trim()
                    } else {
                        &buf
                    };
                    break Some(Answer::Typed(Zeroizing::new(text.to_string())));
                }
                (KeyCode::Esc, _) | (KeyCode::Char('c' | 'd'), KeyModifiers::CONTROL) => {
                    break None;
                }
                (KeyCode::Backspace, _) => {
                    if buf.pop().is_some() {
                        let _ = execute!(so, Print("\x08 \x08"));
                    }
                }
                (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                    let n = buf.chars().count();
                    buf.clear();
                    let _ = execute!(so, Print("\x08 \x08".repeat(n)));
                }
                (KeyCode::Char('g'), KeyModifiers::CONTROL) if kind == Field::NewPassword => {
                    let n = buf.chars().count();
                    let _ = execute!(so, Print("\x08 \x08".repeat(n)));
                    match prompt::generate_password() {
                        Ok(pw) => {
                            let _ = execute!(
                                so,
                                SetForegroundColor(Color::Green),
                                Print(&*pw),
                                ResetColor
                            );
                            break Some(Answer::Generated(pw));
                        }
                        Err(e) => {
                            let _ = execute!(
                                so,
                                SetForegroundColor(Color::Red),
                                Print(e.to_string()),
                                ResetColor
                            );
                            break None;
                        }
                    }
                }
                (KeyCode::Char(c), m) if !m.contains(KeyModifiers::CONTROL) => {
                    buf.push(c);
                    let _ = execute!(so, Print(if kind == Field::Plain { c } else { '*' }));
                }
                _ => {}
            }
        };
        let _ = execute!(so, Print("\r\n"));
        answer.filter(|a| !a.text().is_empty())
    }

    /// A question with a few answers under the arrow keys, below the transcript; the
    /// picker itself is `prompt::choose`, shared with the one-shot commands.
    fn choose<T: Copy>(&mut self, label: &str, options: &[(T, &str, &str)]) -> Option<T> {
        if self.frame_rows > 0 {
            let mut so = io::stdout();
            self.erase_frame(&mut so);
            let _ = so.flush();
        }
        prompt::choose(label, options)
    }

    /// A yes/no question that starts on "no": destructive answers take a keystroke.
    fn ask_yes(&mut self, question: &str) -> bool {
        self.choose(question, &[(false, "no", ""), (true, "yes", "")]) == Some(true)
    }

    /// The device, borrowed out of the shell for a call that also needs the shell as
    /// its prompt - the PIN loop - and put back whatever happened.
    fn with_dev<T>(&mut self, f: impl FnOnce(&mut Self, &mut Device) -> T) -> Result<T, Error> {
        let mut dev = self.dev.take().ok_or(Error::NoBoard)?;
        let r = f(self, &mut dev);
        self.dev = Some(dev);
        Ok(r)
    }

    // --- PIN --------------------------------------------------------------------------

    /// The shared PIN loop (`prompt::unlock_loop`), asking in the frame.
    fn unlock(&mut self) -> Result<(), Error> {
        self.with_dev(|sh, dev| prompt::unlock_loop(dev, sh))??;
        self.unlocked = true;
        Ok(())
    }

    fn ensure_unlocked(&mut self) -> Result<(), Error> {
        let st = self.dev()?.pin_status()?;
        if st.has_pin && !st.unlocked {
            self.unlock()?;
        }
        Ok(())
    }

    /// The hints the shell prints before the board waits for the button.
    fn tap_hint(&mut self, extra: &str) {
        let hint = format!("  ● tap {} on the board{extra}", self.button());
        self.line(Color::Yellow, &hint);
    }

    fn hold_hint(&mut self, extra: &str) {
        let hint = format!(
            "  ● hold {} on the board down for five seconds{extra}",
            self.button()
        );
        self.line(Color::Red, &hint);
    }

    // --- commands ---------------------------------------------------------------------

    /// A credential by name or unique prefix - or, given nothing, by asking.
    fn pick(&mut self, arg: &str, verb: &str) -> Result<Option<String>, Error> {
        self.entries = self.dev()?.list()?;
        if self.entries.is_empty() {
            self.line(DIM, "  nothing stored yet - Enter lists, a adds");
            return Ok(None);
        }
        if arg.is_empty() {
            if let [only] = self.entries.as_slice() {
                return Ok(Some(only.name.clone())); // one entry needs no question
            }
            let described: Vec<(String, String)> = self
                .entries
                .iter()
                .map(|e| (e.name.clone(), describe(e.kind)))
                .collect();
            let options: Vec<(usize, &str, &str)> = described
                .iter()
                .enumerate()
                .map(|(i, (n, d))| (i, n.as_str(), d.as_str()))
                .collect();
            return Ok(self
                .choose(&format!("{verb} which?"), &options)
                .map(|i| self.entries[i].name.clone()));
        }
        let hits = self.matching_entries(arg);
        match hits.as_slice() {
            [(only, _)] => return Ok(Some(only.clone())),
            [(exact, _), ..] if exact == arg.trim() => {
                return Ok(Some(exact.clone()));
            }
            _ => {}
        }
        let names: Vec<&str> = hits.iter().map(|(n, _)| n.as_str()).collect();
        self.line(
            Color::Red,
            &if names.is_empty() {
                format!("  no such credential: {arg}")
            } else {
                format!("  ambiguous: {}", names.join(", "))
            },
        );
        Ok(None)
    }

    /// A name: the entry does what its kind does - a code after a tap, or the login
    /// and, after a tap, the password.
    fn cmd_use(&mut self, arg: &str) -> Result<(), Error> {
        self.ensure_unlocked()?;
        let Some(name) = self.pick(arg, "use")? else {
            return Ok(());
        };
        let stored = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .cloned()
            .ok_or(Error::NotFound)?;
        match stored.kind {
            Kind::Totp(p) => self.use_totp(&name, p),
            Kind::Password => self.use_password(&name),
            Kind::Env => self.use_env(&name),
        }
    }

    fn use_totp(&mut self, name: &str, p: crate::device::Params) -> Result<(), Error> {
        self.tap_hint("");
        let code = self.dev()?.code(name, None)?;
        let remaining = totp::seconds_left(p);
        let copied = copy_to_clipboard(&code, None);
        self.line(Color::Reset, "");
        let tail = format!(
            "    valid {remaining}s{}",
            if copied {
                "  ·  copied to the clipboard"
            } else {
                ""
            }
        );
        self.out(&[(Color::Reset, "    "), (Color::Green, &code), (DIM, &tail)]);
        self.line(Color::Reset, "");
        Ok(())
    }

    /// The stored entries as the menu under the input, the way `/` lists commands, a
    /// tab per kind: ← and → switch the tab, ↑ and ↓ walk it, Enter uses one, typing
    /// narrows across all of them, and on a highlighted row a adds, e edits, d deletes,
    /// i imports - the legend on the rule below says so, which is why the list holds
    /// nothing but entries. An empty vault is an empty tab under that legend.
    fn cmd_list(&mut self) -> Result<(), Error> {
        self.ensure_unlocked()?;
        self.entries = self.dev()?.list()?;
        if self.entries.is_empty() {
            self.line(DIM, "  nothing stored yet - a adds, i imports");
        }
        self.open_tab(Tab::Totp);
        Ok(())
    }

    /// One tab of the list as the menu, nothing highlighted and the input clean: a
    /// name highlighted on another tab would be a stale one.
    fn open_tab(&mut self, tab: Tab) {
        self.input.clear();
        self.cursor = 0;
        self.menu = Some(Menu {
            items: self.tab_entries(tab),
            selected: None,
            first: 0,
            kind: MenuKind::List(tab),
        });
    }

    /// The tab open under the input, if `/list` is what is showing.
    fn tab(&self) -> Option<Tab> {
        match self.menu.as_ref()?.kind {
            MenuKind::List(t) => Some(t),
            MenuKind::Commands | MenuKind::Names => None,
        }
    }

    /// `/add [name]`: asks what to store, then for it. Secrets are always asked for,
    /// hidden: they must not land in the transcript or the history.
    fn cmd_add(&mut self, arg: &str) -> Result<(), Error> {
        let Some(tab) = self.choose(
            "what to store?",
            &[
                (
                    Tab::Totp,
                    "TOTP code",
                    "the second factor a site asks for; a tap per code",
                ),
                (
                    Tab::Password,
                    "password",
                    "a login and a password; the password after a tap",
                ),
                (
                    Tab::Env,
                    "env file",
                    "a project's .env, pasted whole, after a tap; up to 8000 bytes",
                ),
            ],
        ) else {
            return Ok(());
        };
        self.add_kind(tab, arg)
    }

    /// One kind, known: from its tab of the list, or picked under `/add`.
    fn add_kind(&mut self, tab: Tab, arg: &str) -> Result<(), Error> {
        self.ensure_unlocked()?; // PIN first, so a typo there does not cost a pasted secret
        match tab {
            Tab::Totp => self.add_totp(arg),
            Tab::Password => self.add_password(arg),
            Tab::Env => self.add_env(arg),
        }
    }

    fn add_totp(&mut self, arg: &str) -> Result<(), Error> {
        let Some(source) = self.ask(
            "QR text (otpauth://...) or base32 secret, hidden: ",
            Field::Hidden,
        ) else {
            return Ok(());
        };
        let name = if !arg.is_empty() {
            Some(arg.to_string())
        } else if source.starts_with("otpauth://") {
            None
        } else {
            let Some(n) = self.ask("name for it (e.g. github): ", Field::Plain) else {
                return Ok(());
            };
            Some(n.to_string())
        };
        let r = totp::resolve(&source, name.as_deref(), None, None, false)?;
        if !self.store(&r.name, &r.secret, Kind::Totp(r.params))? {
            return Ok(());
        }
        let stored = format!("  stored '{}'", r.name);
        let hint = format!("  -  the site will ask for a code now:  {}", r.name);
        self.out(&[(Color::Green, &stored), (DIM, &hint)]);
        self.line(
            Color::Yellow,
            "  save the site's backup codes: the device keeps none",
        );
        self.refresh();
        Ok(())
    }

    fn add_password(&mut self, arg: &str) -> Result<(), Error> {
        let name = if arg.is_empty() {
            let Some(n) = self.ask("site or account name (e.g. mail): ", Field::Plain) else {
                return Ok(());
            };
            n.to_string()
        } else {
            arg.to_string()
        };
        let login = self
            .ask("login (Enter for none): ", Field::Plain)
            .map_or_else(String::new, |l| l.to_string());
        let Some(pw) = self.ask_new_password() else {
            return Ok(());
        };
        let note = self.ask_note("Enter now skips").unwrap_or_default();
        let blob = password_blob(&name, &login, &pw, &note)?;
        if !self.store(&name, &blob, Kind::Password)? {
            return Ok(());
        }
        let stored = format!("  stored '{name}'");
        let hint = format!("  -  {name} shows the login, then the password and note after a tap");
        self.out(&[(Color::Green, &stored), (DIM, &hint)]);
        self.refresh();
        Ok(())
    }

    /// A `.env`, pasted whole, under a project name. Not through `store`: it is not an
    /// entry, and the device takes it through its own command.
    fn add_env(&mut self, arg: &str) -> Result<(), Error> {
        let name = if arg.is_empty() {
            let Some(n) = self.ask("project name (e.g. myapp): ", Field::Plain) else {
                return Ok(());
            };
            n.to_string()
        } else {
            arg.to_string()
        };
        let Some((text, blob)) = self.env_input()? else {
            return Ok(());
        };
        if !self.store_with(&name, Tab::Env, |d, replace| {
            d.env_put(&name, &blob, replace)
        })? {
            return Ok(());
        }
        let stored = format!("  stored '{name}'");
        let hint = format!("  -  {name} prints the whole file after a tap");
        self.out(&[(Color::Green, &stored), (DIM, &hint)]);
        self.env_preview(&text);
        self.refresh();
        Ok(())
    }

    /// A `.env` pasted below the transcript, as text for the preview and as the checked
    /// blob the device takes; None on Esc.
    fn env_input(&mut self) -> Result<Option<(Zeroizing<String>, EnvBlob)>, Error> {
        let Some(text) =
            self.ask_lines("paste the .env, then Enter on an empty line (Esc cancels)")
        else {
            return Ok(None);
        };
        let blob = EnvBlob::new(Zeroizing::new(text.as_bytes().to_vec()))?;
        Ok(Some((text, blob)))
    }

    /// What the device now holds, shown back right after the store: reading it from
    /// the device again would take a tap.
    fn env_preview(&mut self, text: &str) {
        let lines = text.lines().count();
        let head = format!(
            "  {} bytes, {lines} line{}:",
            text.len(),
            if lines == 1 { "" } else { "s" }
        );
        self.line(DIM, &head);
        self.show_text(text.as_bytes());
        self.line(Color::Yellow, PLAIN_TEXT_LEFT);
    }

    /// Lines pasted or typed below the transcript; Enter on an empty line is the end,
    /// so a blank line inside the text can only arrive by paste. Esc, Ctrl-C or Ctrl-D
    /// means "never mind", as in `ask`. Bracketed paste is on only here, so a paste
    /// lands whole instead of as keystrokes, and an Esc inside it is text, not a
    /// cancel. Backspace stays on its line: going up would mean redrawing, and a paste
    /// is retried, not edited.
    fn ask_lines(&mut self, label: &str) -> Option<Zeroizing<String>> {
        let mut so = io::stdout();
        if self.frame_rows > 0 {
            self.erase_frame(&mut so);
        }
        let _ = execute!(
            so,
            SetForegroundColor(ACCENT),
            Print("  ▸ "),
            ResetColor,
            Print(label),
            Print("\r\n    "),
            EnableBracketedPaste
        );
        let mut buf = Zeroizing::new(String::new());
        let answer = loop {
            let Ok(ev) = event::read() else {
                continue;
            };
            match ev {
                Event::Paste(text) => {
                    let text = Zeroizing::new(text);
                    for c in text.chars() {
                        echo_env(&mut so, c);
                    }
                    let _ = so.flush();
                    buf.push_str(&text);
                }
                Event::Key(k) if k.kind == KeyEventKind::Press => match (k.code, k.modifiers) {
                    (KeyCode::Esc, _) | (KeyCode::Char('c' | 'd'), KeyModifiers::CONTROL) => {
                        break None;
                    }
                    (KeyCode::Enter, _) => {
                        if buf.is_empty() || buf.ends_with('\n') {
                            break Some(buf);
                        }
                        buf.push('\n');
                        echo_env(&mut so, '\n');
                        let _ = so.flush();
                    }
                    (KeyCode::Backspace, _) => {
                        if buf.chars().last().is_some_and(|c| c != '\n') {
                            buf.pop();
                            let _ = execute!(so, Print("\x08 \x08"));
                        }
                    }
                    (KeyCode::Char(c), m) if !m.contains(KeyModifiers::CONTROL) => {
                        buf.push(c);
                        echo_env(&mut so, c);
                        let _ = so.flush();
                    }
                    _ => {}
                },
                _ => {}
            }
        };
        let _ = execute!(so, DisableBracketedPaste, Print("\r\n"));
        answer
    }

    fn show_text(&mut self, blob: &[u8]) {
        let text = lossy(blob);
        for l in text.lines() {
            self.out(&[(DIM, "    "), (Color::Green, l)]);
        }
        self.line(Color::Reset, "");
    }

    /// A device call that comes after a slow prompt - a paste, a password typed twice -
    /// during which the idle timeout may have locked the device: on `Locked`, asks the
    /// PIN and makes the call once more, so what was typed is not lost to the clock.
    fn after_prompt<T>(
        &mut self,
        call: impl Fn(&mut Device) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match call(self.dev()?) {
            Err(Error::Locked) => {
                self.unlock()?;
                call(self.dev()?)
            }
            r => r,
        }
    }

    /// Stores an entry, asking before replacing one with the same name. False if the
    /// user kept the old one.
    fn store(&mut self, name: &str, secret: &[u8], kind: Kind) -> Result<bool, Error> {
        self.store_with(name, Tab::of(kind), |d, replace| {
            d.add(name, secret, kind, replace)
        })
    }

    /// `put` once without replacing; if the name is taken, asks, and once more with
    /// replacing. Entries and `.env` blobs go through different device commands but
    /// the same question.
    fn store_with(
        &mut self,
        name: &str,
        tab: Tab,
        put: impl Fn(&mut Device, bool) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        match self.after_prompt(|d| put(d, false)) {
            Ok(()) => Ok(true),
            Err(Error::Exists) => {
                if !self.replace_ok(name, tab)? {
                    return Ok(false);
                }
                self.after_prompt(|d| put(d, true))?;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// After the device refused a name as taken: whether to store again with replace.
    /// A replace stays within a kind - a password must not quietly take the place of
    /// a .env full of secrets, and the device would refuse it anyway - so another kind
    /// under that name is explained instead of asked about.
    fn replace_ok(&mut self, name: &str, tab: Tab) -> Result<bool, Error> {
        self.entries = self.dev()?.list()?;
        let taken = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| Tab::of(e.kind));
        if let Some(other) = taken.filter(|t| *t != tab) {
            let msg = format!(
                "  '{name}' is already {} - delete it first, or pick another name",
                other.what()
            );
            self.line(Color::Yellow, &msg);
            return Ok(false);
        }
        if !self.ask_yes(&format!("'{name}' already exists - replace it?")) {
            self.line(DIM, "  kept the old one");
            return Ok(false);
        }
        Ok(true)
    }

    /// A password entry by name: the login right away, the password after a tap.
    fn use_password(&mut self, name: &str) -> Result<(), Error> {
        let login = self.dev()?.login(name)?;
        if !login.is_empty() {
            let login = lossy(&login);
            self.out(&[(DIM, "    login     "), (Color::Reset, &login)]);
        }
        self.tap_hint("");
        let entry = self.dev()?.reveal(name)?;
        let text = lossy(entry.password_bytes().unwrap_or_default());
        let tail = copy_secret(&text)
            .map(|n| format!("    {n}"))
            .unwrap_or_default();
        self.out(&[(DIM, "    password  "), (Color::Green, &text), (DIM, &tail)]);
        // The note stays on screen only: recovery codes are read, not pasted.
        let note = entry.note().unwrap_or_default();
        if note.is_empty() {
            self.line(Color::Reset, "");
        } else {
            self.line(DIM, "    note");
            self.show_text(note);
        }
        Ok(())
    }

    /// A `.env`, whole, after a tap: printed line by line, never into the clipboard.
    fn use_env(&mut self, name: &str) -> Result<(), Error> {
        self.tap_hint("");
        let blob = self.dev()?.env_get(name)?;
        self.show_text(&blob);
        Ok(())
    }

    fn cmd_rm(&mut self, arg: &str) -> Result<(), Error> {
        self.ensure_unlocked()?;
        let Some(name) = self.pick(arg, "remove")? else {
            return Ok(());
        };
        if !self.ask_yes(&format!("remove '{name}'? Its secret cannot be recovered.")) {
            self.line(DIM, "  kept");
            return Ok(());
        }
        self.dev()?.delete(&name)?;
        self.line(Color::Green, &format!("  removed '{name}'"));
        self.refresh();
        Ok(())
    }

    /// A new name, secret, login or password for an entry; Enter keeps each as it is,
    /// so a rename never asks for the QR code again. No "replace?" question - editing
    /// is the answer. The contents change first, under the old name; the rename is last.
    fn cmd_edit(&mut self, arg: &str) -> Result<(), Error> {
        self.ensure_unlocked()?;
        let Some(name) = self.pick(arg, "edit")? else {
            return Ok(());
        };
        let kind = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.kind)
            .ok_or(Error::NotFound)?;
        let new_name = self
            .ask(&format!("name (Enter keeps '{name}'): "), Field::Plain)
            .map(|n| n.to_string());
        match kind {
            Kind::Totp(_) => {
                if let Some(source) = self.ask(
                    "new QR text (otpauth://...) or base32 secret, hidden (Enter keeps it): ",
                    Field::Hidden,
                ) {
                    let r = totp::resolve(&source, Some(&name), None, None, false)?;
                    self.after_prompt(|d| d.add(&name, &r.secret, Kind::Totp(r.params), true))?;
                }
            }
            Kind::Password => {
                let current = String::from_utf8_lossy(&self.dev()?.login(&name)?).into_owned();
                let label = if current.is_empty() {
                    "login (Enter for none): ".to_string()
                } else {
                    format!("login (Enter keeps {current}): ")
                };
                let login = self
                    .ask(&label, Field::Plain)
                    .map_or_else(|| current.clone(), |l| l.to_string());
                let typed = match self.field(
                    "password (Enter keeps it, Ctrl-G generates one): ",
                    Field::NewPassword,
                ) {
                    Some(Answer::Generated(pw)) => Some(pw),
                    Some(Answer::Typed(pw)) => {
                        let Some(pw) = self.confirmed(pw, "passwords") else {
                            return Ok(());
                        };
                        Some(pw)
                    }
                    None => None,
                };
                let note = self.ask_note("Enter now keeps it");
                if typed.is_some() || note.is_some() || login != current {
                    // Login, password and note are sealed together, so whatever is
                    // kept has to come back first - through its usual gesture.
                    let kept = if typed.is_none() || note.is_none() {
                        self.tap_hint(" to keep the rest");
                        Some(self.dev()?.reveal(&name)?)
                    } else {
                        None
                    };
                    let kept_part = |part: fn(&Entry) -> Option<&[u8]>| {
                        lossy(kept.as_ref().and_then(part).unwrap_or_default())
                    };
                    let pw = typed.unwrap_or_else(|| kept_part(Entry::password_bytes));
                    let note = note.unwrap_or_else(|| kept_part(Entry::note));
                    let blob = password_blob(&name, &login, &pw, &note)?;
                    self.after_prompt(|d| d.add(&name, &blob, Kind::Password, true))?;
                }
            }
            Kind::Env => {
                // A blob is not renamed on the device: store it under the new name
                // and delete the old one instead.
                if new_name.as_deref().is_some_and(|n| n != name) {
                    return Err(Error::Value(
                        "a .env keeps its name: add it under the new one, then delete this one"
                            .into(),
                    ));
                }
                if let Some((text, blob)) = self.env_input()? {
                    self.after_prompt(|d| d.env_put(&name, &blob, true))?;
                    self.env_preview(&text);
                }
            }
        }
        let name = match new_name {
            Some(new) if new != name => {
                self.dev()?.rename(&name, &new)?;
                new
            }
            _ => name,
        };
        self.line(Color::Green, &format!("  updated '{name}'"));
        self.refresh();
        Ok(())
    }

    /// A password typed twice, since it is hidden; None when the two differ or on Esc.
    fn ask_new_password(&mut self) -> Option<Zeroizing<String>> {
        match self.field("password (Ctrl-G generates one): ", Field::NewPassword)? {
            Answer::Generated(pw) => Some(pw),
            Answer::Typed(pw) => self.confirmed(pw, "passwords"),
        }
    }

    /// A note below the transcript - recovery codes, a security answer, anything -
    /// without its trailing newlines; None when skipped with Enter or Esc.
    fn ask_note(&mut self, on_enter: &str) -> Option<Zeroizing<String>> {
        let pasted = self.ask_lines(&format!(
            "note (recovery codes, anything), then Enter on an empty line ({on_enter})"
        ))?;
        // A paste from Windows brings CRLF; the device takes text, newlines only.
        let mut text = Zeroizing::new(pasted.replace('\r', ""));
        let len = text.trim_end_matches('\n').len();
        text.truncate(len);
        (!text.is_empty()).then_some(text)
    }

    /// `pw` once more, since it was hidden; None when the second try differs. `what`
    /// names it in the mismatch line: "passwords", "PINs".
    fn confirmed(&mut self, pw: Zeroizing<String>, what: &str) -> Option<Zeroizing<String>> {
        if self.ask("again: ", Field::Hidden).as_deref() != Some(&*pw) {
            self.line(Color::Red, &format!("  {what} do not match"));
            return None;
        }
        Some(pw)
    }

    fn cmd_pin(&mut self) -> Result<(), Error> {
        self.with_dev(Shell::pin_flow)??;
        self.refresh();
        Ok(())
    }

    /// Set or change the PIN on `dev` - which is out of the shell while it asks, so
    /// provisioning can run this on a board it is still holding.
    fn pin_flow(&mut self, dev: &mut Device) -> Result<(), Error> {
        let old = if dev.pin_status()?.has_pin {
            let Some(p) = self.ask("current PIN: ", Field::Hidden) else {
                return Ok(());
            };
            Some(p)
        } else {
            None
        };
        let Some(new) = self.ask("new PIN (8 digits): ", Field::Hidden) else {
            return Ok(());
        };
        let Some(new) = self.confirmed(new, "PINs") else {
            return Ok(());
        };
        let new = pin(&new)?;
        if let Some(old) = old {
            dev.pin_change(pin(&old)?, new)?;
            self.line(Color::Green, "  PIN changed; all entries re-encrypted");
        } else {
            dev.pin_set(new)?;
            self.line(Color::Green, "  PIN set");
        }
        Ok(())
    }

    fn cmd_wipe(&mut self) -> Result<(), Error> {
        if !self.ask_yes("wipe every secret and the PIN from this key?") {
            self.line(DIM, "  kept");
            return Ok(());
        }
        self.hold_hint(" - the light turns red");
        self.dev()?.wipe()?;
        self.line(
            Color::Green,
            "  wiped - no PIN, no credentials; /pin sets a new one",
        );
        self.refresh();
        Ok(())
    }

    /// `/setup [--erase] [board]` - the board is only needed when several folders
    /// exist for the chip the bootloader reports.
    fn cmd_setup(&mut self, arg: &str) -> Result<(), Error> {
        let erase = arg.split_whitespace().any(|w| w == "--erase");
        let board = arg
            .split_whitespace()
            .find(|w| *w != "--erase")
            .map(str::to_string);
        let what = if erase {
            "erase everything on it and flash"
        } else {
            "flash the firmware onto"
        };
        if !self.ask_yes(&format!("{what} the board on {}?", self.port)) {
            self.line(DIM, "  nothing done");
            return Ok(());
        }
        self.dev = None; // espflash needs the port to itself
        let port = self.port.clone();
        let mut lines = Vec::new();
        let flashed = setup::flash_new_board(Some(&port), board.as_deref(), erase, &mut |s| {
            lines.push(s.to_string());
        });
        for l in lines {
            self.line(DIM, &l);
        }
        match flashed {
            Ok(mut d) => {
                self.version = d.probe();
                self.port.clone_from(&d.path);
                self.dev = Some(d);
            }
            Err(e) => {
                self.reconnect();
                return Err(e);
            }
        }
        self.line(
            Color::Green,
            &format!("  flashed - {}", self.version.as_deref().unwrap_or("?")),
        );
        let button = self.button();
        let passed = self.with_dev(|sh, dev| setup::provision(dev, &button, sh))??;
        if !passed {
            self.line(
                Color::Red,
                "  SELFTEST FAILED - the device's TOTP math is wrong",
            );
        }
        self.refresh();
        self.out(&[
            (Color::Green, "  ready"),
            (
                DIM,
                "  -  Enter opens the list, a stores the first credential",
            ),
        ]);
        Ok(())
    }

    fn cmd_selftest(&mut self) -> Result<(), Error> {
        self.ensure_unlocked()?;
        let button = self.button();
        let ask = format!("  ● tap {button} on the board");
        self.line(Color::Yellow, &ask);
        let mut lines = Vec::new();
        let ok = totp::selftest(self.dev()?, &button, |l| lines.push(l.to_string()))?;
        for l in lines {
            self.line(DIM, &l);
        }
        if ok {
            self.line(Color::Green, "  the device and the host agree");
        } else {
            self.line(
                Color::Red,
                "  SELFTEST FAILED - the device's TOTP math is wrong",
            );
        }
        Ok(())
    }

    /// `/import [file]`, reached from the list with i: a password manager's CSV export,
    /// one question per row. The per-row loop is `import::run`, shared with the one-shot
    /// command; its questions draw flat below the transcript, so the frame goes first
    /// and comes back after.
    fn cmd_import(&mut self, arg: &str) -> Result<(), Error> {
        let Some(path) = self.path_arg(arg, "path to the CSV export: ") else {
            return Ok(());
        };
        self.ensure_unlocked()?;
        let parsed = import::read(&path)?;
        self.line(DIM, &format!("  {}", parsed.summary()));
        for s in &parsed.skipped {
            self.line(DIM, &format!("    skipped: {s}"));
        }
        let Some(mut dev) = self.dev.take() else {
            return Err(Error::NoBoard);
        };
        let done = import::run(&mut dev, &parsed.rows, &mut |s| {
            self.line(DIM, &format!("  {s}"));
        });
        self.dev = Some(dev);
        self.line(Color::Yellow, &format!("  {}", import::reminder(&path)));
        self.line(Color::Green, &format!("  {}", done?.line()));
        self.refresh();
        Ok(())
    }

    /// `arg` as a path, or the path asked for; None when the person gives up.
    fn path_arg(&mut self, arg: &str, label: &str) -> Option<PathBuf> {
        if !arg.is_empty() {
            return Some(PathBuf::from(arg));
        }
        let p = self.ask(label, Field::Plain)?;
        Some(PathBuf::from(p.as_str()))
    }

    /// `/backup [file]`: the passphrase twice, the PIN if needed, two taps, one file.
    fn cmd_backup(&mut self, arg: &str) -> Result<(), Error> {
        let Some(path) = self.path_arg(arg, "write the backup to: ") else {
            return Ok(());
        };
        let path = backup::target(&path)?;
        let Some(pass) = self.ask(
            "backup passphrase (five or six random words): ",
            Field::Hidden,
        ) else {
            return Ok(());
        };
        passphrase(&pass)?;
        let Some(pass) = self.confirmed(pass, "passphrases") else {
            return Ok(());
        };
        self.ensure_unlocked()?;
        let hint = format!(
            "  ● tap {} on the board twice - the light turns blue",
            self.button()
        );
        self.line(Color::Blue, &hint);
        let n = backup::export(self.dev()?, &path, passphrase(&pass)?)?;
        let done = format!(
            "  {n} item{} sealed into {} - it opens only with the passphrase, on any vkey",
            if n == 1 { "" } else { "s" },
            path.display()
        );
        self.line(Color::Green, &done);
        Ok(())
    }

    /// `/restore [file]`: the passphrase once, the PIN if needed, no button.
    fn cmd_restore(&mut self, arg: &str) -> Result<(), Error> {
        let Some(path) = self.path_arg(arg, "restore from: ") else {
            return Ok(());
        };
        let path = backup::source(&path)?;
        let Some(pass) = self.ask("backup passphrase: ", Field::Hidden) else {
            return Ok(());
        };
        passphrase(&pass)?;
        self.ensure_unlocked()?;
        let n = backup::import(self.dev()?, &path, passphrase(&pass)?)?;
        let done = format!(
            "  {n} item{} restored from {}",
            if n == 1 { "" } else { "s" },
            path.display()
        );
        self.line(Color::Green, &done);
        self.refresh();
        Ok(())
    }

    fn cmd_help(&mut self) {
        for (name, desc) in COMMANDS {
            let n = format!("  /{name:<10}");
            self.out(&[(ACCENT, &n), (DIM, desc)]);
        }
    }

    /// A `/command [arg]` runs the command; anything else is the name of an entry to
    /// use, and an empty line offers the list of them. Leaving is Ctrl-D, not a command.
    fn dispatch(&mut self, line: &str) -> Result<(), Error> {
        let (cmd, arg) = match line.strip_prefix('/') {
            Some(body) => {
                let (word, arg) = body
                    .split_once(' ')
                    .map_or((body, ""), |(w, a)| (w, a.trim()));
                if word.is_empty() {
                    self.cmd_help();
                    return Ok(());
                }
                let Some(cmd) = resolve_command(word) else {
                    let msg = format!("  unknown command: {word}");
                    self.out(&[(Color::Red, &msg), (DIM, "  -  / shows them")]);
                    return Ok(());
                };
                (cmd, arg)
            }
            None => match line.trim() {
                "" => ("list", ""),
                name => ("use", name),
            },
        };
        if !self.connected() && !self.reconnect() {
            self.line(Color::Red, "  board disconnected - plug it back in");
            return Ok(());
        }
        if self.version.is_none() && cmd != "setup" {
            self.line(
                Color::Yellow,
                "  the board has no vkey firmware yet - run /setup first",
            );
            return Ok(());
        }
        let r = match cmd {
            "use" => self.cmd_use(arg),
            "list" => self.cmd_list(),
            "add" => self.cmd_add(arg),
            "edit" => self.cmd_edit(arg),
            "rm" => self.cmd_rm(arg),
            "unlock" => {
                if self.dev()?.pin_status()?.unlocked {
                    self.line(DIM, "  already unlocked");
                    Ok(())
                } else {
                    self.unlock().map(|()| self.refresh())
                }
            }
            "lock" => self.dev()?.lock().map(|()| self.refresh()),
            "pin" => self.cmd_pin(),
            "wipe" => self.cmd_wipe(),
            "setup" => self.cmd_setup(arg),
            "selftest" => self.cmd_selftest(),
            "import" => self.cmd_import(arg),
            "backup" => self.cmd_backup(arg),
            "restore" => self.cmd_restore(arg),
            other => unreachable!("resolve_command returned an unknown command: {other}"),
        };
        self.report(r)
    }

    /// How a command's outcome reaches the transcript; only a device that is gone for
    /// good ends the shell.
    fn report(&mut self, r: Result<(), Error>) -> Result<(), Error> {
        match r {
            Ok(()) => {}
            Err(Error::Refused) => self.line(Color::Yellow, &format!("  {}", Error::Refused)),
            Err(Error::Wiped) => {
                self.line(Color::Red, &format!("  {}", Error::Wiped));
                self.refresh();
            }
            Err(Error::Io(m)) => {
                self.line(Color::Red, &format!("  lost the device: {m}"));
                if !self.reconnect() {
                    return Err(Error::NoBoard);
                }
            }
            Err(e) => self.line(Color::Red, &format!("  {e}")),
        }
        Ok(())
    }

    // --- editing ----------------------------------------------------------------------

    /// Entries of any kind whose name contains `text`, case-insensitively: the search,
    /// which is just typing. An exact name comes first, so Enter on it never picks a
    /// longer one that happens to contain it.
    fn matching_entries(&self, text: &str) -> Vec<(String, String)> {
        let text = text.trim().to_lowercase();
        let mut items: Vec<(String, String)> = self
            .entries
            .iter()
            .filter(|e| e.name.to_lowercase().contains(&text))
            .map(|e| (e.name.clone(), describe(e.kind)))
            .collect();
        items.sort_by_cached_key(|(n, _)| n.to_lowercase() != text);
        items
    }

    /// The entries of one tab, as menu items. The tab already says the kind, so only
    /// what differs within it is described: TOTP parameters off the defaults.
    fn tab_entries(&self, tab: Tab) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|e| Tab::of(e.kind) == tab)
            .map(|e| {
                let what = if tab == Tab::Totp {
                    describe(e.kind)
                } else {
                    String::new()
                };
                (e.name.clone(), what)
            })
            .collect()
    }

    fn update_menu(&mut self) {
        let text = self.input.trim_start();
        let items: Vec<(String, String)> = if let Some(body) = text.strip_prefix('/') {
            match body.split_once(' ') {
                None => COMMANDS
                    .iter()
                    .filter(|(n, _)| n.starts_with(&body.to_ascii_lowercase()))
                    .map(|(n, d)| (format!("/{n}"), d.to_string()))
                    .collect(),
                Some(_) => Vec::new(),
            }
        } else if text.is_empty() {
            Vec::new()
        } else {
            self.matching_entries(text)
        };
        self.menu = if items.is_empty() {
            None
        } else {
            Some(Menu {
                items,
                selected: None,
                first: 0,
                kind: if text.starts_with('/') {
                    MenuKind::Commands
                } else {
                    MenuKind::Names
                },
            })
        };
    }

    /// One of the list's letters, with the menu closed and the input handed over as the
    /// name it held.
    fn letter_action(&mut self, c: char) -> Key {
        let name = self.input.trim().to_string();
        let tab = self.tab();
        self.input.clear();
        self.cursor = 0;
        self.menu = None;
        self.hist_pos = None;
        match (c, tab) {
            ('a', Some(tab)) => Key::Add(tab),
            ('a', None) => Key::Submit("/add".to_string()),
            ('i', _) => Key::Submit("/import".to_string()),
            ('d', _) => Key::Submit(format!("/rm {name}")),
            _ => Key::Submit(format!("/edit {name}")),
        }
    }

    fn letters_act(&self) -> bool {
        self.menu.as_ref().is_some_and(|m| match m.kind {
            MenuKind::List(_) => true,
            MenuKind::Names => m.selected.is_some(),
            MenuKind::Commands => false,
        })
    }

    /// Tab: extends the input to what every menu item still agrees on, the way a shell
    /// completes a path. False when there is nothing to add; the caller cycles instead.
    fn complete(&mut self) -> bool {
        let Some(m) = &self.menu else {
            return false;
        };
        let texts: Vec<&str> = m.items.iter().map(|(t, _)| t.as_str()).collect();
        let Some(first) = texts.first() else {
            return false; // a search with no match
        };
        let mut common = (*first).to_string();
        for text in &texts[1..] {
            let agreed = common
                .chars()
                .zip(text.chars())
                .take_while(|(a, b)| a.eq_ignore_ascii_case(b))
                .count();
            common = common.chars().take(agreed).collect();
        }
        if common.chars().count() <= self.input.trim_start().chars().count() {
            return false;
        }
        self.input = common;
        self.cursor = self.input.len();
        self.update_menu();
        true
    }

    /// Moves the menu selection, wrapping; the first move from "nothing selected"
    /// lands on the first or the last item.
    fn select(&mut self, dir: Dir) {
        let Some(m) = self.menu.as_mut() else { return };
        let n = m.items.len();
        if n == 0 {
            return; // an empty list: nothing to land on
        }
        let next = match (dir, m.selected) {
            (Dir::Next, None) => 0,
            (Dir::Next, Some(cur)) => (cur + 1) % n,
            (Dir::Prev, None) => n - 1,
            (Dir::Prev, Some(cur)) => (cur + n - 1) % n,
        };
        m.selected = Some(next);
        self.input = m.items[next].0.clone();
        self.cursor = self.input.len();
    }

    fn insert(&mut self, c: char) {
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    fn prev_char(&self) -> usize {
        self.input[..self.cursor]
            .chars()
            .next_back()
            .map_or(0, |c| self.cursor - c.len_utf8())
    }

    fn next_char(&self) -> usize {
        self.input[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |c| self.cursor + c.len_utf8())
    }

    fn handle_key(&mut self, k: KeyEvent) -> Key {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Enter => {
                // A highlighted menu item is already in the input: one Enter runs it.
                let line = std::mem::take(&mut self.input);
                self.cursor = 0;
                self.menu = None;
                self.hist_pos = None;
                return Key::Submit(line);
            }
            KeyCode::Char('c') if ctrl => {
                if self.input.is_empty() {
                    return Key::Quit;
                }
                self.input.clear();
                self.cursor = 0;
                self.menu = None;
            }
            KeyCode::Char('d') if ctrl => return Key::Quit,
            KeyCode::Esc => self.menu = None,
            KeyCode::Tab => {
                if self.input.is_empty() {
                    self.input = "/".into();
                    self.cursor = 1;
                    self.update_menu();
                } else if !self.complete() {
                    self.select(Dir::Next);
                }
            }
            KeyCode::Down => {
                if self.menu.is_some() {
                    self.select(Dir::Next);
                } else {
                    self.history_move(Dir::Next);
                }
            }
            KeyCode::BackTab => self.select(Dir::Prev),
            KeyCode::Up => {
                if self.menu.is_some() {
                    self.select(Dir::Prev);
                } else {
                    self.history_move(Dir::Prev);
                }
            }
            // In the list the arrows turn the tab; a highlighted name there is not
            // something to edit in place.
            KeyCode::Left => match self.tab() {
                Some(t) => self.open_tab(t.shift(Dir::Prev)),
                None => self.cursor = self.prev_char(),
            },
            KeyCode::Right => match self.tab() {
                Some(t) => self.open_tab(t.shift(Dir::Next)),
                None => self.cursor = self.next_char(),
            },
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.input.len(),
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.input.len(),
            KeyCode::Char('u') if ctrl => {
                self.input.drain(..self.cursor);
                self.cursor = 0;
                self.update_menu();
            }
            KeyCode::Char('w') if ctrl => {
                let end = self.cursor;
                let trimmed = self.input[..end].trim_end();
                let start = trimmed.rfind(' ').map_or(0, |i| i + 1);
                self.input.drain(start..end);
                self.cursor = start;
                self.update_menu();
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let p = self.prev_char();
                    self.input.drain(p..self.cursor);
                    self.cursor = p;
                    self.update_menu();
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.input.len() {
                    let n = self.next_char();
                    self.input.drain(self.cursor..n);
                    self.update_menu();
                }
            }
            // In the list a letter is an action. A highlighted row is already the input -
            // a name; with nothing highlighted, e and d go on to ask which.
            KeyCode::Char(c @ ('a' | 'd' | 'e' | 'i')) if !ctrl && self.letters_act() => {
                return self.letter_action(c);
            }
            KeyCode::Char(c) if !ctrl => {
                self.insert(c);
                self.update_menu();
            }
            _ => {}
        }
        Key::Redraw
    }

    /// Walks the history; past its newest entry the line is empty again.
    fn history_move(&mut self, dir: Dir) {
        let len = self.history.len();
        if len == 0 {
            return;
        }
        let pos = match (dir, self.hist_pos) {
            (Dir::Prev, None) => len - 1,
            (Dir::Prev, Some(0)) | (Dir::Next, None) => return,
            (Dir::Prev, Some(p)) => p - 1,
            (Dir::Next, Some(p)) => p + 1,
        };
        if pos >= len {
            self.hist_pos = None;
            self.input.clear();
        } else {
            self.hist_pos = Some(pos);
            self.input = self.history[pos].clone();
        }
        self.cursor = self.input.len();
        self.menu = None;
    }

    // --- loop ---------------------------------------------------------------------------

    fn main_loop(&mut self) -> Result<u8, Error> {
        self.refresh();
        let _raw = RawMode::enter()?;
        let mut so = io::stdout();
        let banner = format!("  ✻ vkey {}", env!("CARGO_PKG_VERSION"));
        let _ = queue!(
            so,
            SetForegroundColor(ACCENT),
            SetAttribute(Attribute::Bold),
            Print(banner),
            SetAttribute(Attribute::Reset),
            ResetColor,
            Print("\r\n")
        );
        if self.version.is_none() {
            let _ = queue!(
                so,
                SetForegroundColor(Color::Yellow),
                Print("  the board does not answer - /setup flashes it and asks for a PIN"),
                ResetColor,
                Print("\r\n")
            );
        } else {
            let _ = queue!(
                so,
                SetForegroundColor(DIM),
                Print("  / for commands · ↑↓ or Tab picks · Enter runs"),
                ResetColor,
                Print("\r\n")
            );
        }
        let _ = queue!(so, Print("\r\n"));
        // Nothing works without the PIN, not even the list, so ask right away. A
        // refused prompt is not an error: the shell opens locked and /unlock waits.
        if self.version.is_some() && self.has_pin && !self.unlocked {
            match self.unlock() {
                Ok(()) => self.refresh(),
                Err(Error::Value(_)) => {}
                Err(e) => self.line(Color::Red, &format!("  {e}")),
            }
        }
        self.draw_frame(&mut so);

        let mut resize_at: Option<Instant> = None;
        let mut last_tick = Instant::now();
        loop {
            // A resize burst settles before anything is redrawn; the tick refreshes
            // the status line once a second.
            let wait = match resize_at {
                Some(t) => SETTLE.saturating_sub(t.elapsed()),
                None => Duration::from_secs(1).saturating_sub(last_tick.elapsed()),
            };
            if !event::poll(wait)? {
                if resize_at.is_some() {
                    resize_at = None;
                    self.redraw_after_resize();
                } else {
                    last_tick = Instant::now();
                    self.refresh_status();
                }
                continue;
            }
            match event::read()? {
                Event::Resize(_, _) => resize_at = Some(Instant::now()),
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    if resize_at.is_some() {
                        continue;
                    }
                    match self.handle_key(k) {
                        Key::Quit => break,
                        Key::Redraw => {
                            self.erase_frame(&mut so);
                            self.draw_frame(&mut so);
                        }
                        Key::Submit(line) => {
                            let line = line.trim().to_string();
                            self.erase_frame(&mut so);
                            if line.is_empty() {
                                // Enter on nothing: the list of entries to pick from.
                                self.dispatch("")?;
                                self.draw_frame(&mut so);
                                continue;
                            }
                            self.history.push(line.clone());
                            let echo = format!("  ❯ {line}");
                            self.line(DIM, &echo);
                            self.dispatch(&line)?;
                            self.draw_frame(&mut so);
                        }
                        Key::Add(tab) => {
                            self.erase_frame(&mut so);
                            self.line(DIM, "  ❯ /add");
                            let r = self.add_kind(tab, "");
                            self.report(r)?;
                            self.draw_frame(&mut so);
                        }
                    }
                }
                _ => {}
            }
        }
        self.lock_on_exit();
        if self.frame_rows > 0 {
            self.erase_frame(&mut so);
            let _ = so.flush();
        }
        Ok(0)
    }

    /// Leaving the shell puts the key away: what it was unlocked for is over, and the
    /// idle timeout is a backstop, not the way to lock.
    fn lock_on_exit(&mut self) {
        if let Some(dev) = self.dev.as_mut()
            && let Err(e) = dev.lock()
        {
            self.line(Color::Red, &format!("  could not lock the key: {e}"));
        }
    }
}
