//! Passwords and TOTP secrets out of a Google Password Manager or 1Password 8 CSV
//! export, one question per row: the device holds what must be offline, not a copy
//! of the whole manager.
//!
//! The export is plain text. It is read into memory that scrubs itself, no password
//! ever reaches the screen, and the file stays where it is: deleting it is the
//! owner's call, once the device has been checked.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use csv_core::{ReadRecordResult, Reader};
use zeroize::Zeroizing;

use crate::device::{Device, Error, NAME_MAX, login_item};
use crate::item::Item;
use crate::prompt::SyncUi;
use crate::sources::{self, FILE, Manifest, Outcome, Phase, SyncRun};
use crate::totp;

/// One item the export can put on the device. The name and the login are printed; the
/// fields never are.
pub struct Row {
    pub name: String,
    pub login: String,
    pub item: Item,
}

impl Row {
    /// Whether this row is a one-time password rather than a password, for the summary
    /// that counts them apart.
    fn is_totp(&self) -> bool {
        self.item.first(vaultkey_core::item::Class::Seed).is_some()
    }
}

pub struct Parsed {
    source: &'static str,
    pub rows: Vec<Row>,
    /// What cannot go on the device, and why. Never a password.
    pub skipped: Vec<String>,
    /// Names the export still holds but this parse could not turn into an entry - a
    /// row whose password was cleared, a secret that would not resolve. The export
    /// offers them, so a mirror must not treat them as withdrawn and delete them.
    pub dropped: Vec<String>,
}

impl Parsed {
    /// `1Password export: 42 passwords, 7 TOTP codes; 3 rows skipped`
    #[must_use]
    pub fn summary(&self) -> String {
        let totp = self.rows.iter().filter(|r| r.is_totp()).count();
        let skipped = if self.skipped.is_empty() {
            String::new()
        } else {
            format!("; {} rows skipped", self.skipped.len())
        };
        format!(
            "{} export: {} passwords, {totp} TOTP codes{skipped}",
            self.source,
            self.rows.len() - totp
        )
    }
}

#[derive(Default)]
pub struct Summary {
    pub added: usize,
    pub replaced: usize,
    pub skipped: usize,
    /// Entries this source had brought and no longer offers.
    pub deleted: usize,
    /// Rows after a "stop", or after the device filled up.
    pub left: usize,
}

impl Summary {
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "added {} · replaced {} · skipped {} · deleted {} · not reached {}",
            self.added, self.replaced, self.skipped, self.deleted, self.left
        )
    }
}

/// The last word after any import, successful or not.
#[must_use]
pub fn reminder(path: &Path) -> String {
    format!(
        "the export still holds every password in plain text - delete it and empty the trash (shred -u {} on ext4)",
        path.display()
    )
}

pub fn read(path: &Path) -> Result<Parsed, Error> {
    let bytes = std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| Error::Value(format!("cannot read {}: {e}", path.display())))?;
    parse(&bytes)
}

/// Which manager wrote the file, told by its header row.
struct Format {
    source: &'static str,
    /// The column holding an otpauth URI, when the export has one.
    otp: Option<usize>,
    archived: Option<usize>,
}

fn format_of(header: &[&str]) -> Option<Format> {
    let cols: Vec<String> = header
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let cols: Vec<&str> = cols.iter().map(String::as_str).collect();
    match cols.as_slice() {
        ["name", "url", "username", "password", "note", ..] => Some(Format {
            source: "Google Password Manager",
            otp: None,
            archived: None,
        }),
        ["title", "url", "username", "password", "otpauth", ..] => Some(Format {
            source: "1Password",
            otp: Some(4),
            archived: cols.iter().position(|c| *c == "archived"),
        }),
        _ => None,
    }
}

/// A row as the manager wrote it, before it becomes device entries.
struct Raw {
    title: String,
    url: String,
    login: String,
    password: Zeroizing<String>,
    otp: Option<Zeroizing<String>>,
}

pub fn parse(csv: &[u8]) -> Result<Parsed, Error> {
    let mut format = None;
    let mut raws: Vec<Raw> = Vec::new();
    let mut archived = 0usize;
    records(csv, &mut |fields| {
        let Some(f) = &format else {
            format = Some(format_of(fields).ok_or_else(|| {
                Error::Value("not a Google Password Manager or 1Password 8 export".into())
            })?);
            return Ok(());
        };
        if fields.iter().all(|c| c.trim().is_empty()) {
            return Ok(());
        }
        let col = |i: usize| fields.get(i).copied().unwrap_or("");
        if f.archived
            .is_some_and(|i| col(i).eq_ignore_ascii_case("true"))
        {
            archived += 1;
            return Ok(());
        }
        raws.push(Raw {
            title: col(0).to_string(),
            url: col(1).to_string(),
            login: col(2).trim().to_string(),
            password: Zeroizing::new(col(3).to_string()),
            otp: f
                .otp
                .map(|i| col(i).trim())
                .filter(|o| !o.is_empty())
                .map(|o| Zeroizing::new(o.to_string())),
        });
        Ok(())
    })?;
    let Some(format) = format else {
        return Err(Error::Value("the file is empty".into()));
    };
    let mut parsed = Parsed {
        source: format.source,
        rows: Vec::new(),
        skipped: Vec::new(),
        dropped: Vec::new(),
    };
    if archived > 0 {
        parsed.skipped.push(format!("{archived} archived items"));
    }
    rows_of(&raws, &mut parsed);
    Ok(parsed)
}

/// Device entries out of the raw rows. Two rows with the same title get the login
/// appended, so `google.com` with three accounts becomes three entries; `unique_name`
/// settles what is still not unique after that.
fn rows_of(raws: &[Raw], out: &mut Parsed) {
    let names: Vec<Option<String>> = raws.iter().map(|r| entry_name(&r.title, &r.url)).collect();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for name in names.iter().flatten() {
        *seen.entry(name).or_default() += 1;
    }
    let mut taken = BTreeSet::new();
    for (i, raw) in raws.iter().enumerate() {
        let Some(name) = &names[i] else {
            out.skipped
                .push(format!("row {}: no title and no URL", i + 2));
            continue;
        };
        let dup = seen.get(name.as_str()).is_some_and(|n| *n > 1);
        let login = if dup { raw.login.as_str() } else { "" };
        let name = unique_name(name, login, &mut taken);
        if raw.password.is_empty() && raw.otp.is_none() {
            out.skipped.push(format!("{name}: no password"));
            out.dropped.push(name);
            continue;
        }
        if !raw.password.is_empty() {
            match login_item(&raw.login, &raw.password, "") {
                Ok(item) => out.rows.push(Row {
                    name: name.clone(),
                    login: raw.login.clone(),
                    item,
                }),
                Err(e) => {
                    out.skipped.push(format!("{name}: {e}"));
                    out.dropped.push(name.clone());
                }
            }
        }
        if let Some(otp) = &raw.otp {
            let otp_name = unique_name(&name, "otp", &mut taken);
            match totp::resolve(otp, Some(&otp_name), None, None, false) {
                Ok(r) => out.rows.push(Row {
                    name: r.name.clone(),
                    login: String::new(),
                    item: r.item(),
                }),
                Err(e) => {
                    out.skipped.push(format!("{otp_name}: {e}"));
                    out.dropped.push(otp_name);
                }
            }
        }
    }
}

/// The title, or the site's host when there is none; cut to what a name may be.
pub(crate) fn entry_name(title: &str, url: &str) -> Option<String> {
    let title = title.trim();
    let name = if title.is_empty() {
        url::Url::parse(url.trim())
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default()
    } else {
        title.to_string()
    };
    if name.is_empty() {
        return None;
    }
    Some(truncate(&name))
}

/// At most `NAME_MAX` bytes, never mid-character.
pub(crate) fn truncate(s: &str) -> String {
    cut(s, NAME_MAX)
}

/// The first `max` bytes of `s`, never mid-character.
fn cut(s: &str, max: usize) -> String {
    let mut s = s.to_string();
    while s.len() > max {
        s.pop();
    }
    s
}

/// The shortest a site is cut to before the login is cut instead: `dash.cloud…` still
/// says which site it is, `d:` does not.
const MIN_SITE: usize = 12;

/// The name an entry gets: `site`, or `site:login` where the site alone would not say
/// which account this is. A name is `NAME_MAX` bytes at most, and it is the *site*
/// that is shortened to make room - the login is what tells two accounts apart, so
/// cutting it is what silently merged them. `taken` is what this import has already
/// named: two rows that still collide - one site, one login, twice - are numbered,
/// because the device holds one entry per name and the second would be refused.
pub(crate) fn unique_name(site: &str, login: &str, taken: &mut BTreeSet<String>) -> String {
    let mut n = 1;
    loop {
        let suffix = if n == 1 {
            String::new()
        } else {
            format!(":{n}")
        };
        let room = NAME_MAX - suffix.len();
        let name = if login.is_empty() {
            cut(site, room)
        } else {
            let login = cut(login, room.saturating_sub(1 + MIN_SITE));
            let site = cut(site, room - 1 - login.len());
            format!("{site}:{login}")
        } + &suffix;
        if taken.insert(name.clone()) {
            return name;
        }
        n += 1;
    }
}

/// Every record of `csv` as its fields, unescaped. `csv-core` is a state machine over
/// buffers we own: the fields land in memory that scrubs itself, and multi-line
/// quoted fields (1Password notes) parse the way RFC 4180 says.
fn records(csv: &[u8], f: &mut dyn FnMut(&[&str]) -> Result<(), Error>) -> Result<(), Error> {
    let bad = || Error::Value("the file is not well-formed CSV".into());
    let mut rdr = Reader::new();
    let mut out = Zeroizing::new(vec![0u8; csv.len() + 1]);
    let mut ends = [0usize; 16];
    let (mut pos, mut o, mut e) = (0, 0, 0);
    loop {
        let (res, nin, nout, nend) = rdr.read_record(&csv[pos..], &mut out[o..], &mut ends[e..]);
        pos += nin;
        o += nout;
        e += nend;
        match res {
            ReadRecordResult::InputEmpty => {}
            ReadRecordResult::OutputFull | ReadRecordResult::OutputEndsFull => return Err(bad()),
            ReadRecordResult::End => return Ok(()),
            ReadRecordResult::Record => {
                let mut fields = Vec::with_capacity(e);
                let mut from = 0;
                for &to in &ends[..e] {
                    fields.push(std::str::from_utf8(&out[from..to]).map_err(|_| bad())?);
                    from = to;
                }
                f(&fields)?;
                out[..o].fill(0);
                (o, e) = (0, 0);
            }
        }
    }
}

/// Stores rows from a CSV export onto the device, and deletes what this export used
/// to bring and no longer does. Existing entries are skipped unless `replace`.
///
/// The file is the mirror: only what an earlier import of *this same file* left behind
/// is ever deleted, and never an entry added by hand or one that came from 1Password.
pub fn run(
    dev: &mut Device,
    parsed: &Parsed,
    file: &Path,
    replace: bool,
    ui: &mut dyn SyncUi,
) -> Result<Summary, Error> {
    let rows = &parsed.rows;
    let mut run = SyncRun::default();
    let mut map = Manifest::load();
    let entries = dev.list().unwrap_or_default();
    let existing: BTreeSet<String> = entries.iter().map(|e| e.name.clone()).collect();
    let ping_target = sources::survivor(&entries);

    // An export from somewhere else is a different mirror: it adds, but it must not
    // delete what the last one brought. The path is all this host can tell them by, so
    // it is resolved first - two `passwords.csv` in different folders are not one file.
    let source = std::fs::canonicalize(file)
        .unwrap_or_else(|_| file.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let blocked = (!map.mirrors(FILE, &source))
        .then(|| "this key has not been mirrored from this file before".to_string())
        .or_else(|| {
            rows.is_empty()
                .then(|| "the export held no rows at all".to_string())
        });

    let mut offered = BTreeSet::new();
    let mut full = false;

    for (i, row) in rows.iter().enumerate() {
        let desc = if row.login.is_empty() {
            row.name.clone()
        } else {
            format!("{} ({})", row.name, row.login)
        };

        if !replace && existing.contains(&row.name) {
            ui.info(&format!("  skipped '{desc}' (already exists)"));
            run.summary.skipped += 1;
            run.saw(&row.name, Outcome::Offered);
            sources::absorb(&mut run, FILE, &mut map, &mut offered)?;
            continue;
        }

        let mut retried = false;
        loop {
            match dev.put(&row.name, &row.item, replace) {
                Ok(()) => {
                    if replace && existing.contains(&row.name) {
                        run.summary.replaced += 1;
                        ui.info(&format!("  updated '{desc}'"));
                    } else {
                        run.summary.added += 1;
                        ui.info(&format!("  stored '{desc}'"));
                    }
                    run.saw(&row.name, Outcome::Wrote);
                    break;
                }
                Err(Error::Exists) if replace => {
                    dev.put(&row.name, &row.item, true)?;
                    run.summary.replaced += 1;
                    run.saw(&row.name, Outcome::Wrote);
                    ui.info(&format!("  updated '{desc}'"));
                    break;
                }
                Err(Error::Exists) => {
                    run.summary.skipped += 1;
                    run.saw(&row.name, Outcome::Offered);
                    ui.info(&format!("  skipped '{desc}' (already exists)"));
                    break;
                }
                Err(Error::Full) => {
                    ui.info("the device is full");
                    run.summary.left = rows.len() - i;
                    run.saw(&row.name, Outcome::Offered);
                    full = true;
                    break;
                }
                Err(Error::Locked) if !retried => {
                    retried = true;
                    ui.info("  device locked: re-authenticating PIN...");
                    ui.unlock(dev)?;
                }
                Err(e) => return Err(e),
            }
        }
        sources::absorb(&mut run, FILE, &mut map, &mut offered)?;
        if full {
            // The export still offers the rows this run never reached; name them, or
            // the next pass would read them as withdrawn and delete them.
            offered.extend(rows[i..].iter().map(|r| r.name.clone()));
            break;
        }
    }

    // Deletions come after every write, so a run that stops early leaves the key
    // holding more than it should rather than less. A full device still gets here:
    // deleting is what makes room for the next run.
    // A row the parser threw away is still a row the export holds.
    offered.extend(parsed.dropped.iter().cloned());

    let phase = Phase {
        bucket: FILE,
        offered,
        blocked,
    };

    sources::finish(dev, &mut map, &[phase], ping_target.as_ref(), ui, &mut run)?;

    // Remember which export this key now mirrors, so the next import of it may delete.
    map.set_source(FILE, &source);
    map.save()?;

    Ok(run.summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE: &str = "name,url,username,password,note\n\
        GitHub,https://github.com,me,hunter2,\n\
        google.com,https://accounts.google.com,a@gmail.com,pw-a,\n\
        google.com,https://accounts.google.com,b@gmail.com,pw-b,\n\
        ,https://example.org/login,x,pw-x,\n\
        Empty,https://example.org,x,,\n";

    const ONEPASSWORD: &str = "\u{feff}Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
        GitHub,https://github.com,me,\"say \"\"hi\"\"\",otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,,false,,\"two\nlines\"\n\
        Old,https://old.example,me,pw,,,true,,\n\
        Counter,https://c.example,me,pw,otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1,,false,,\n";

    fn names(p: &Parsed) -> Vec<&str> {
        p.rows.iter().map(|r| r.name.as_str()).collect()
    }

    #[test]
    fn a_row_the_parser_threw_away_is_still_offered() {
        // The password was cleared in the manager but the row is still in the export.
        // Nothing can be stored for it - and nothing may be deleted for it either.
        let csv = b"name,url,username,password,note\nBank,https://bank.example,me,,\n";
        let parsed = parse(csv).expect("parses");
        assert!(parsed.rows.is_empty());
        assert_eq!(parsed.dropped, vec!["Bank".to_string()]);
    }

    #[test]
    fn a_name_that_does_not_fit_loses_the_site_and_never_the_login() {
        let mut taken = BTreeSet::new();
        let long = unique_name(
            "stakanopt.keepincrm.com",
            "systema98opt@gmail.com",
            &mut taken,
        );
        assert_eq!(
            long, "stakanopt.ke:systema98opt@gmail.",
            "the site is shortened to make room; the login is what tells two \
             accounts apart, so cutting it is what merged them"
        );
        assert_eq!(long.len(), NAME_MAX);

        // One site, one login, twice - the second name is numbered, or the device
        // would refuse it as taken and the entry would be lost.
        let first = unique_name("github.com", "eloicompany", &mut taken);
        let second = unique_name("github.com", "eloicompany", &mut taken);
        assert_eq!(first, "github.com:eloicompany");
        assert_eq!(second, "github.com:eloicompany:2");
    }

    #[test]
    fn google_rows_and_duplicates() {
        let p = parse(GOOGLE.as_bytes()).expect("parses");
        assert_eq!(
            names(&p),
            [
                "GitHub",
                "google.com:a@gmail.com",
                "google.com:b@gmail.com",
                "example.org"
            ],
            "title, then title:login for duplicates, then the host"
        );
        assert!(
            p.rows.iter().all(|r| !r.is_totp()),
            "Google has no TOTP column"
        );
        assert_eq!(
            p.skipped,
            ["Empty: no password"],
            "an empty password is skipped"
        );
        assert_eq!(
            p.summary(),
            "Google Password Manager export: 4 passwords, 0 TOTP codes; 1 rows skipped",
            "summary"
        );
    }

    #[test]
    fn onepassword_otp_quotes_bom_and_archived() {
        let p = parse(ONEPASSWORD.as_bytes()).expect("parses");
        assert_eq!(
            names(&p),
            ["GitHub", "GitHub:otp", "Counter"],
            "OTPAuth adds :otp"
        );
        assert!(p.rows[1].is_totp(), ":otp is a one-time password");
        let login = &p.rows[0].item;
        assert_eq!(
            login
                .by_label("username")
                .expect("a username field")
                .text()
                .as_str(),
            "me"
        );
        assert_eq!(
            login
                .by_label("password")
                .expect("a password field")
                .text()
                .as_str(),
            "say \"hi\"",
            "quotes unescaped"
        );
        assert_eq!(p.skipped.len(), 2, "archived + HOTP: {:?}", p.skipped);
        assert_eq!(
            p.skipped[0], "1 archived items",
            "archived items are counted"
        );
        assert!(
            p.skipped[1].starts_with("Counter:otp: "),
            "HOTP is refused by name: {}",
            p.skipped[1]
        );
    }

    #[test]
    fn long_names_and_secrets() {
        let long = "x".repeat(40);
        let csv = format!(
            "name,url,username,password,note\n{long},,me,{},\nok,,me,pw,\n",
            "p".repeat(300)
        );
        let p = parse(csv.as_bytes()).expect("parses");
        assert_eq!(
            names(&p),
            ["x".repeat(NAME_MAX), "ok".to_string()],
            "a 300-byte password is a password now: the 256-byte secret is gone, and \
             the name is what is still cut to NAME_MAX"
        );
        assert!(p.skipped.is_empty(), "nothing to skip: {:?}", p.skipped);

        // Past the field limit, though, it is still refused - here, before the wire.
        let csv = format!(
            "name,url,username,password,note\ntoobig,,me,{},\n",
            "p".repeat(crate::device::VALUE_MAX + 1)
        );
        let p = parse(csv.as_bytes()).expect("parses");
        assert!(
            names(&p).is_empty(),
            "a password past VALUE_MAX does not fit"
        );
        assert_eq!(p.skipped.len(), 1, "and it says so: {:?}", p.skipped);
    }

    #[test]
    fn other_files_are_refused() {
        assert!(parse(b"user,pass\nme,pw\n").is_err(), "unknown header");
        assert!(parse(b"").is_err(), "empty file");
    }
}
