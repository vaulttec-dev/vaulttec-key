//! Passwords and TOTP secrets out of a Google Password Manager or 1Password 8 CSV
//! export, one question per row: the device holds what must be offline, not a copy
//! of the whole manager.
//!
//! The export is plain text. It is read into memory that scrubs itself, no password
//! ever reaches the screen, and the file stays where it is: deleting it is the
//! owner's call, once the device has been checked.

use std::collections::HashMap;
use std::path::Path;

use csv_core::{ReadRecordResult, Reader};
use zeroize::Zeroizing;

use crate::device::{Device, Error, Kind, NAME_MAX, password_blob};
use crate::prompt::choose;
use crate::totp;

/// One entry the export can put on the device. The name and the login are printed;
/// the secret never is.
pub struct Row {
    pub name: String,
    pub login: String,
    pub kind: Kind,
    pub secret: Zeroizing<Vec<u8>>,
}

pub struct Parsed {
    source: &'static str,
    pub rows: Vec<Row>,
    /// What cannot go on the device, and why. Never a password.
    pub skipped: Vec<String>,
}

impl Parsed {
    /// `1Password export: 42 passwords, 7 TOTP codes; 3 rows skipped`
    #[must_use]
    pub fn summary(&self) -> String {
        let totp = self
            .rows
            .iter()
            .filter(|r| matches!(r.kind, Kind::Totp(_)))
            .count();
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
    /// Rows after a "stop", or after the device filled up.
    pub left: usize,
}

impl Summary {
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "added {} · replaced {} · skipped {} · not reached {}",
            self.added, self.replaced, self.skipped, self.left
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
    };
    if archived > 0 {
        parsed.skipped.push(format!("{archived} archived items"));
    }
    rows_of(&raws, &mut parsed);
    Ok(parsed)
}

/// Device entries out of the raw rows. Two rows with the same title get the login
/// appended, so `google.com` with three accounts becomes three entries.
fn rows_of(raws: &[Raw], out: &mut Parsed) {
    let names: Vec<Option<String>> = raws.iter().map(|r| entry_name(&r.title, &r.url)).collect();
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for name in names.iter().flatten() {
        *seen.entry(name).or_default() += 1;
    }
    for (i, raw) in raws.iter().enumerate() {
        let Some(name) = &names[i] else {
            out.skipped
                .push(format!("row {}: no title and no URL", i + 2));
            continue;
        };
        let dup = seen.get(name.as_str()).is_some_and(|n| *n > 1);
        let name = if dup && !raw.login.is_empty() {
            truncate(format!("{name}:{}", raw.login))
        } else {
            name.clone()
        };
        if raw.password.is_empty() && raw.otp.is_none() {
            out.skipped.push(format!("{name}: no password"));
            continue;
        }
        if !raw.password.is_empty() {
            match password_blob(&name, &raw.login, &raw.password, "") {
                Ok(secret) => out.rows.push(Row {
                    name: name.clone(),
                    login: raw.login.clone(),
                    kind: Kind::Password,
                    secret,
                }),
                Err(e) => out.skipped.push(format!("{name}: {e}")),
            }
        }
        if let Some(otp) = &raw.otp {
            let otp_name = truncate(format!("{name}:otp"));
            match totp::resolve(otp, Some(&otp_name), None, None, false) {
                Ok(r) => out.rows.push(Row {
                    name: r.name,
                    login: String::new(),
                    kind: Kind::Totp(r.params),
                    secret: r.secret,
                }),
                Err(e) => out.skipped.push(format!("{otp_name}: {e}")),
            }
        }
    }
}

/// The title, or the site's host when there is none; cut to what a name may be.
fn entry_name(title: &str, url: &str) -> Option<String> {
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
    Some(truncate(name))
}

/// At most `NAME_MAX` bytes, never mid-character.
fn truncate(mut s: String) -> String {
    while s.len() > NAME_MAX {
        s.pop();
    }
    s
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

/// What the person says about one row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Add,
    Skip,
    Stop,
}

/// Walks the rows with the person, one question each. Stops on "stop", Esc, or a
/// full device; anything else the device refuses is an error.
pub fn run(dev: &mut Device, rows: &[Row], say: &mut dyn FnMut(&str)) -> Result<Summary, Error> {
    let mut sum = Summary::default();
    for (i, row) in rows.iter().enumerate() {
        let what = match row.kind {
            Kind::Password => "password",
            Kind::Totp(_) => "totp",
            Kind::Env => "env", // no export has one; the match stays exhaustive
        };
        let label = if row.login.is_empty() {
            format!("{}  ({what})", row.name)
        } else {
            format!("{}  login {}  ({what})", row.name, row.login)
        };
        let choice = choose(
            &label,
            &[
                (Next::Add, "add", ""),
                (Next::Skip, "skip", ""),
                (Next::Stop, "stop", "leave the rest"),
            ],
        );
        match choice {
            Some(Next::Add) => match dev.add(&row.name, &row.secret, row.kind, false) {
                Ok(()) => sum.added += 1,
                Err(Error::Exists) => {
                    let replace = choose(
                        &format!("'{}' already exists", row.name),
                        &[(false, "keep the old one", ""), (true, "replace", "")],
                    );
                    if replace == Some(true) {
                        dev.add(&row.name, &row.secret, row.kind, true)?;
                        sum.replaced += 1;
                    } else {
                        sum.skipped += 1;
                    }
                }
                Err(Error::Full) => {
                    say("the device is full");
                    sum.left = rows.len() - i;
                    break;
                }
                Err(e) => return Err(e),
            },
            Some(Next::Skip) => sum.skipped += 1,
            Some(Next::Stop) | None => {
                sum.left = rows.len() - i;
                break;
            }
        }
    }
    Ok(sum)
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
            p.rows.iter().all(|r| r.kind == Kind::Password),
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
        assert!(
            matches!(p.rows[1].kind, Kind::Totp(_)),
            ":otp is a TOTP entry"
        );
        assert_eq!(
            &p.rows[0].secret[..],
            b"\x02me\x08say \"hi\"",
            "login_len | login | password_len | password, quotes unescaped"
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
        assert_eq!(names(&p), ["ok"], "the oversized secret is not a row");
        assert_eq!(p.skipped.len(), 1, "one reason: {:?}", p.skipped);
        assert!(
            p.skipped[0].starts_with(&"x".repeat(NAME_MAX)),
            "the name is cut to NAME_MAX bytes: {}",
            p.skipped[0]
        );
    }

    #[test]
    fn other_files_are_refused() {
        assert!(parse(b"user,pass\nme,pw\n").is_err(), "unknown header");
        assert!(parse(b"").is_err(), "empty file");
    }
}
