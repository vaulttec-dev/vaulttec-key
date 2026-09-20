//! Exercises the whole PIN lifecycle on a real board, including the wipe.
//!
//! ```text
//! vkey check --wipe-everything
//! ```
//!
//! THIS ERASES EVERY SECRET ON THE DEVICE. It exists for development boards and for
//! proving a firmware build before it goes anywhere near real credentials. Every step
//! is a PASS/FAIL line; the exit code is non-zero if any failed. The device is left
//! wiped: no PIN, no entries. Codes need the button, so it says when to tap and when
//! to hold; the rules about which gesture does what are proven on the host, in
//! `firmware/core/tests`.

use std::num::NonZeroU8;

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::device::{
    AUTH_CHALLENGE_LEN, AUTH_SECRET_LEN, Category, Class, Device, EnvBlob, Error, FieldKind,
    MAX_ATTEMPTS, Params, Reach, login_item, passphrase, pin,
};
use crate::item::{Item, OwnedField};
use crate::totp::{TEST_SECRET, decode_base32, seed_field, selftest};
use crate::{auth, backup, boards};

const PIN: &str = "12345678";
const NEW_PIN: &str = "87654321";
const LOGIN: &str = "me@example.com";
const PASSWORD: &str = "correct horse battery staple";
const NOTE: &str = "recovery:\n1234-5678\n8765-4321";

/// A service's usual credential, with a chosen period.
fn totp_item(period: u8, secret: &[u8]) -> Item {
    let params = Params {
        period: NonZeroU8::new(period).expect("periods here are never zero"),
        ..Params::DEFAULT
    };
    Item::new(Category::Login).with(seed_field(params, secret).expect("valid secret"))
}

/// Counts failures and prints one line per check.
struct Report {
    failures: u32,
    button: String,
}

impl Report {
    fn check(&mut self, label: &str, ok: bool, detail: &str) {
        println!(
            "  {}  {label}{}{detail}",
            if ok { "PASS" } else { "FAIL" },
            if detail.is_empty() { "" } else { "  " }
        );
        if !ok {
            self.failures += 1;
        }
    }

    /// Passes only if the call failed with exactly `want`.
    fn expect<T>(&mut self, label: &str, r: &Result<T, Error>, want: &Error) {
        self.expect_with(label, r, |e| e == want);
    }

    /// Passes only if the call failed the way `want` describes.
    fn expect_with<T>(&mut self, label: &str, r: &Result<T, Error>, want: impl Fn(&Error) -> bool) {
        match r {
            Ok(_) => self.check(label, false, "no error raised"),
            Err(e) if want(e) => self.check(label, true, ""),
            Err(e) => self.check(label, false, &format!("{e:?}")),
        }
    }

    fn tap(&self) {
        println!("  >>> tap {} when the light turns amber", self.button);
    }
}

pub fn run(d: &mut Device) -> Result<u8, Error> {
    let version = d.info()?;
    let mut rep = Report {
        failures: 0,
        button: boards::button(Some(&version)),
    };
    println!("device: {version}\n");

    clean_start(d, &mut rep)?;
    println!("\n=== no PIN yet ===");
    unprovisioned(d, &mut rep)?;
    println!("\n=== provisioning ===");
    provisioning(d, &mut rep)?;
    println!("\n=== entries ===");
    let first_code = entries(d, &mut rep)?;
    println!("\n=== password ===");
    password(d, &mut rep)?;
    println!("\n=== env ===");
    let env_blob = env(d, &mut rep)?;
    println!("\n=== backup ===");
    backup(d, &mut rep, &first_code, &env_blob)?;
    println!("\n=== lock / unlock ===");
    lock_unlock(d, &mut rep)?;
    println!("\n=== rekey ===");
    rekey(d, &mut rep, &first_code, &env_blob)?;
    println!("\n=== auth: a login answered while locked ===");
    auth(d, &mut rep)?;
    println!("\n=== live code against an independent HMAC ===");
    let ok = selftest(d, &rep.button, |line| println!("{line}"))?;
    rep.check("selftest", ok, "");
    println!("\n=== wipe ===");
    wipe(d, &mut rep)?;

    println!("\n  device left wiped: no PIN, no entries - set yours with  vkey pin set  or /pin");
    if rep.failures > 0 {
        println!("\n{} failure(s)", rep.failures);
        Ok(1)
    } else {
        println!("\nall checks passed");
        Ok(0)
    }
}

/// Start from nothing, whatever state the board is in.
fn clean_start(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    if d.pin_status()?.has_pin {
        println!("  (device has a PIN; exhausting retries to reach a clean state)");
        d.lock()?;
        for _ in 0..MAX_ATTEMPTS {
            if d.pin_unlock(pin("00000000")?) == Err(Error::Incompatible) {
                // Written under the other key setup: only a wipe clears it.
                println!(
                    "  >>> the vault is from a different key setup - hold {} down for five \
                     seconds when the light turns red",
                    rep.button
                );
                d.wipe()?;
                crate::sources::forget_all();
                break;
            }
        }
    } else if !matches!(d.pin_unlock(pin("00000000")?), Err(Error::NoPin)) {
        // No PIN as far as the status can tell, yet the flash is not blank: an image
        // this firmware cannot read (an older layout). Only a wipe clears it, and no
        // attempt was spent finding out.
        println!(
            "  >>> the vault is from an older firmware layout - hold {} down for five \
             seconds when the light turns red",
            rep.button
        );
        d.wipe()?;
    }
    let st = d.pin_status()?;
    rep.check(
        "clean start",
        !st.has_pin && !st.unlocked && st.retries_left == MAX_ATTEMPTS,
        &format!("{st:?}"),
    );
    println!(
        "  key derivation: {}",
        if st.chip_bound {
            "chip-bound"
        } else {
            "PIN only"
        }
    );
    Ok(())
}

fn unprovisioned(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    rep.expect(
        "list refused before a PIN exists",
        &d.list(),
        &Error::Locked,
    );
    rep.expect(
        "add refused before a PIN exists",
        &d.put("x", &totp_item(30, b"xxxxxxxxxx"), false),
        &Error::Locked,
    );
    rep.expect(
        "unlock refused before a PIN exists",
        &d.pin_unlock(pin(PIN)?),
        &Error::NoPin,
    );
    Ok(())
}

fn provisioning(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    d.pin_set(pin(PIN)?)?;
    let st = d.pin_status()?;
    rep.check(
        "pin_set leaves device unlocked",
        st.has_pin && st.unlocked,
        "",
    );
    // Timed on an unlock, not on pin_set: pin_set also writes the whole image, and
    // that is the flash's time, not the key derivation's.
    d.lock()?;
    let started = std::time::Instant::now();
    d.pin_unlock(pin(PIN)?)?;
    let took = started.elapsed();
    rep.check(
        "key derivation under 2 s (1.2 s of Argon2 plus the round trip)",
        took.as_millis() < 2000,
        &format!("{} ms", took.as_millis()),
    );
    rep.expect(
        "second pin_set refused",
        &d.pin_set(pin(PIN)?),
        &Error::PinExists,
    );
    Ok(())
}

/// Adds, refuses a duplicate, replaces; returns the first code for the rekey check.
fn entries(d: &mut Device, rep: &mut Report) -> Result<String, Error> {
    let secret = decode_base32(TEST_SECRET)?;
    d.put("t", &totp_item(30, &secret), false)?;
    rep.check("add", d.list()?.iter().any(|e| e.name == "t"), "");
    rep.expect(
        "duplicate name refused without replace",
        &d.put("t", &totp_item(30, &secret), false),
        &Error::Exists,
    );
    d.put("t", &totp_item(60, &secret), true)?;
    rep.check(
        "replace honoured, and it replaced rather than added",
        d.list()?.iter().filter(|e| e.name == "t").count() == 1,
        "",
    );
    // A rename re-seals the entry under the new name; the code below proves the
    // secret survived the round trip.
    d.rename("t", "t2")?;
    let names: Vec<String> = d.list()?.into_iter().map(|e| e.name).collect();
    rep.check(
        "rename",
        names.iter().any(|n| n == "t2") && !names.iter().any(|n| n == "t"),
        &format!("{names:?}"),
    );
    rep.expect(
        "rename onto a taken name refused",
        &d.rename("t2", "t2"),
        &Error::Exists,
    );
    d.rename("t2", "t")?;
    rep.tap();
    let c1 = d.code("t", Some(59))?;
    rep.check("code while unlocked proves 60s period", c1 == "287082", &c1);
    Ok(c1.text)
}

fn password(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    d.put("p", &login_item(LOGIN, PASSWORD, NOTE)?, false)?;
    rep.expect(
        "no code from a password",
        &d.code("p", Some(59)),
        &Error::BadArg,
    );
    let open = d.get("p", Reach::Open)?;
    rep.check(
        "login without a gesture",
        open.by_label("username").map(|f| f.text().to_string()) == Some(LOGIN.to_string()),
        "",
    );
    rep.check(
        "and nothing but the login",
        open.fields.iter().all(|f| f.class == Class::Open),
        "",
    );
    // A seed belongs to no reach below Seed: the item comes back without it.
    let totp_open = d.get("t", Reach::Open)?;
    rep.check(
        "no seed among a TOTP entry's open fields",
        totp_open.fields.is_empty(),
        "",
    );

    d.rename("p", "p2")?;
    rep.check(
        "login intact after a rename",
        d.get("p2", Reach::Open)?
            .by_label("username")
            .map(|f| f.text().to_string())
            == Some(LOGIN.to_string()),
        "",
    );
    d.rename("p2", "p")?;

    rep.tap();
    let shown = d.get("p", Reach::Secret)?;
    rep.check(
        "password and note after a tap",
        shown.by_label("password").map(|f| f.text().to_string()) == Some(PASSWORD.to_string())
            && shown.by_label("notesPlain").map(|f| f.text().to_string()) == Some(NOTE.to_string()),
        "",
    );
    rep.tap();
    let seedless = d.get("t", Reach::Secret)?;
    rep.check(
        "a tap never hands over a seed",
        seedless.first(Class::Seed).is_none(),
        "",
    );
    Ok(())
}

/// A `.env` of a couple of kilobytes: too big for an entry, whole after a tap.
fn env(d: &mut Device, rep: &mut Report) -> Result<Vec<u8>, Error> {
    let mut blob: Vec<u8> = Vec::new();
    for i in 0..40 {
        blob.extend_from_slice(format!("VAR_{i}={}\n", "x".repeat(40)).as_bytes());
    }
    let env = EnvBlob::new(Zeroizing::new(blob.clone()))?;
    d.put("e", &env.item(), false)?;
    rep.check(
        "env stored and listed as env",
        d.list()?
            .iter()
            .any(|e| e.name == "e" && e.category == Category::Env),
        "",
    );
    rep.expect(
        "duplicate env refused without replace",
        &d.put("e", &env.item(), false),
        &Error::Exists,
    );
    rep.expect(
        "no code from an env",
        &d.code("e", Some(59)),
        &Error::BadArg,
    );
    rep.tap();
    let shown = d.get("e", Reach::Secret)?;
    let bytes = shown
        .by_label(".env")
        .map(|f| f.value.to_vec())
        .unwrap_or_default();
    rep.check(
        "env revealed whole after a tap",
        bytes == blob,
        &format!("{} bytes", bytes.len()),
    );
    Ok(blob)
}

/// Everything out under a passphrase after two taps, the seed and the blob deleted,
/// everything back in: the same code and the same bytes prove the round trip.
fn backup(
    d: &mut Device,
    rep: &mut Report,
    first_code: &str,
    env_blob: &[u8],
) -> Result<(), Error> {
    const PASS: &str = "correct horse battery staple";
    let dir = std::env::temp_dir().join(format!("vkey-check-{}.vkb", std::process::id()));
    println!("  >>> tap {} ONCE when the light turns blue", rep.button);
    rep.expect(
        "backup refused for one tap",
        &backup::export(d, &dir, passphrase(PASS)?),
        &Error::Refused,
    );
    println!("  >>> tap {} twice when the light turns blue", rep.button);
    let n = backup::export(d, &dir, passphrase(PASS)?)?;
    rep.check("backup written", n == 3, &format!("{n} items"));
    d.delete("t")?;
    d.delete("e")?;
    rep.expect(
        "restore refused with the wrong passphrase",
        &backup::import(d, &dir, passphrase("correct horse battery")?),
        &Error::BadBackup,
    );
    let done = backup::import(d, &dir, passphrase(PASS)?)?;
    rep.check(
        "restore",
        done.count == 3 && done.skipped.is_empty(),
        &format!("{} items", done.count),
    );
    let _ = std::fs::remove_file(&dir);
    rep.tap();
    let c = d.code("t", Some(59))?;
    rep.check("code after restore", c == first_code, &c);
    rep.tap();
    let shown = d.get("e", Reach::Secret)?;
    rep.check(
        "env after restore",
        shown.by_label(".env").map(|f| f.value.to_vec()).as_deref() == Some(env_blob),
        "",
    );
    Ok(())
}

fn lock_unlock(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    d.lock()?;
    rep.check("lock", !d.pin_status()?.unlocked, "");
    rep.expect(
        "code refused while locked",
        &d.code("t", Some(59)),
        &Error::Locked,
    );
    rep.expect(
        "fields refused while locked",
        &d.get("p", Reach::Secret),
        &Error::Locked,
    );
    rep.expect(
        "even open fields refused while locked",
        &d.get("p", Reach::Open),
        &Error::Locked,
    );
    rep.expect("list refused while locked", &d.list(), &Error::Locked);
    match d.pin_unlock(pin("99999999")?) {
        Err(Error::WrongPin(n)) => rep.check(
            "wrong PIN rejected, counter down",
            n == 7,
            &format!("{n} left"),
        ),
        other => rep.check("wrong PIN rejected", false, &format!("{other:?}")),
    }
    d.pin_unlock(pin(PIN)?)?;
    rep.check(
        "correct PIN resets counter",
        d.pin_status()?.retries_left == MAX_ATTEMPTS,
        "",
    );
    Ok(())
}

fn rekey(d: &mut Device, rep: &mut Report, first_code: &str, env_blob: &[u8]) -> Result<(), Error> {
    d.pin_change(pin(PIN)?, pin(NEW_PIN)?)?;
    rep.tap();
    let c2 = d.code("t", Some(59))?;
    rep.check(
        "same code after PIN change",
        first_code == c2,
        &format!("{first_code} vs {c2}"),
    );
    rep.tap();
    let again = d.get("e", Reach::Secret)?;
    rep.check(
        "same env after PIN change",
        again.by_label(".env").map(|f| f.value.to_vec()).as_deref() == Some(env_blob),
        "",
    );
    d.lock()?;
    rep.expect_with("old PIN no longer works", &d.pin_unlock(pin(PIN)?), |e| {
        matches!(e, Error::WrongPin(_))
    });
    d.pin_unlock(pin(NEW_PIN)?)?;
    rep.check("new PIN works", d.pin_status()?.unlocked, "");
    Ok(())
}

/// An auth secret signs a challenge after a tap with the device locked, and the
/// signature verifies under the seed's public key on this side; a chip without its
/// eFuse key refuses to hold one at all.
fn auth(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    const SECRET: [u8; AUTH_SECRET_LEN] = [0x5A; AUTH_SECRET_LEN];
    let bound = d.pin_status()?.chip_bound;
    let auth_item = Item::new(Category::Auth).with(OwnedField::new(
        Class::Secret,
        FieldKind::Concealed,
        "seed",
        &SECRET,
    ));
    let added = d.put("a", &auth_item, false);
    if !bound {
        rep.expect(
            "no auth secret without a chip key",
            &added,
            &Error::Incompatible,
        );
        return Ok(());
    }
    added?;
    rep.expect(
        "no code from an auth secret",
        &d.code("a", Some(59)),
        &Error::BadArg,
    );
    let challenge = [0x33; AUTH_CHALLENGE_LEN];
    d.lock()?;
    rep.tap();
    let signature = d.respond("a", &challenge)?;
    rep.check(
        "the signature verifies under the public key",
        auth::verifies(
            &SigningKey::from_bytes(&SECRET).verifying_key(),
            &challenge,
            &signature,
        ),
        "",
    );
    let st = d.pin_status()?;
    rep.check(
        "still locked, no attempt spent",
        !st.unlocked && st.retries_left == MAX_ATTEMPTS,
        &format!("{st:?}"),
    );
    d.pin_unlock(pin(NEW_PIN)?)?;
    d.delete("a")?;
    Ok(())
}

fn wipe(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    d.lock()?;
    let mut wiped = false;
    for i in 1..=MAX_ATTEMPTS {
        match d.pin_unlock(pin("00000000")?) {
            Err(Error::WrongPin(_)) => {}
            Err(Error::Wiped) => {
                wiped = true;
                rep.check(
                    &format!("wiped after {i} wrong PINs"),
                    i == MAX_ATTEMPTS,
                    "",
                );
                break;
            }
            other => {
                rep.check("wipe sequence", false, &format!("{other:?}"));
                break;
            }
        }
    }
    rep.check("wipe happened", wiped, "");
    let st = d.pin_status()?;
    rep.check("no PIN after wipe", !st.has_pin, &format!("{st:?}"));
    d.pin_set(pin(PIN)?)?;
    rep.check("no entries after wipe", d.list()?.is_empty(), "");
    d.lock()?;
    for _ in 0..8 {
        let _ = d.pin_unlock(pin("00000000")?);
    }
    rep.check("left without a PIN", !d.pin_status()?.has_pin, "");
    Ok(())
}
