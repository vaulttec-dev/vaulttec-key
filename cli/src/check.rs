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

use zeroize::Zeroizing;

use crate::device::{
    Device, EnvBlob, Error, Kind, MAX_ATTEMPTS, Params, passphrase, password_blob, pin,
};
use crate::totp::{TEST_SECRET, decode_base32, selftest};
use crate::{backup, boards};

const PIN: &str = "123456";
const NEW_PIN: &str = "654321";
const LOGIN: &str = "me@example.com";
const PASSWORD: &str = "correct horse battery staple";
const NOTE: &str = "recovery:\n1234-5678\n8765-4321";

/// A service's usual credential, with a chosen period.
const fn totp(period: u8) -> Kind {
    Kind::Totp(Params {
        period: NonZeroU8::new(period).expect("periods here are never zero"),
        ..Params::DEFAULT
    })
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
            if d.pin_unlock(pin("000000")?) == Err(Error::Incompatible) {
                // Written under the other key setup: only a wipe clears it.
                println!(
                    "  >>> the vault is from a different key setup - hold {} down for five \
                     seconds when the light turns red",
                    rep.button
                );
                d.wipe()?;
                break;
            }
        }
    } else if !matches!(d.pin_unlock(pin("000000")?), Err(Error::NoPin)) {
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
        &d.add("x", b"xxxxxxxxxx", totp(30), false),
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
    d.add("t", &secret, totp(30), false)?;
    rep.check("add", d.list()?.iter().any(|e| e.name == "t"), "");
    rep.expect(
        "duplicate name refused without replace",
        &d.add("t", &secret, totp(30), false),
        &Error::Exists,
    );
    d.add("t", &secret, totp(60), true)?;
    let e = d.list()?.into_iter().find(|e| e.name == "t");
    rep.check(
        "replace honoured (period 60)",
        e.as_ref().map(|e| e.kind) == Some(totp(60)),
        &format!("{e:?}"),
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
    rep.check("code while unlocked", c1.len() == 6, &c1);
    Ok(c1)
}

fn password(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    let blob = password_blob("p", LOGIN, PASSWORD, NOTE)?;
    d.add("p", &blob, Kind::Password, false)?;
    rep.expect(
        "no code from a password",
        &d.code("p", Some(59)),
        &Error::BadArg,
    );
    rep.expect("no reveal of a TOTP seed", &d.reveal("t"), &Error::BadArg);
    rep.expect("no login of a TOTP seed", &d.login("t"), &Error::BadArg);
    rep.check(
        "login without a gesture",
        *d.login("p")? == LOGIN.as_bytes(),
        "",
    );
    d.rename("p", "p2")?;
    rep.check(
        "login intact after a rename",
        *d.login("p2")? == LOGIN.as_bytes(),
        "",
    );
    d.rename("p2", "p")?;
    rep.tap();
    let shown = d.reveal("p")?;
    rep.check(
        "password and note revealed after a tap",
        shown.password_bytes() == Some(PASSWORD.as_bytes())
            && shown.note() == Some(NOTE.as_bytes()),
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
    d.env_put("e", &env, false)?;
    rep.check(
        "env stored and listed as env",
        d.list()?
            .iter()
            .any(|e| e.name == "e" && e.kind == Kind::Env),
        "",
    );
    rep.expect(
        "duplicate env refused without replace",
        &d.env_put("e", &env, false),
        &Error::Exists,
    );
    rep.expect(
        "no entry over an env name",
        &d.add("e", &decode_base32(TEST_SECRET)?, totp(30), true),
        &Error::Exists,
    );
    rep.expect(
        "no env over an entry name",
        &d.env_put("t", &env, true),
        &Error::Exists,
    );
    rep.expect(
        "no code from an env",
        &d.code("e", Some(59)),
        &Error::NotFound,
    );
    rep.expect("no env from a password", &d.env_get("p"), &Error::NotFound);
    rep.tap();
    let shown = d.env_get("e")?;
    rep.check(
        "env revealed whole after a tap",
        *shown == blob,
        &format!("{} bytes", shown.len()),
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
    let n = backup::import(d, &dir, passphrase(PASS)?)?;
    rep.check("restore", n == 3, &format!("{n} items"));
    let _ = std::fs::remove_file(&dir);
    rep.tap();
    let c = d.code("t", Some(59))?;
    rep.check("code after restore", c == first_code, &c);
    rep.tap();
    let shown = d.env_get("e")?;
    rep.check("env after restore", *shown == env_blob, "");
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
        "reveal refused while locked",
        &d.reveal("p"),
        &Error::Locked,
    );
    rep.expect("env refused while locked", &d.env_get("e"), &Error::Locked);
    rep.expect("list refused while locked", &d.list(), &Error::Locked);
    match d.pin_unlock(pin("999999")?) {
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
    let again = d.env_get("e")?;
    rep.check("same env after PIN change", *again == env_blob, "");
    d.lock()?;
    rep.expect_with("old PIN no longer works", &d.pin_unlock(pin(PIN)?), |e| {
        matches!(e, Error::WrongPin(_))
    });
    d.pin_unlock(pin(NEW_PIN)?)?;
    rep.check("new PIN works", d.pin_status()?.unlocked, "");
    Ok(())
}

fn wipe(d: &mut Device, rep: &mut Report) -> Result<(), Error> {
    d.lock()?;
    let mut wiped = false;
    for i in 1..=MAX_ATTEMPTS {
        match d.pin_unlock(pin("000000")?) {
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
        let _ = d.pin_unlock(pin("000000")?);
    }
    rep.check("left without a PIN", !d.pin_status()?.has_pin, "");
    Ok(())
}
