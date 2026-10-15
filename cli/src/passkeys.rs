//! `vkey passkey`: the passkeys the nRF52840 keeps, under the key's FIDO PIN.
//!
//! ```text
//! vkey passkey list    site and account of every passkey on the key
//! vkey passkey rm      one of them erased, picked from the list
//! vkey passkey pin     the FIDO PIN set, or changed
//! ```
//!
//! The FIDO PIN is the passkeys' own and stays apart from vkey's (`crate::fido` says
//! why). Only passkeys a site made discoverable are kept on the key; the `vkey auth`
//! login and the commit signing key are not, so no list shows them.

use zeroize::Zeroizing;

use crate::device::Error;
use crate::fido::{FIDO_PIN_MAX, FIDO_PIN_MIN, Key, Passkey, Token};
use crate::prompt;

/// The key, and a token from its FIDO PIN.
pub fn unlocked() -> Result<(Key, Token), Error> {
    let mut key = Key::open()?;
    let pin = prompt::prompt_secret("FIDO PIN")?;
    let token = key.token(&pin)?;
    Ok((key, token))
}

pub fn list() -> Result<u8, Error> {
    let (mut key, token) = unlocked()?;
    let all = key.passkeys(&token)?;
    if all.is_empty() {
        println!("no passkeys on the key");
    }
    for p in &all {
        println!("{}\t{}", p.site, p.user);
    }
    Ok(0)
}

pub fn rm() -> Result<u8, Error> {
    let (mut key, token) = unlocked()?;
    let all = key.passkeys(&token)?;
    let labels: Vec<String> = all.iter().map(label).collect();
    let options: Vec<(usize, &str, &str)> = labels
        .iter()
        .enumerate()
        .map(|(i, l)| (i, l.as_str(), ""))
        .collect();
    let Some(at) = prompt::choose("erase which passkey?", &options) else {
        println!("nothing erased");
        return Ok(0);
    };
    if !prompt::yes_no(&erase_question(&labels[at])) {
        println!("nothing erased");
        return Ok(0);
    }
    key.delete_passkey(&token, &all[at].id)?;
    println!("erased {}", labels[at]);
    Ok(0)
}

/// `vkey passkey pin`: set where there is none, changed where there is.
pub fn pin() -> Result<u8, Error> {
    let mut key = Key::open()?;
    let old = if key.pin_is_set()? {
        Some(prompt::prompt_secret("current FIDO PIN")?)
    } else {
        None
    };
    let new = new_pin()?;
    match old {
        Some(old) => key.change_pin(&old, &new)?,
        None => key.set_pin(&new)?,
    }
    println!("the FIDO PIN is set: browsers and vkey ask for it before the passkeys");
    Ok(0)
}

/// A new FIDO PIN, asked twice.
pub fn new_pin() -> Result<Zeroizing<String>, Error> {
    let new = prompt::prompt_secret(&format!(
        "new FIDO PIN ({FIDO_PIN_MIN}-{FIDO_PIN_MAX} characters, not vkey's PIN)"
    ))?;
    if !(FIDO_PIN_MIN..=FIDO_PIN_MAX).contains(&new.len()) {
        return Err(Error::Value(format!(
            "a FIDO PIN is {FIDO_PIN_MIN} to {FIDO_PIN_MAX} characters"
        )));
    }
    if prompt::prompt_secret("again")? != new {
        return Err(Error::Value(
            "the two did not match; nothing changed".into(),
        ));
    }
    Ok(new)
}

/// The question before a passkey is erased: the order that leaves nothing dead behind -
/// the site first, where the public half lives, then the key.
pub fn erase_question(label: &str) -> String {
    format!(
        "erase the passkey {label} from the key? Remove it on the site first: once erased \
         here it signs in nowhere, and the site keeps listing it until it is removed there too"
    )
}

/// How a passkey is named to a person: the site and, when the site gave one, the account.
pub fn label(p: &Passkey) -> String {
    if p.user.is_empty() {
        p.site.clone()
    } else {
        format!("{} - {}", p.site, p.user)
    }
}
