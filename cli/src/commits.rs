//! `vkey commits`: every git commit signed with a tap on the key.
//!
//! ```text
//! vkey commits enable     an SSH key on the key, git told to sign with it
//! vkey commits disable    git stops signing; the key stays for the next enable
//! ```
//!
//! The key is a FIDO2 authenticator (the nRF52840's passkeys), and OpenSSH keeps a
//! private key on one as an `-sk` key: `ssh-keygen` makes the credential after a tap and
//! leaves on disk only its handle, which signs nothing without the key and a tap. git
//! signs with SSH keys since 2.34, so a commit is `ssh-keygen -Y sign` with that handle
//! and costs one tap. The credential is not resident: the handle in `~/.ssh` is the only
//! way back to it, and it is not in the `.vkb`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::device::Error;
use crate::{file, prompt};

/// The key handle, `.pub` next to it. Not in `~/.ssh`: GNOME Keyring loads every key
/// there into its agent, which cannot sign with a FIDO2 key, and `ssh-keygen -Y sign`
/// asks the agent first - every commit then fails with "agent refused operation".
const KEY: &str = ".config/vkey/commit-signing-key";
/// Who signed what, for `git log --show-signature` and `git verify-commit`.
const SIGNERS: &str = ".config/git/allowed_signers";

/// `vkey commits enable`: the SSH key (made once, a tap), the user's line among the
/// allowed signers, git's four settings, and the public half offered to GitHub.
pub fn enable() -> Result<u8, Error> {
    let home = home()?;
    let key = home.join(KEY);
    let key_text = key.to_string_lossy().into_owned();
    refuse_foreign("gpg.format", "ssh")?;
    refuse_foreign("user.signingkey", &key_text)?;
    let Some(email) = git_get("user.email")? else {
        return Err(Error::Value(
            "git has no user.email to sign as:  git config --global user.email you@example.com"
                .into(),
        ));
    };

    if !key.exists() {
        make_key(&key)?;
    }
    let public = fs::read_to_string(pub_path(&key))?;
    let signers = home.join(SIGNERS);
    if let Some(dir) = signers.parent() {
        fs::create_dir_all(dir)?;
    }
    let existing = match fs::read_to_string(&signers) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    file::replace(
        &signers,
        with_signer(&existing, &email, public.trim()).as_bytes(),
        0o644,
    )?;

    git_set("gpg.format", "ssh")?;
    git_set("user.signingkey", &key_text)?;
    git_set("gpg.ssh.allowedSignersFile", &signers.to_string_lossy())?;
    git_set("commit.gpgsign", "true")?;

    println!("every git commit is now signed: tap the key when its light turns amber");
    offer_to_github(&key)?;
    Ok(0)
}

/// `vkey commits disable`: git stops signing. The key, its handle and the allowed
/// signers stay, so the next enable takes no tap and GitHub needs no new key.
pub fn disable() -> Result<u8, Error> {
    let status = Command::new("git")
        .args(["config", "--global", "--unset", "commit.gpgsign"])
        .status()?;
    // 5: the setting was not there, which is what was asked for.
    if !status.success() && status.code() != Some(5) {
        return Err(Error::Value(
            "git config --unset commit.gpgsign failed".into(),
        ));
    }
    println!("git commits are no longer signed; enable again to sign with the same key");
    Ok(0)
}

/// Whether git signs every commit with this key.
pub fn enabled() -> bool {
    let Ok(home) = home() else {
        return false;
    };
    let key = home.join(KEY).to_string_lossy().into_owned();
    matches!(git_get("commit.gpgsign"), Ok(Some(v)) if v == "true")
        && matches!(git_get("user.signingkey"), Ok(Some(v)) if v == key)
}

fn home() -> Result<PathBuf, Error> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| Error::Value("HOME is not set".into()))
}

fn pub_path(key: &Path) -> PathBuf {
    let mut p = key.as_os_str().to_owned();
    p.push(".pub");
    PathBuf::from(p)
}

/// The credential, after a tap. `-N ""`: the handle needs no passphrase, because it
/// signs nothing without the key and a tap on it.
fn make_key(key: &Path) -> Result<(), Error> {
    if let Some(dir) = key.parent() {
        fs::create_dir_all(dir)?;
    }
    eprintln!("tap the key when its light turns amber, to make the signing key");
    let status = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ecdsa-sk",
            "-N",
            "",
            "-C",
            "vkey commit signing",
            "-f",
        ])
        .arg(key)
        .status()
        .map_err(|e| Error::Value(format!("ssh-keygen: {e}")))?;
    if !status.success() {
        return Err(Error::Value(
            "ssh-keygen made no key: no tap in time, or no FIDO2 key it could reach".into(),
        ));
    }
    Ok(())
}

/// GitHub shows a commit as verified only when it knows the key as a signing key.
/// Uploading publishes it, so it is asked, and needs `gh` with the scope for it.
fn offer_to_github(key: &Path) -> Result<(), Error> {
    let public = pub_path(key);
    let by_hand = format!(
        "  gh ssh-key add {} --type signing --title vkey",
        public.display()
    );
    let gh = Command::new("gh").args(["auth", "status"]).output();
    if !matches!(gh, Ok(ref o) if o.status.success()) {
        println!(
            "for GitHub to show the commits as verified, add the key as a signing key:\n{by_hand}"
        );
        return Ok(());
    }
    if !prompt::is_tty() || !prompt::yes_no("add the key to GitHub as a signing key?") {
        println!("to add it later:\n{by_hand}");
        return Ok(());
    }
    let out = Command::new("gh")
        .args(["ssh-key", "add"])
        .arg(&public)
        .args(["--type", "signing", "--title", "vkey"])
        .output()?;
    if out.status.success() {
        println!("added to GitHub: commits signed by this key show as verified");
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    if why.contains("admin:ssh_signing_key") {
        println!(
            "gh needs the scope to add signing keys first:\n  gh auth refresh -h github.com -s admin:ssh_signing_key\nthen:\n{by_hand}"
        );
    } else if why.contains("already") {
        println!("GitHub already has this key");
    } else {
        println!("GitHub refused the key: {}\n{by_hand}", why.trim());
    }
    Ok(())
}

/// A global git setting, or None when it is not set.
fn git_get(name: &str) -> Result<Option<String>, Error> {
    let out = Command::new("git")
        .args(["config", "--global", "--get", name])
        .output()
        .map_err(|e| Error::Value(format!("git: {e}")))?;
    if out.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ));
    }
    // 1: not set. Anything else is git failing, which must not read as "not set".
    if out.status.code() == Some(1) {
        return Ok(None);
    }
    Err(Error::Value(format!("git config --get {name} failed")))
}

fn git_set(name: &str, value: &str) -> Result<(), Error> {
    let status = Command::new("git")
        .args(["config", "--global", name, value])
        .status()?;
    if !status.success() {
        return Err(Error::Value(format!("git config {name} failed")));
    }
    Ok(())
}

/// A setting someone else made is not overwritten: signing with another key, or
/// through GPG, is a choice this command does not get to undo silently.
fn refuse_foreign(name: &str, ours: &str) -> Result<(), Error> {
    match git_get(name)? {
        Some(v) if v != ours => Err(Error::Value(format!(
            "git already has {name} = {v}; unset it first if vkey should sign instead:\n  git config --global --unset {name}"
        ))),
        _ => Ok(()),
    }
}

/// `existing` with `email`'s line replaced by one for `public`, every other line kept.
fn with_signer(existing: &str, email: &str, public: &str) -> String {
    let mine = format!("{email} ");
    let mut out = String::new();
    for line in existing.lines().filter(|l| !l.starts_with(&mine)) {
        out.push_str(line);
        out.push('\n');
    }
    out + email + " namespaces=\"git\" " + public + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAA vkey commit signing";

    #[test]
    fn a_signer_is_added_beside_the_others() {
        let out = with_signer("bob@x namespaces=\"git\" ssh-ed25519 BBBB\n", "me@x", KEY_A);
        assert_eq!(
            out,
            format!("bob@x namespaces=\"git\" ssh-ed25519 BBBB\nme@x namespaces=\"git\" {KEY_A}\n")
        );
    }

    #[test]
    fn a_signer_already_there_is_replaced_not_doubled() {
        let first = with_signer("", "me@x", "old-key");
        let out = with_signer(&first, "me@x", KEY_A);
        assert_eq!(out, format!("me@x namespaces=\"git\" {KEY_A}\n"));
    }

    #[test]
    fn a_longer_address_sharing_the_prefix_is_not_mine() {
        let out = with_signer("me@x.org namespaces=\"git\" k\n", "me@x", KEY_A);
        assert!(out.starts_with("me@x.org namespaces=\"git\" k\n"));
    }
}
