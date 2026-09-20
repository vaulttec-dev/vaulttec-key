//! 1Password integration via the official `op` CLI.
//!
//! Pulls passwords, TOTP credentials and `.env` documents directly from
//! 1Password in memory (`Zeroizing`), without writing cleartext files to disk.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::auth::replace_file;
use crate::device::{Category, Class, Device, EnvBlob, Error, FieldKind, Reach};
use crate::import::{Summary, entry_name, truncate, unique_name};
use crate::item::{Item, OwnedField, class_of, field_kind_name, field_kind_of, op_category};
use crate::prompt::SyncUi;
use crate::sources::{
    Manifest, OP_DOC, OP_ENV, OP_ITEM, Outcome, Phase, SyncRun, absorb, claim_written, config_path,
    finish, keep_unlocked, survivor,
};
use crate::totp;

/// Verifies that the `op` command-line tool is installed in `PATH` and has an active account.
fn check_op() -> Result<(), Error> {
    match Command::new("op").arg("--version").output() {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Value(
                "1Password CLI ('op') not found in PATH; see https://developer.1password.com/docs/cli/"
                    .into(),
            ));
        }
        Err(e) => return Err(Error::Value(format!("failed to run 'op': {e}"))),
    }

    let check = Command::new("op")
        .arg("vault")
        .arg("list")
        .output()
        .map_err(|e| Error::Value(format!("failed to run 'op': {e}")))?;

    if !check.status.success() {
        let err = String::from_utf8_lossy(&check.stderr);
        let msg = err.trim();
        return Err(Error::Value(if msg.is_empty() {
            "no 1Password account is configured or signed in.\n\
             Run 'op account add' (and 'eval $(op signin)') or enable \
             'Integrate with 1Password CLI' in 1Password Settings -> Developer."
                .into()
        } else {
            msg.to_string()
        }));
    }

    Ok(())
}

/// Runs `op` with the specified arguments, capturing standard output into `Zeroizing` memory.
fn op_exec(args: &[&str]) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_op()?;
    let output = Command::new("op")
        .args(args)
        .output()
        .map_err(|e| Error::Value(format!("failed to run 'op': {e}")))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let msg = err.trim();
        return Err(Error::Value(if msg.is_empty() {
            format!("'op' failed with exit code {}", output.status)
        } else {
            msg.to_string()
        }));
    }
    Ok(Zeroizing::new(output.stdout))
}

/// Runs `op` with `stdin` fed to it, for the item JSON an export sends back. The
/// secrets go down a pipe rather than into the command line, where the shell history
/// and every other process on the machine would see them.
fn op_exec_stdin(args: &[&str], stdin: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_op()?;
    let mut child = Command::new("op")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Value(format!("failed to run 'op': {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| Error::Value("'op' took no stdin".into()))?
        .write_all(stdin)
        .map_err(|e| Error::Value(format!("failed to write to 'op': {e}")))?;
    let output = child
        .wait_with_output()
        .map_err(|e| Error::Value(format!("failed to run 'op': {e}")))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let msg = err.trim();
        return Err(Error::Value(if msg.is_empty() {
            format!("'op' failed with exit code {}", output.status)
        } else {
            msg.to_string()
        }));
    }
    Ok(Zeroizing::new(output.stdout))
}

/// `op <what> list` as JSON, narrowed to a tag and a vault when given.
fn op_list(
    what: &str,
    tag: Option<&str>,
    vault: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut args = vec![what, "list", "--format", "json"];
    if let Some(t) = tag {
        args.extend(&["--tags", t]);
    }
    if let Some(v) = vault {
        args.extend(&["--vault", v]);
    }
    op_exec(&args)
}

#[derive(Deserialize, Debug)]
pub(crate) struct OpListEntry {
    pub(crate) id: String,
    pub(crate) title: String,
}

#[derive(Deserialize, Debug)]
pub(crate) struct OpField {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) label: String,
    #[serde(rename = "type", default)]
    pub(crate) field_type: String,
    #[serde(default)]
    pub(crate) purpose: Option<String>,
    #[serde(default)]
    pub(crate) value: Option<String>,
    /// Which section of the item the field is shown in. Carried because the mirror runs
    /// both ways: an item written back without its sections is a flat item.
    #[serde(default)]
    pub(crate) section: Option<OpSection>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct OpSection {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) label: Option<String>,
}

impl OpSection {
    /// What to show and store: the label if there is one, else the id 1Password made.
    fn name(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.id)
    }
}

#[derive(Deserialize, Debug)]
pub(crate) struct OpUrl {
    #[serde(default)]
    pub(crate) href: String,
    #[serde(default)]
    pub(crate) primary: bool,
}

#[derive(Deserialize, Debug)]
pub(crate) struct OpItemDetail {
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) category: String,
    #[serde(default)]
    pub(crate) fields: Vec<OpField>,
    #[serde(default)]
    pub(crate) urls: Vec<OpUrl>,
}

/// A 1Password item as the key stores it: every field, with its section, its type and
/// the class its type implies.
///
/// There is no longer a question of "which field is *the* password". The key holds
/// fields now, so `master-password`, `password_reset[password]` and a custom field
/// named in any language all travel as themselves, under their own labels, and the
/// class - not the label - decides which gesture reaches them. What used to be lost or
/// quietly substituted is simply carried.
///
/// The one field that is rewritten is a one-time password: 1Password keeps an
/// `otpauth://` URI, and the device wants the parameters and the seed, so the URI is
/// parsed here and rebuilt on the way back out.
pub(crate) fn item_of(detail: &OpItemDetail) -> Result<(Item, Vec<String>), Error> {
    let mut item = Item::new(category_of_op(&detail.category));
    let mut notes = Vec::new();

    for f in &detail.fields {
        let Some(raw) = &f.value else { continue };
        if raw.trim().is_empty() {
            continue;
        }
        let label = if f.label.is_empty() { &f.id } else { &f.label };
        let section = f.section.as_ref().map(OpSection::name).unwrap_or_default();

        // A file field carries a reference, not the file: the bytes are an attachment,
        // and `op item create` will not take one back from anywhere but a path on disk.
        if f.field_type.eq_ignore_ascii_case("FILE") {
            notes.push(format!("'{label}' is an attachment and stays in 1Password"));
            continue;
        }

        let is_otp =
            f.field_type.eq_ignore_ascii_case("OTP") || raw.trim().starts_with("otpauth://");
        let field = if is_otp {
            match totp::resolve(raw.trim(), Some(&detail.title), None, None, false) {
                Ok(r) => match totp::seed_field(r.params, &r.secret) {
                    Ok(sf) => sf,
                    Err(e) => {
                        notes.push(format!("'{label}': {e}"));
                        continue;
                    }
                },
                Err(e) => {
                    notes.push(format!("'{label}': {e}"));
                    continue;
                }
            }
        } else {
            let mut kind = field_kind_of(&f.field_type);
            if f.purpose.as_deref() == Some("PASSWORD")
                && (f.field_type.is_empty() || kind == FieldKind::String)
            {
                kind = FieldKind::Concealed;
            }
            // `purpose` is 1Password's own word for what a field is for, and both
            // PASSWORD and NOTES fields hold secrets that must not leak without a tap.
            let class = if matches!(f.purpose.as_deref(), Some("PASSWORD" | "NOTES")) {
                Class::Secret
            } else {
                class_of(kind)
            };
            OwnedField {
                class,
                kind,
                section: section.to_string(),
                label: label.clone(),
                value: Zeroizing::new(raw.trim_end_matches('\r').as_bytes().to_vec()),
            }
        };
        item.fields.push(field);
    }

    // A URL is a field of the item in 1Password's JSON but a list beside it; the key
    // keeps it as a field so an item written back still autofills.
    for (i, u) in detail
        .urls
        .iter()
        .filter(|u| !u.href.is_empty())
        .enumerate()
    {
        let label = if u.primary || i == 0 {
            "website"
        } else {
            "url"
        };
        item.fields.push(OwnedField::new(
            Class::Open,
            FieldKind::Url,
            label,
            u.href.as_bytes(),
        ));
    }

    // A secure note whose body really is a `.env` becomes one: that is what `vkey env`
    // looks for, and what a project wants back as a file.
    if item.category == Category::SecureNote
        && let Some(note) = item
            .fields
            .iter()
            .find(|f| f.label == "notesPlain")
            .or_else(|| item.first(Class::Secret))
            .or_else(|| item.first(Class::Open))
        && EnvBlob::new(note.value.clone()).is_ok()
        && (looks_like_env(&detail.title) || item.fields.len() == 1)
    {
        let blob = EnvBlob::new(note.value.clone())?;
        return Ok((blob.item(), notes));
    }

    if item.fields.is_empty() {
        return Err(Error::Value(
            "no password, one-time password or .env in it".into(),
        ));
    }
    Ok((item, notes))
}

/// Whether a title says this is a `.env` rather than a note that happens to parse.
fn looks_like_env(title: &str) -> bool {
    std::path::Path::new(title)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("env"))
        || title.to_ascii_lowercase().contains("env")
}

/// 1Password's category name as the key's category. Every one of the twenty-two is
/// stored; an unknown one becomes a secure note rather than being dropped, because a
/// category the key cannot name is still an item someone wants back.
fn category_of_op(cat: &str) -> Category {
    match cat.to_ascii_uppercase().as_str() {
        "LOGIN" => Category::Login,
        "PASSWORD" => Category::Password,
        "CREDIT_CARD" => Category::CreditCard,
        "IDENTITY" => Category::Identity,
        "DOCUMENT" => Category::Document,
        "SOFTWARE_LICENSE" => Category::SoftwareLicense,
        "BANK_ACCOUNT" => Category::BankAccount,
        "DATABASE" => Category::Database,
        "DRIVER_LICENSE" => Category::DriverLicense,
        "OUTDOOR_LICENSE" => Category::OutdoorLicense,
        "MEMBERSHIP" => Category::Membership,
        "PASSPORT" => Category::Passport,
        "REWARD_PROGRAM" => Category::RewardProgram,
        "SOCIAL_SECURITY_NUMBER" => Category::SocialSecurityNumber,
        "WIRELESS_ROUTER" => Category::WirelessRouter,
        "SERVER" => Category::Server,
        "EMAIL_ACCOUNT" => Category::EmailAccount,
        "API_CREDENTIAL" => Category::ApiCredential,
        "MEDICAL_RECORD" => Category::MedicalRecord,
        "SSH_KEY" => Category::SshKey,
        "CRYPTO_WALLET" => Category::CryptoWallet,
        _ => Category::SecureNote,
    }
}

/// Extracts a clean name for a `.env` entry from a document or note title.
#[must_use]
pub(crate) fn env_entry_name(title: &str) -> String {
    let trimmed = title.trim();
    let stripped = if let Some(base) = trimmed
        .strip_suffix(".env")
        .or_else(|| trimmed.strip_suffix(".ENV"))
    {
        base
    } else {
        trimmed
    };
    let final_name = stripped.trim();
    if final_name.is_empty() {
        "env".to_string()
    } else {
        truncate(final_name)
    }
}

/// Parses a string formatted as `name:id`, `name=id`, or `name id` into `(name, id)`.
#[must_use]
pub fn parse_env_spec(spec: &str) -> Option<(String, String)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Some((name, id)) = spec.split_once(':') {
        let n = name.trim();
        let i = id.trim();
        if !n.is_empty() && !i.is_empty() {
            return Some((n.to_string(), i.to_string()));
        }
    }
    if let Some((name, id)) = spec.split_once('=') {
        let n = name.trim();
        let i = id.trim();
        if !n.is_empty() && !i.is_empty() {
            return Some((n.to_string(), i.to_string()));
        }
    }
    let parts: Vec<&str> = spec.split_whitespace().collect();
    if parts.len() == 2 {
        let n = parts[0].trim();
        let i = parts[1].trim();
        if !n.is_empty() && !i.is_empty() {
            return Some((n.to_string(), i.to_string()));
        }
    }
    None
}

/// Path to local config file storing 1Password Environment name-to-ID mappings.
fn env_storage_path() -> Option<PathBuf> {
    config_path("op_environments.json")
}

/// Loads saved environment (name -> ID) mappings from disk.
pub fn load_saved_envs() -> HashMap<String, String> {
    let Some(path) = env_storage_path() else {
        return HashMap::new();
    };
    let Ok(data) = std::fs::read(&path) else {
        return HashMap::new();
    };
    serde_json::from_slice(&data).unwrap_or_default()
}

/// Saves or updates a saved environment (name -> ID) mapping on disk. Written the way
/// the source map is: whole, and readable only by its owner - these are entry names,
/// and a locked key names nothing.
pub fn save_saved_env(name: &str, id: &str) {
    let Some(path) = env_storage_path() else {
        return;
    };
    let mut map = load_saved_envs();
    map.insert(name.to_string(), id.to_string());
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_vec_pretty(&map) {
        let _ = replace_file(&path, &json, 0o600);
    }
}

/// Returns true if an `op` error is critical (missing binary, session locked, auth failure).
#[must_use]
pub(crate) fn is_critical_op_error(msg: &str) -> bool {
    msg.contains("not found in PATH")
        || msg.contains("not currently signed in")
        || msg.contains("authentication")
        || msg.contains("no 1Password account")
        || msg.contains("failed to run 'op'")
}

/// Stores or updates an item on the device, skipping it when it already exists and
/// `replace` is false. One function for every kind of thing there is, because there is
/// now only one kind of thing: an item.
fn put_item(
    dev: &mut Device,
    name: &str,
    item: &Item,
    replace: bool,
    ui: &mut dyn SyncUi,
    run: &mut SyncRun,
) -> Result<(), Error> {
    let mut retried = false;
    loop {
        match dev.put(name, item, false) {
            Ok(()) => {
                run.summary.added += 1;
                run.saw(name, Outcome::Wrote);
                ui.info(&format!("  stored '{name}'"));
                return Ok(());
            }
            Err(Error::Exists) if replace => {
                dev.put(name, item, true)?;
                run.summary.replaced += 1;
                run.saw(name, Outcome::Wrote);
                ui.info(&format!("  updated '{name}'"));
                return Ok(());
            }
            Err(Error::Exists) => {
                run.summary.skipped += 1;
                run.saw(name, Outcome::Offered);
                ui.info(&format!("  skipped '{name}' (already exists)"));
                return Ok(());
            }
            Err(Error::Full) => {
                run.saw(name, Outcome::Offered);
                ui.info("the device is full");
                return Err(Error::Full);
            }
            Err(Error::Locked) if !retried => {
                retried = true;
                ui.info("  device locked: re-authenticating PIN...");
                ui.unlock(dev)?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Imports secrets from a detailed 1Password item.
pub(crate) fn process_item(
    dev: &mut Device,
    item: &OpItemDetail,
    qualify_dup: bool,
    replace: bool,
    ui: &mut dyn SyncUi,
    run: &mut SyncRun,
    taken: &mut BTreeSet<String>,
) -> Result<(), Error> {
    let primary_url = item
        .urls
        .iter()
        .find(|u| u.primary)
        .map_or_else(|| item.urls.first().map_or("", |u| &u.href), |u| &u.href);

    let base_name =
        entry_name(&item.title, primary_url).unwrap_or_else(|| truncate(item.title.trim()));

    if base_name.is_empty() {
        run.summary.skipped += 1;
        return Ok(());
    }

    // One 1Password item is one item on the key: its fields travel together, under one
    // name and one tap, the way they sit together in the manager.
    let (stored, notes) = match item_of(item) {
        Ok(pair) => pair,
        Err(e) => {
            // Saying nothing here is what made a sync look like it had lost entries.
            ui.info(&format!("  skipped '{base_name}': {e}"));
            run.summary.skipped += 1;
            return Ok(());
        }
    };
    for note in &notes {
        ui.info(&format!("  '{base_name}': {note}"));
    }

    // The login tells two items of one title apart, so it is what qualifies the name.
    let qualifier = if qualify_dup {
        stored
            .by_label("username")
            .map(OwnedField::text)
            .unwrap_or_default()
    } else {
        Zeroizing::new(String::new())
    };
    let name = unique_name(&base_name, &qualifier, taken);
    put_item(dev, &name, &stored, replace, ui, run)
}

/// Imports an `.env` document from 1Password.
pub(crate) fn process_document(
    dev: &mut Device,
    doc_id: &str,
    title: &str,
    replace: bool,
    ui: &mut dyn SyncUi,
    run: &mut SyncRun,
) -> Result<(), Error> {
    let name = env_entry_name(title);
    let content = match op_exec(&["document", "get", doc_id]) {
        Ok(b) => b,
        Err(e) => {
            ui.info(&format!("  failed to get document '{title}': {e}"));
            run.summary.skipped += 1;
            run.saw(&name, Outcome::Offered);
            return Ok(());
        }
    };

    let blob = match EnvBlob::new(content) {
        Ok(b) => b,
        Err(e) => {
            ui.info(&format!("  document '{title}' is not a valid .env: {e}"));
            run.summary.skipped += 1;
            run.saw(&name, Outcome::Offered);
            return Ok(());
        }
    };

    put_item(dev, &name, &blob.item(), replace, ui, run)
}

/// Imports a 1Password Developer Environment by its ID.
pub fn process_environment(
    dev: &mut Device,
    env_name: &str,
    env_id: &str,
    replace: bool,
    ui: &mut dyn SyncUi,
    run: &mut SyncRun,
) -> Result<(), Error> {
    let name = env_entry_name(env_name);
    ui.info(&format!("syncing environment '{name}' ({env_id})..."));

    let content = match op_exec(&["environment", "read", env_id]) {
        Ok(b) => b,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("unknown command \"environment\"")
                || msg.contains("unknown command 'environment'")
            {
                ui.info(&format!(
                    "  failed to read environment '{name}': 1Password CLI does not support 'op environment'. \
                     Upgrade to beta (v2.39.1-beta.01 or newer):\n    \
                     sudo install -m 2755 -g onepassword-cli /tmp/op_beta/op /usr/bin/op"
                ));
            } else {
                ui.info(&format!("  failed to read environment '{name}': {e}"));
            }
            run.summary.skipped += 1;
            run.saw(&name, Outcome::Offered);
            return Ok(());
        }
    };

    let s = match std::str::from_utf8(&content) {
        Ok(s) => s,
        Err(e) => {
            ui.info(&format!("  environment '{name}' is not UTF-8: {e}"));
            run.summary.skipped += 1;
            run.saw(&name, Outcome::Offered);
            return Ok(());
        }
    };

    let mut clean = String::new();
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        clean.push_str(t);
        clean.push('\n');
    }

    let blob = match EnvBlob::new(Zeroizing::new(clean.into_bytes())) {
        Ok(b) => b,
        Err(e) => {
            ui.info(&format!("  environment '{name}' is not a valid .env: {e}"));
            run.summary.skipped += 1;
            run.saw(&name, Outcome::Offered);
            return Ok(());
        }
    };

    save_saved_env(&name, env_id);
    put_item(dev, &name, &blob.item(), replace, ui, run)
}

/// Which 1Password account `op` is signed in to. A run that finds a different account
/// than the map remembers deletes nothing: the listing is honest, it is simply
/// somebody else's vault, and every name from the old one would look abandoned.
fn op_account() -> Option<String> {
    #[derive(Deserialize)]
    struct Who {
        #[serde(default)]
        account_uuid: String,
        #[serde(default)]
        url: String,
    }
    let raw = op_exec(&["whoami", "--format", "json"]).ok()?;
    let who: Who = serde_json::from_slice(&raw).ok()?;
    let id = if who.account_uuid.is_empty() {
        who.url
    } else {
        who.account_uuid
    };
    (!id.is_empty()).then_some(id)
}

/// The names an item of this title can have put on the key, without reading the item:
/// the entry itself, the `.env` it may carry in a note, and whatever the map already
/// says this item left behind - its TOTP, or the `name:login` of a duplicate title,
/// which cannot be derived without the login. Needed whenever an item is listed but
/// not read: unread is not the same as withdrawn.
fn item_names(map: &Manifest, base_name: &str) -> Vec<String> {
    let mut names = map.family(OP_ITEM, base_name);
    names.push(base_name.to_string());
    names.push(env_entry_name(base_name));
    names
}

/// Why this bucket must not delete anything this run, if it must not. A narrowed
/// listing is a selection rather than a mirror of the vault, and an account that is
/// unknown or is not the one this bucket came from is somebody else's vault: every
/// name the old one left would look abandoned.
fn why_not_prune(
    map: &Manifest,
    bucket: &str,
    account: Option<&str>,
    selection: bool,
) -> Option<String> {
    if selection {
        return Some("--tag or --vault makes this a selection, not a mirror".into());
    }
    match account {
        None => Some("the 1Password account could not be identified".into()),
        Some(id) if !map.mirrors(bucket, id) => {
            Some("this bucket has not been mirrored from this 1Password account before".into())
        }
        Some(_) => None,
    }
}

/// Pulls a single item, document, or environment by title or ID. It claims what it
/// writes but never deletes: one item is not a mirror of the vault.
pub fn pull_item(
    dev: &mut Device,
    item_query: &str,
    replace: bool,
    ui: &mut dyn SyncUi,
) -> Result<Summary, Error> {
    let mut run = SyncRun::default();

    // Check if query is specified as name:id or name=id for an environment
    if let Some((name, id)) = parse_env_spec(item_query) {
        process_environment(dev, &name, &id, replace, ui, &mut run)?;
        claim_written(&mut run, OP_ENV)?;
        return Ok(run.summary);
    }

    // First, try as an item
    match op_exec(&["item", "get", item_query, "--format", "json"]) {
        Ok(raw_json) => {
            let item: OpItemDetail = serde_json::from_slice(&raw_json)
                .map_err(|e| Error::Value(format!("failed to parse 1Password item JSON: {e}")))?;
            process_item(
                dev,
                &item,
                false,
                replace,
                ui,
                &mut run,
                &mut BTreeSet::new(),
            )?;
            claim_written(&mut run, OP_ITEM)?;
            return Ok(run.summary);
        }
        Err(e) => {
            let msg = e.to_string();
            if is_critical_op_error(&msg) {
                return Err(e);
            }
        }
    }

    // If item get was not found, try as a document
    match op_exec(&["document", "get", item_query]) {
        Ok(raw_doc) => {
            let blob = EnvBlob::new(raw_doc).map_err(|e| {
                Error::Value(format!(
                    "content of '{item_query}' is not a valid .env: {e}"
                ))
            })?;
            let name = env_entry_name(item_query);
            put_item(dev, &name, &blob.item(), replace, ui, &mut run)?;
            claim_written(&mut run, OP_DOC)?;
            return Ok(run.summary);
        }
        Err(e) => {
            let msg = e.to_string();
            if is_critical_op_error(&msg) {
                return Err(e);
            }
        }
    }

    // If item and document not found, try as an environment read
    let Ok(raw_env) = op_exec(&["environment", "read", item_query]) else {
        return Err(Error::Value(format!(
            "could not find '{item_query}' as a 1Password item, document, or environment"
        )));
    };
    let name = env_entry_name(item_query);
    let s = std::str::from_utf8(&raw_env)
        .map_err(|e| Error::Value(format!("environment '{item_query}' is not UTF-8: {e}")))?;
    let mut clean = String::new();
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        clean.push_str(t);
        clean.push('\n');
    }
    let blob = EnvBlob::new(Zeroizing::new(clean.into_bytes())).map_err(|e| {
        Error::Value(format!(
            "content of environment '{item_query}' is not a valid .env: {e}"
        ))
    })?;
    put_item(dev, &name, &blob.item(), replace, ui, &mut run)?;
    claim_written(&mut run, OP_ENV)?;
    Ok(run.summary)
}

/// What every phase of a sync shares: the key, the map being filled, the counters, and
/// the ping that holds the auto-lock off while a long phase runs.
struct Mirror<'a> {
    dev: &'a mut Device,
    map: &'a mut Manifest,
    run: &'a mut SyncRun,
    ui: &'a mut dyn SyncUi,
    ping: Option<String>,
    last_ping: Instant,
    /// What the key already held when the run started.
    existing: BTreeSet<String>,
    /// What this run has already named. Two items of one site and one login would
    /// otherwise both ask for the same name, and the second would be refused.
    taken: BTreeSet<String>,
    replace: bool,
    /// Set once the key has no room left. The phases go on naming what the source
    /// offers - otherwise the rest would read as withdrawn - but write nothing more.
    full: bool,
}

impl Mirror<'_> {
    /// Passwords, TOTP secrets and the `.env` an item may carry in a note.
    fn items(&mut self, items: &[OpListEntry], blocked: Option<String>) -> Result<Phase, Error> {
        // Two items of the same title are told apart by their login, so their names
        // are not the title alone.
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for entry in items {
            *counts.entry(entry.title.as_str()).or_default() += 1;
        }

        let mut offered = BTreeSet::new();
        let mut unread: Option<String> = None;
        for entry in items {
            // Every category is mirrored now: a passport and a credit card go on the
            // key like a login does. What an item is decides nothing about whether it
            // is stored - only its fields' classes decide what comes back out.
            let is_dup = counts.get(entry.title.as_str()).copied().unwrap_or(0) > 1;
            let base_name = truncate(entry.title.trim());

            // An untitled item is named after its URL, which the listing does not
            // carry: this run cannot say which entry is its, so it must not delete.
            if base_name.is_empty() {
                unread =
                    Some("an item with no title could not be matched to its entry".to_string());
                self.run.summary.skipped += 1;
                continue;
            }

            if self.full {
                offered.extend(item_names(self.map, &base_name));
                self.run.summary.left += 1;
                continue;
            }

            // Fast path: an unchanged item is not read at all, which is why what it
            // would have produced has to be named here instead.
            if !self.replace && !is_dup && self.existing.contains(&base_name) {
                self.ui.info(&format!("syncing item '{}'...", entry.title));
                self.ui
                    .info(&format!("  skipped '{base_name}' (already exists)"));
                self.run.summary.skipped += 1;
                // Unread, but its name is spoken for all the same.
                self.taken.insert(base_name.clone());
                offered.extend(item_names(self.map, &base_name));
                continue;
            }

            keep_unlocked(self.dev, self.ping.as_ref(), &mut self.last_ping);
            self.ui.info(&format!("syncing item '{}'...", entry.title));

            // Unread is not withdrawn: keep what the item brought, and do not delete
            // from this bucket at all - a listing read only in part is not a mirror.
            let detail = match read_item(&entry.id) {
                Ok(d) => d,
                Err(e) => {
                    self.ui
                        .info(&format!("  failed to read item '{}': {e}", entry.title));
                    self.run.summary.skipped += 1;
                    offered.extend(item_names(self.map, &base_name));
                    unread = Some(format!("item '{}' could not be read", entry.title));
                    continue;
                }
            };

            match process_item(
                self.dev,
                &detail,
                is_dup,
                self.replace,
                self.ui,
                self.run,
                &mut self.taken,
            ) {
                Ok(()) => {}
                Err(Error::Full) => {
                    self.full = true;
                    offered.extend(item_names(self.map, &base_name));
                }
                Err(e) => return Err(e),
            }
            absorb(self.run, OP_ITEM, self.map, &mut offered)?;
        }

        Ok(Phase {
            bucket: OP_ITEM,
            blocked: blocked.or(unread),
            offered,
        })
    }

    /// `.env` files kept as 1Password documents.
    fn documents(
        &mut self,
        documents: Option<&[OpListEntry]>,
        blocked: Option<String>,
    ) -> Result<Phase, Error> {
        let mut offered = BTreeSet::new();
        for doc in documents.unwrap_or_default() {
            let name = env_entry_name(&doc.title);
            if self.full {
                offered.insert(name);
                self.run.summary.left += 1;
                continue;
            }
            if !self.replace && self.existing.contains(&name) {
                self.ui
                    .info(&format!("syncing document '{}'...", doc.title));
                self.ui
                    .info(&format!("  skipped env '{name}' (already exists)"));
                self.run.summary.skipped += 1;
                offered.insert(name);
                continue;
            }

            keep_unlocked(self.dev, self.ping.as_ref(), &mut self.last_ping);
            self.ui
                .info(&format!("syncing document '{}'...", doc.title));
            match process_document(
                self.dev,
                &doc.id,
                &doc.title,
                self.replace,
                self.ui,
                self.run,
            ) {
                Ok(()) => {}
                Err(Error::Full) => {
                    self.full = true;
                    offered.insert(name);
                }
                Err(e) => return Err(e),
            }
            absorb(self.run, OP_DOC, self.map, &mut offered)?;
        }

        Ok(Phase {
            bucket: OP_DOC,
            blocked,
            offered,
        })
    }

    /// 1Password Developer Environments, named by this host's saved map.
    fn environments(
        &mut self,
        environments: &[(&str, &str)],
        blocked: Option<String>,
    ) -> Result<Phase, Error> {
        let mut offered = BTreeSet::new();
        for &(name, id) in environments {
            let env_name = env_entry_name(name);
            if self.full {
                offered.insert(env_name);
                self.run.summary.left += 1;
                continue;
            }
            if !self.replace && self.existing.contains(&env_name) {
                self.ui
                    .info(&format!("syncing environment '{name}' ({id})..."));
                self.ui
                    .info(&format!("  skipped env '{env_name}' (already exists)"));
                self.run.summary.skipped += 1;
                offered.insert(env_name);
                continue;
            }

            keep_unlocked(self.dev, self.ping.as_ref(), &mut self.last_ping);
            match process_environment(self.dev, name, id, self.replace, self.ui, self.run) {
                Ok(()) => {}
                Err(Error::Full) => {
                    self.full = true;
                    offered.insert(env_name);
                }
                Err(e) => return Err(e),
            }
            absorb(self.run, OP_ENV, self.map, &mut offered)?;
        }

        Ok(Phase {
            bucket: OP_ENV,
            blocked,
            offered,
        })
    }
}

/// One item in full, by its id.
fn read_item(id: &str) -> Result<OpItemDetail, Error> {
    let raw = op_exec(&["item", "get", id, "--format", "json"])?;
    serde_json::from_slice(&raw).map_err(|e| Error::Value(format!("invalid JSON: {e}")))
}

/// Synchronizes all items (passwords, TOTP, .env) and optional environments from
/// 1Password to the key, and deletes what 1Password no longer has.
///
/// Deleting is the narrow path: only a run that mirrors the whole source deletes, and
/// only names this host's map says that source owns. An entry under a name no source
/// offers is in no bucket, so nothing here can reach it.
pub fn sync(
    dev: &mut Device,
    tag: Option<&str>,
    vault: Option<&str>,
    environments: &[(&str, &str)],
    replace: bool,
    ui: &mut dyn SyncUi,
) -> Result<Summary, Error> {
    let mut run = SyncRun::default();
    let mut map = Manifest::load();

    // Whether each bucket may delete at all, settled before anything is written: the
    // map changes as the run goes, and this question is about where the run started.
    let selection = tag.is_some() || vault.is_some();
    let account = (!selection).then(op_account).flatten();
    let account_id = account.as_deref();
    let item_blocked = why_not_prune(&map, OP_ITEM, account_id, selection);
    let doc_blocked = why_not_prune(&map, OP_DOC, account_id, selection);
    let env_blocked = why_not_prune(&map, OP_ENV, account_id, selection);

    ui.info("fetching items from 1Password...");
    let items_out = op_list("item", tag, vault)?;
    let items: Vec<OpListEntry> = serde_json::from_slice(&items_out)
        .map_err(|e| Error::Value(format!("failed to parse 1Password item list: {e}")))?;

    // A listing that failed is not an empty listing: told apart, because treating a
    // failure as "1Password has no documents" would delete every blob that came from
    // one.
    let documents: Option<Vec<OpListEntry>> = op_list("document", tag, vault)
        .ok()
        .and_then(|out| serde_json::from_slice(&out).ok());

    ui.info(&format!(
        "found {} items and {} documents in 1Password",
        items.len(),
        documents.as_ref().map_or(0, Vec::len)
    ));

    // There is no listing to ask 1Password for environments, so the whole of this
    // host's saved map is what counts as the mirror; anything less is a selection.
    let saved = load_saved_envs();
    let asked: BTreeSet<String> = environments
        .iter()
        .map(|(name, _)| env_entry_name(name))
        .collect();
    let every_env = !saved.is_empty() && saved.keys().all(|n| asked.contains(n));

    let entries = dev.list().unwrap_or_default();
    let mut mirror = Mirror {
        existing: entries.iter().map(|e| e.name.clone()).collect(),
        taken: BTreeSet::new(),
        ping: survivor(&entries),
        last_ping: Instant::now(),
        dev,
        map: &mut map,
        run: &mut run,
        ui,
        replace,
        full: false,
    };

    let phases = [
        mirror.items(
            &items,
            item_blocked.or_else(|| {
                items
                    .is_empty()
                    .then(|| "1Password listed no items at all".to_string())
            }),
        )?,
        mirror.documents(
            documents.as_deref(),
            doc_blocked.or_else(|| match &documents {
                None => Some("the document listing failed".to_string()),
                Some(d) if d.is_empty() => Some("1Password listed no documents at all".to_string()),
                Some(_) => None,
            }),
        )?,
        mirror.environments(
            environments,
            env_blocked.or_else(|| {
                (!every_env)
                    .then(|| "this run asked for some environments, not all of them".to_string())
            }),
        )?,
    ];

    // Everything the phases still hold, taken before the key and the screen are needed
    // again: `mirror` borrows both.
    let (full, ping) = (mirror.full, mirror.ping.take());

    if full {
        ui.info("the device is full: nothing more was written");
    }

    // What each source now owns, and what it dropped, gone from the key. Last, so a run
    // that stops early leaves the key holding more than it should rather than less -
    // but a full device still gets here, since deleting is what makes room.
    finish(dev, &mut map, &phases, ping.as_ref(), ui, &mut run)?;

    // Remember what each bucket now mirrors, so the next run may delete from it. Only
    // a whole-vault run has an account at all, so a selection records nothing.
    if let Some(id) = &account {
        for phase in &phases {
            map.set_source(phase.bucket, id);
        }
        map.save()?;
    }

    Ok(run.summary)
}

/// An item off the key, written back into 1Password as `op item create` takes it: the
/// same JSON `op item get` hands out.
///
/// This is the direction that made `threat-model.md` lose a claim. A seed leaves the
/// key here, in the clear, because an item written back without its one-time password
/// is not the item that was taken - and that costs the double tap, the same gesture a
/// backup costs, because it is the same act.
pub fn export_item(
    dev: &mut Device,
    name: &str,
    vault: Option<&str>,
    ui: &mut dyn SyncUi,
) -> Result<String, Error> {
    let stored = dev
        .list()?
        .into_iter()
        .find(|e| e.name == name)
        .ok_or(Error::NotFound)?;
    let Some(category) = op_category(stored.category) else {
        return Err(Error::Value(
            "an auth secret is not written back: it is this machine's login, and 1Password \
             has no use for it"
                .into(),
        ));
    };

    // What reach the item needs is what it holds: a seed costs the double tap, and
    // nothing else does. Asking for the seed reach on an item without one would cost a
    // gesture for nothing.
    let (_, shape) = dev.get_with_shape(name, Reach::Open)?;
    let reach = if shape.has_seed() {
        ui.info("tap the button twice: the whole item, seed included, is leaving the key");
        Reach::Seed
    } else if shape.has_secret() {
        ui.info("tap the button: the item is leaving the key");
        Reach::Secret
    } else {
        Reach::Open
    };
    let item = dev.get(name, reach)?;

    let json = item_json(name, category, &item)?;
    let mut args = vec!["item", "create", "-", "--format", "json"];
    if let Some(v) = vault {
        args.extend(["--vault", v]);
    }
    let out = op_exec_stdin(&args, json.as_bytes())?;
    let made: OpListEntry = serde_json::from_slice(&out)
        .map_err(|e| Error::Value(format!("'op' answered something unexpected: {e}")))?;
    Ok(made.id)
}

/// The item JSON `op item create` reads: the category, the title, and every field with
/// the section, type and label it had. Built with `serde_json` rather than by hand, so
/// a password with a quote in it cannot break the shape.
fn item_json(name: &str, category: &str, item: &Item) -> Result<Zeroizing<String>, Error> {
    let mut fields = Vec::new();
    let mut urls = Vec::new();
    for f in &item.fields {
        // A top-level URL is a field here and a list there. Custom URL fields with a section
        // or a custom label remain in fields.
        if f.kind == FieldKind::Url
            && f.section.is_empty()
            && (f.label == "website" || f.label == "url")
        {
            urls.push(serde_json::json!({
                "href": f.try_text()?.as_str(),
                "primary": f.label == "website",
            }));
            continue;
        }
        // A seed is stored as the parameters and the secret; 1Password wants the URI.
        let value = if f.class == Class::Seed {
            totp::seed_uri(name, &f.value)?
        } else {
            f.try_text()?
        };
        let is_notes = f.class == Class::Secret && f.label == "notesPlain" && f.section.is_empty();
        let kind = if f.class == Class::Secret && f.kind == FieldKind::String && !is_notes {
            FieldKind::Concealed
        } else {
            f.kind
        };
        let mut field = serde_json::Map::new();
        field.insert("id".into(), f.label.clone().into());
        field.insert("label".into(), f.label.clone().into());
        if is_notes {
            field.insert("purpose".into(), "NOTES".into());
        }
        field.insert("type".into(), field_kind_name(kind).into());
        field.insert("value".into(), value.as_str().into());
        if !f.section.is_empty() {
            field.insert(
                "section".into(),
                serde_json::json!({ "id": f.section, "label": f.section }),
            );
        }
        fields.push(serde_json::Value::Object(field));
    }
    let doc = serde_json::json!({
        "title": name,
        "category": category.to_ascii_uppercase().replace(' ', "_"),
        "fields": fields,
        "urls": urls,
    });
    serde_json::to_string(&doc)
        .map(Zeroizing::new)
        .map_err(|e| Error::Value(format!("cannot build the item JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_field_of_a_login_travels_under_its_own_label() {
        let json = r#"{
            "id": "item1",
            "title": "GitHub",
            "category": "LOGIN",
            "fields": [
                { "id": "username", "label": "username", "purpose": "USERNAME", "value": "testuser" },
                { "id": "password", "label": "password", "purpose": "PASSWORD", "value": "secret123" },
                { "id": "x", "label": "master-password", "type": "CONCEALED", "value": "other" },
                { "id": "y", "label": "\u043f\u0430\u0440\u043e\u043b\u044c", "type": "CONCEALED", "value": "custom" },
                { "id": "totp", "label": "one-time password", "type": "OTP", "value": "otpauth://totp/GitHub:testuser?secret=JBSWY3DPEHPK3PXP" }
            ],
            "urls": [
                { "href": "https://github.com", "primary": true }
            ]
        }"#;

        let detail: OpItemDetail = serde_json::from_str(json).expect("valid JSON");
        let (item, notes) = item_of(&detail).expect("an item");
        assert!(notes.is_empty());
        assert_eq!(item.category, Category::Login);

        assert_eq!(
            item.by_label("username")
                .expect("a username")
                .text()
                .as_str(),
            "testuser"
        );
        assert_eq!(
            item.by_label("password")
                .expect("a password")
                .text()
                .as_str(),
            "secret123"
        );
        // The two fields the old importer lost: one it substituted for the password,
        // one it could not name at all.
        assert_eq!(
            item.by_label("master-password")
                .expect("kept")
                .text()
                .as_str(),
            "other"
        );
        assert_eq!(
            item.by_label("пароль").expect("kept").text().as_str(),
            "custom"
        );
        assert_eq!(
            item.by_label("master-password").expect("kept").class,
            Class::Secret,
            "a concealed field needs a tap, whatever it is called"
        );

        let seed = item.first(Class::Seed).expect("a seed");
        assert_eq!(seed.kind, FieldKind::Otp);
        assert_eq!(
            &seed.value[3..],
            b"Hello!\xde\xad\xbe\xef".as_slice(),
            "the URI was decoded to the parameters and the secret"
        );
        assert_eq!(
            item.by_label("website").expect("a url").text().as_str(),
            "https://github.com"
        );
    }

    #[test]
    fn a_secure_note_that_is_an_env_becomes_one() {
        let json = r#"{
            "id": "note1",
            "title": "myapp.env",
            "category": "SECURE_NOTE",
            "fields": [
                { "id": "notesPlain", "label": "notesPlain", "purpose": "NOTES", "value": "DATABASE_URL=postgres://localhost\nPORT=8080\n" }
            ],
            "urls": []
        }"#;

        let detail: OpItemDetail = serde_json::from_str(json).expect("valid JSON");
        let (item, _) = item_of(&detail).expect("an item");
        assert_eq!(item.category, Category::Env);
        assert_eq!(
            &item.by_label(".env").expect("the blob").value[..],
            b"DATABASE_URL=postgres://localhost\nPORT=8080\n"
        );
    }

    #[test]
    fn a_category_this_cli_has_not_met_is_kept_rather_than_dropped() {
        let json = r#"{
            "id": "p",
            "title": "Passport",
            "category": "PASSPORT",
            "fields": [
                { "id": "number", "label": "number", "type": "STRING", "value": "AA123456" }
            ],
            "urls": []
        }"#;
        let detail: OpItemDetail = serde_json::from_str(json).expect("valid JSON");
        let (item, _) = item_of(&detail).expect("an item");
        assert_eq!(item.category, Category::Passport);
        assert_eq!(
            item.by_label("number").expect("kept").class,
            Class::Open,
            "a passport number is not behind a tap: it is not a secret to type in"
        );
    }

    #[test]
    fn an_item_with_nothing_in_it_says_so() {
        let json =
            r#"{ "id": "e", "title": "Empty", "category": "LOGIN", "fields": [], "urls": [] }"#;
        let detail: OpItemDetail = serde_json::from_str(json).expect("valid JSON");
        assert!(
            item_of(&detail).is_err(),
            "an item with no fields is named in the summary, not stored"
        );
    }

    #[test]
    fn an_item_written_back_is_the_json_op_hands_out() {
        let item = Item::new(Category::Login)
            .with(OwnedField::new(
                Class::Open,
                FieldKind::String,
                "username",
                b"me@example.com",
            ))
            .with(OwnedField::new(
                Class::Secret,
                FieldKind::Concealed,
                "password",
                b"hunter2",
            ))
            .with(OwnedField::new(
                Class::Open,
                FieldKind::Url,
                "website",
                b"https://github.com",
            ));
        let json = item_json("github.com", "Login", &item).expect("builds");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        assert_eq!(v["title"], "github.com");
        assert_eq!(v["category"], "LOGIN");
        assert_eq!(v["urls"][0]["href"], "https://github.com");
        assert_eq!(
            v["urls"][0]["primary"], true,
            "the field labelled website is the autofill URL"
        );
        let fields = v["fields"].as_array().expect("fields");
        assert_eq!(fields.len(), 2, "the URL left the field list");
        assert_eq!(fields[1]["type"], "CONCEALED");
        assert_eq!(fields[1]["value"], "hunter2");
    }

    #[test]
    fn test_env_entry_name_handling() {
        assert_eq!(env_entry_name(".env"), "env");
        assert_eq!(env_entry_name(".ENV"), "env");
        assert_eq!(env_entry_name("backend.env"), "backend");
        assert_eq!(env_entry_name("frontend.ENV"), "frontend");
        assert_eq!(env_entry_name("production"), "production");
    }

    #[test]
    fn test_error_filters() {
        assert!(is_critical_op_error(
            "1Password CLI ('op') not found in PATH"
        ));
        assert!(is_critical_op_error("You are not currently signed in"));
        assert!(!is_critical_op_error("item 'xyz' not found"));
    }

    #[test]
    fn an_unread_item_still_names_its_totp_and_its_env() {
        // The fast path skips an unchanged item without reading it, so these are the
        // names it would have produced. Miss one and the next sync deletes it.
        let mut map = Manifest::default();
        map.claim("GitHub", OP_ITEM);
        map.claim("GitHub:otp", OP_ITEM);
        // A duplicate title qualified by login: unguessable, only the map knows it.
        map.claim("AWS:alice", OP_ITEM);
        map.claim("AWS:bob", OP_ITEM);
        map.claim("elsewhere", OP_DOC);

        let github = item_names(&map, "GitHub");
        assert!(github.contains(&"GitHub".to_string()));
        assert!(github.contains(&"GitHub:otp".to_string()));

        let aws = item_names(&map, "AWS");
        assert!(aws.contains(&"AWS:alice".to_string()));
        assert!(aws.contains(&"AWS:bob".to_string()));
        assert!(!aws.contains(&"elsewhere".to_string()));

        // A note's .env is named after the title with the suffix taken off.
        assert!(item_names(&map, "myapp.env").contains(&"myapp".to_string()));
    }

    #[test]
    fn test_parse_env_spec_handling() {
        assert_eq!(
            parse_env_spec("doc2pay-production:blgexucrwfr2dtsxe2q4uu7dp4"),
            Some((
                "doc2pay-production".into(),
                "blgexucrwfr2dtsxe2q4uu7dp4".into()
            ))
        );
        assert_eq!(
            parse_env_spec("doc2pay-production=blgexucrwfr2dtsxe2q4uu7dp4"),
            Some((
                "doc2pay-production".into(),
                "blgexucrwfr2dtsxe2q4uu7dp4".into()
            ))
        );
        assert_eq!(
            parse_env_spec("doc2pay-production blgexucrwfr2dtsxe2q4uu7dp4"),
            Some((
                "doc2pay-production".into(),
                "blgexucrwfr2dtsxe2q4uu7dp4".into()
            ))
        );
        assert_eq!(parse_env_spec("doc2pay-production"), None);
        assert_eq!(parse_env_spec(""), None);
        assert_eq!(parse_env_spec(" : "), None);
    }

    #[test]
    fn open_field_named_notesplain_preserves_open_class_across_export_and_import() {
        let item = Item::new(Category::Login).with(OwnedField::new(
            Class::Open,
            FieldKind::String,
            "notesPlain",
            b"not a secret note",
        ));
        let json = item_json("test-login", "Login", &item).expect("builds");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let field = &v["fields"][0];
        assert_eq!(field["label"], "notesPlain");
        assert!(
            field.get("purpose").is_none(),
            "open field should not receive NOTES purpose"
        );
        assert_eq!(field["type"], "STRING");

        let detail: OpItemDetail = serde_json::from_str(&json).expect("valid JSON");
        let (imported, _) = item_of(&detail).expect("parses");
        let f = imported.by_label("notesPlain").expect("field present");
        assert_eq!(f.class, Class::Open, "open class must be preserved");
    }
}
