//! 1Password integration via the official `op` CLI.
//!
//! Pulls passwords, TOTP credentials and `.env` documents directly from
//! 1Password in memory (`Zeroizing`), without writing cleartext files to disk.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::device::{Device, EnvBlob, Error, Kind, password_blob};
use crate::import::{Summary, entry_name, truncate};
use crate::prompt::SyncUi;
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
    #[serde(default)]
    pub(crate) category: String,
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

/// Extracted credentials from a 1Password item.
pub(crate) struct Extracted {
    pub(crate) password: Option<(String, Zeroizing<String>, Zeroizing<String>)>,
    pub(crate) otp: Option<Zeroizing<String>>,
    pub(crate) env: Option<Zeroizing<Vec<u8>>>,
}

/// Inspects fields of a 1Password item and categorizes secrets.
pub(crate) fn parse_item_fields(item: &OpItemDetail) -> Extracted {
    let mut username = String::new();
    let mut password = None;
    let mut note = Zeroizing::new(String::new());
    let mut otp = None;

    for f in &item.fields {
        let Some(raw_val) = &f.value else {
            continue;
        };
        let val = raw_val.trim();
        if val.is_empty() {
            continue;
        }

        let is_password = f.purpose.as_deref() == Some("PASSWORD")
            || f.label.eq_ignore_ascii_case("password")
            || f.id.eq_ignore_ascii_case("password");
        let is_username = f.purpose.as_deref() == Some("USERNAME")
            || f.label.eq_ignore_ascii_case("username")
            || f.id.eq_ignore_ascii_case("username");
        let is_notes = f.purpose.as_deref() == Some("NOTES")
            || f.label.eq_ignore_ascii_case("notesPlain")
            || f.id.eq_ignore_ascii_case("notesPlain");
        let is_otp = f.field_type == "OTP"
            || f.label.eq_ignore_ascii_case("one-time password")
            || val.starts_with("otpauth://");

        if is_password {
            password = Some(Zeroizing::new(val.to_string()));
        } else if is_username {
            username = val.to_string();
        } else if is_notes {
            note = Zeroizing::new(raw_val.trim_end_matches('\r').to_string());
        } else if is_otp {
            otp = Some(Zeroizing::new(val.to_string()));
        }
    }

    // Check if the item is an ENV file stored in notes
    let is_env_title = std::path::Path::new(&item.title)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("env"))
        || item.title.to_ascii_lowercase().contains("env");

    let env = if item.category == "SECURE_NOTE" || is_env_title {
        if note.is_empty() {
            None
        } else {
            let note_bytes = Zeroizing::new(note.as_bytes().to_vec());
            if EnvBlob::new(note_bytes.clone()).is_ok() {
                Some(note_bytes)
            } else {
                None
            }
        }
    } else {
        None
    };

    let pass_tuple = password.map(|pw| (username, pw, note));

    Extracted {
        password: pass_tuple,
        otp,
        env,
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
        truncate(final_name.to_string())
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
    let mut p = dirs::config_dir()?;
    p.push("vaultkey");
    p.push("op_environments.json");
    Some(p)
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

/// Saves or updates a saved environment (name -> ID) mapping on disk.
pub fn save_saved_env(name: &str, id: &str) {
    let Some(path) = env_storage_path() else {
        return;
    };
    let mut map = load_saved_envs();
    map.insert(name.to_string(), id.to_string());
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        let _ = std::fs::write(&path, json);
    }
}

/// Checks whether an item category might contain credentials or environment files.
#[must_use]
pub(crate) fn is_supported_category(cat: &str) -> bool {
    matches!(
        cat.to_ascii_uppercase().as_str(),
        "LOGIN" | "PASSWORD" | "SECURE_NOTE" | "SERVER" | "DATABASE" | ""
    )
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

/// Stores or updates an entry on the device, prompting if it already exists and `replace` is false.
fn put_entry(
    dev: &mut Device,
    name: &str,
    secret: &[u8],
    kind: Kind,
    replace: bool,
    ui: &mut dyn SyncUi,
    sum: &mut Summary,
) -> Result<(), Error> {
    let mut retried = false;
    loop {
        match dev.add(name, secret, kind, false) {
            Ok(()) => {
                sum.added += 1;
                ui.info(&format!("  stored '{name}'"));
                return Ok(());
            }
            Err(Error::Exists) if replace => {
                dev.add(name, secret, kind, true)?;
                sum.replaced += 1;
                ui.info(&format!("  updated '{name}'"));
                return Ok(());
            }
            Err(Error::Exists) => {
                sum.skipped += 1;
                ui.info(&format!("  skipped '{name}' (already exists)"));
                return Ok(());
            }
            Err(Error::Full) => {
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

/// Stores or updates an `.env` blob on the device.
fn put_env(
    dev: &mut Device,
    name: &str,
    blob: &EnvBlob,
    replace: bool,
    ui: &mut dyn SyncUi,
    sum: &mut Summary,
) -> Result<(), Error> {
    let mut retried = false;
    loop {
        match dev.env_put(name, blob, false) {
            Ok(()) => {
                sum.added += 1;
                ui.info(&format!("  stored env '{name}'"));
                return Ok(());
            }
            Err(Error::Exists) if replace => {
                dev.env_put(name, blob, true)?;
                sum.replaced += 1;
                ui.info(&format!("  updated env '{name}'"));
                return Ok(());
            }
            Err(Error::Exists) => {
                sum.skipped += 1;
                ui.info(&format!("  skipped env '{name}' (already exists)"));
                return Ok(());
            }
            Err(Error::Full) => {
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
    sum: &mut Summary,
) -> Result<(), Error> {
    let primary_url = item
        .urls
        .iter()
        .find(|u| u.primary)
        .map_or_else(|| item.urls.first().map_or("", |u| &u.href), |u| &u.href);

    let base_name = entry_name(&item.title, primary_url)
        .unwrap_or_else(|| truncate(item.title.trim().to_string()));

    if base_name.is_empty() {
        sum.skipped += 1;
        return Ok(());
    }

    let extracted = parse_item_fields(item);
    let mut touched = false;

    // 1. Password
    if let Some((login, pw, note)) = extracted.password {
        let name = if qualify_dup && !login.is_empty() {
            truncate(format!("{base_name}:{login}"))
        } else {
            base_name.clone()
        };

        match password_blob(&name, &login, &pw, &note) {
            Ok(blob) => {
                put_entry(dev, &name, &blob, Kind::Password, replace, ui, sum)?;
                touched = true;
            }
            Err(e) => {
                ui.info(&format!("  skipped password for '{name}': {e}"));
            }
        }
    }

    // 2. TOTP
    if let Some(otp_val) = extracted.otp {
        let otp_name = if touched {
            truncate(format!("{base_name}:otp"))
        } else {
            base_name.clone()
        };

        match totp::resolve(&otp_val, Some(&otp_name), None, None, false) {
            Ok(resolved) => {
                put_entry(
                    dev,
                    &resolved.name,
                    &resolved.secret,
                    Kind::Totp(resolved.params),
                    replace,
                    ui,
                    sum,
                )?;
                touched = true;
            }
            Err(e) => {
                ui.info(&format!("  skipped TOTP for '{otp_name}': {e}"));
            }
        }
    }

    // 3. ENV (from notes if applicable)
    if let Some(env_bytes) = extracted.env {
        let env_name = env_entry_name(&base_name);
        match EnvBlob::new(env_bytes) {
            Ok(blob) => {
                put_env(dev, &env_name, &blob, replace, ui, sum)?;
                touched = true;
            }
            Err(e) => {
                ui.info(&format!("  skipped env '{env_name}': {e}"));
            }
        }
    }

    if !touched {
        sum.skipped += 1;
    }

    Ok(())
}

/// Imports an `.env` document from 1Password.
pub(crate) fn process_document(
    dev: &mut Device,
    doc_id: &str,
    title: &str,
    replace: bool,
    ui: &mut dyn SyncUi,
    sum: &mut Summary,
) -> Result<(), Error> {
    let content = match op_exec(&["document", "get", doc_id]) {
        Ok(b) => b,
        Err(e) => {
            ui.info(&format!("  failed to get document '{title}': {e}"));
            sum.skipped += 1;
            return Ok(());
        }
    };

    let blob = match EnvBlob::new(content) {
        Ok(b) => b,
        Err(e) => {
            ui.info(&format!("  document '{title}' is not a valid .env: {e}"));
            sum.skipped += 1;
            return Ok(());
        }
    };

    let name = env_entry_name(title);
    put_env(dev, &name, &blob, replace, ui, sum)
}

/// Imports a 1Password Developer Environment by its ID.
pub fn process_environment(
    dev: &mut Device,
    env_name: &str,
    env_id: &str,
    replace: bool,
    ui: &mut dyn SyncUi,
    sum: &mut Summary,
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
            sum.skipped += 1;
            return Ok(());
        }
    };

    let s = match std::str::from_utf8(&content) {
        Ok(s) => s,
        Err(e) => {
            ui.info(&format!("  environment '{name}' is not UTF-8: {e}"));
            sum.skipped += 1;
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
            sum.skipped += 1;
            return Ok(());
        }
    };

    save_saved_env(&name, env_id);
    put_env(dev, &name, &blob, replace, ui, sum)
}

/// Pulls a single item, document, or environment by title or ID.
pub fn pull_item(
    dev: &mut Device,
    item_query: &str,
    replace: bool,
    ui: &mut dyn SyncUi,
) -> Result<Summary, Error> {
    let mut sum = Summary::default();

    // Check if query is specified as name:id or name=id for an environment
    if let Some((name, id)) = parse_env_spec(item_query) {
        process_environment(dev, &name, &id, replace, ui, &mut sum)?;
        return Ok(sum);
    }

    // First, try as an item
    match op_exec(&["item", "get", item_query, "--format", "json"]) {
        Ok(raw_json) => {
            let item: OpItemDetail = serde_json::from_slice(&raw_json)
                .map_err(|e| Error::Value(format!("failed to parse 1Password item JSON: {e}")))?;
            process_item(dev, &item, false, replace, ui, &mut sum)?;
            return Ok(sum);
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
            put_env(dev, &name, &blob, replace, ui, &mut sum)?;
            return Ok(sum);
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
    put_env(dev, &name, &blob, replace, ui, &mut sum)?;
    Ok(sum)
}

/// Pings the device at most every 30 s during a long sync to reset its auto-lock.
fn keep_unlocked(dev: &mut Device, target: Option<&(String, Kind)>, last: &mut Instant) {
    if last.elapsed() < Duration::from_secs(30) {
        return;
    }
    if let Some((name, kind)) = target {
        match kind {
            Kind::Password => {
                let _ = dev.login(name);
            }
            Kind::Env => {
                let _ = dev.env_get(name);
            }
            Kind::Totp(_) | Kind::Auth => {}
        }
    }
    *last = Instant::now();
}

/// Synchronizes all items (passwords, TOTP, .env) and optional environments from 1Password to the key.
pub fn sync(
    dev: &mut Device,
    tag: Option<&str>,
    vault: Option<&str>,
    environments: &[(&str, &str)],
    replace: bool,
    ui: &mut dyn SyncUi,
) -> Result<Summary, Error> {
    let mut sum = Summary::default();

    let existing_entries = dev.list().unwrap_or_default();
    let existing: HashSet<String> = if replace {
        HashSet::new()
    } else {
        existing_entries.iter().map(|e| e.name.clone()).collect()
    };
    let ping_target: Option<(String, Kind)> = existing_entries
        .into_iter()
        .find(|e| matches!(e.kind, Kind::Password | Kind::Env))
        .map(|e| (e.name, e.kind));
    let mut last_ping = Instant::now();

    // 1. Fetch item list
    ui.info("fetching items from 1Password...");
    let items_out = op_list("item", tag, vault)?;
    let items: Vec<OpListEntry> = serde_json::from_slice(&items_out)
        .map_err(|e| Error::Value(format!("failed to parse 1Password item list: {e}")))?;

    // 2. Fetch document list
    let documents: Vec<OpListEntry> = match op_list("document", tag, vault) {
        Ok(out) => serde_json::from_slice(&out).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    ui.info(&format!(
        "found {} items and {} documents in 1Password",
        items.len(),
        documents.len()
    ));

    // Count title occurrences to qualify duplicates
    let mut counts: HashMap<String, usize> = HashMap::new();
    for entry in &items {
        *counts.entry(entry.title.clone()).or_default() += 1;
    }

    // 3. Process items
    for entry in &items {
        if !is_supported_category(&entry.category) {
            sum.skipped += 1;
            continue;
        }

        let is_dup = counts.get(&entry.title).copied().unwrap_or(0) > 1;
        let base_name = truncate(entry.title.trim().to_string());

        // Fast path: if not replacing and not a duplicate title, skip immediately without slow 'op item get'
        if !replace && !is_dup && !base_name.is_empty() && existing.contains(&base_name) {
            ui.info(&format!("syncing item '{}'...", entry.title));
            ui.info(&format!("  skipped '{base_name}' (already exists)"));
            sum.skipped += 1;
            continue;
        }

        keep_unlocked(dev, ping_target.as_ref(), &mut last_ping);

        ui.info(&format!("syncing item '{}'...", entry.title));
        let detail_raw = match op_exec(&["item", "get", &entry.id, "--format", "json"]) {
            Ok(d) => d,
            Err(e) => {
                ui.info(&format!("  failed to read item '{}': {e}", entry.title));
                sum.skipped += 1;
                continue;
            }
        };

        let detail: OpItemDetail = match serde_json::from_slice(&detail_raw) {
            Ok(d) => d,
            Err(e) => {
                ui.info(&format!("  invalid JSON for '{}': {e}", entry.title));
                sum.skipped += 1;
                continue;
            }
        };

        process_item(dev, &detail, is_dup, replace, ui, &mut sum)?;
    }

    // 4. Process documents
    for doc in &documents {
        let name = env_entry_name(&doc.title);
        if !replace && existing.contains(&name) {
            ui.info(&format!("syncing document '{}'...", doc.title));
            ui.info(&format!("  skipped env '{name}' (already exists)"));
            sum.skipped += 1;
            continue;
        }

        keep_unlocked(dev, ping_target.as_ref(), &mut last_ping);
        ui.info(&format!("syncing document '{}'...", doc.title));
        process_document(dev, &doc.id, &doc.title, replace, ui, &mut sum)?;
    }

    // 5. Process developer environments
    for &(name, id) in environments {
        let env_name = env_entry_name(name);
        if !replace && existing.contains(&env_name) {
            ui.info(&format!("syncing environment '{name}' ({id})..."));
            ui.info(&format!("  skipped env '{env_name}' (already exists)"));
            sum.skipped += 1;
            continue;
        }

        keep_unlocked(dev, ping_target.as_ref(), &mut last_ping);
        process_environment(dev, name, id, replace, ui, &mut sum)?;
    }

    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_login_with_otp() {
        let json = r#"{
            "id": "item1",
            "title": "GitHub",
            "category": "LOGIN",
            "fields": [
                { "id": "username", "label": "username", "purpose": "USERNAME", "value": "testuser" },
                { "id": "password", "label": "password", "purpose": "PASSWORD", "value": "secret123" },
                { "id": "totp", "label": "one-time password", "type": "OTP", "value": "otpauth://totp/GitHub:testuser?secret=JBSWY3DPEHPK3PXP" }
            ],
            "urls": [
                { "href": "https://github.com", "primary": true }
            ]
        }"#;

        let detail: OpItemDetail = serde_json::from_str(json).expect("valid JSON");
        let ext = parse_item_fields(&detail);

        assert!(ext.password.is_some());
        let (user, pass, _) = ext.password.expect("password exists");
        assert_eq!(user, "testuser");
        assert_eq!(*pass, "secret123");

        assert!(ext.otp.is_some());
        assert_eq!(
            *ext.otp.expect("otp exists"),
            "otpauth://totp/GitHub:testuser?secret=JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn parse_secure_note_env() {
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
        let ext = parse_item_fields(&detail);

        assert!(ext.env.is_some());
        let env_bytes = ext.env.expect("env exists");
        let blob = EnvBlob::new(env_bytes).expect("valid env blob");
        assert_eq!(
            blob.as_bytes(),
            b"DATABASE_URL=postgres://localhost\nPORT=8080\n"
        );
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
    fn test_category_and_error_filters() {
        assert!(is_supported_category("LOGIN"));
        assert!(is_supported_category("PASSWORD"));
        assert!(is_supported_category("SECURE_NOTE"));
        assert!(!is_supported_category("CREDIT_CARD"));
        assert!(!is_supported_category("PASSPORT"));

        assert!(is_critical_op_error(
            "1Password CLI ('op') not found in PATH"
        ));
        assert!(is_critical_op_error("You are not currently signed in"));
        assert!(!is_critical_op_error("item 'xyz' not found"));
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
}
