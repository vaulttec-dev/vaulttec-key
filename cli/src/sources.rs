//! Which source each synced entry came from, remembered on this host.
//!
//! The device stores no metadata beyond a name and a kind, and a source is not a
//! property of the secret: it is a property of the sync that put the secret there. A
//! byte in flash would also sit outside the AEAD tag, where anything with flash access
//! could flip it and steer a deletion. So the map lives here, in
//! `~/.config/vaultkey/sources.json`, written whole at mode 0600 - it holds entry
//! names, and a locked key deliberately names nothing.
//!
//! An entry the owner added by hand is never in the map, so a sync never deletes it.
//! A missing or unreadable map reads as empty, which deletes nothing at all.
//!
//! What a sync does with the map is here too, so that a pull from 1Password and an
//! import from a CSV claim and delete by the same rules.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::auth::replace_file;
use crate::device::{Category, Device, Error, Reach, Stored};
use crate::import::Summary;
use crate::prompt::SyncUi;

/// The buckets a name can belong to. A name has exactly one owner: the sync that
/// wrote it last.
pub const OP_ITEM: &str = "op:item";
pub const OP_DOC: &str = "op:doc";
pub const OP_ENV: &str = "op:env";
pub const FILE: &str = "file";

/// Entry names by bucket, and what each bucket was last synced against.
#[derive(Default, Serialize, Deserialize)]
pub struct Manifest {
    /// Entry name -> the bucket that last wrote it.
    owners: BTreeMap<String, String>,
    /// Bucket -> what it last mirrored: a 1Password account, a CSV path. A bucket
    /// pointed at something else must not delete what the previous source left.
    sources: BTreeMap<String, String>,
}

/// Where this host keeps a file of its own, `op_environments.json` included.
pub(crate) fn config_path(file: &str) -> Option<PathBuf> {
    let mut p = dirs::config_dir()?;
    p.push("vaultkey");
    p.push(file);
    Some(p)
}

fn path() -> Result<PathBuf, Error> {
    config_path("sources.json")
        .ok_or_else(|| Error::Value("no config directory for this user".into()))
}

impl Manifest {
    /// The map as this host has it. Anything unreadable is an empty map, which is the
    /// safe answer: an empty map deletes nothing.
    #[must_use]
    pub fn load() -> Manifest {
        let Ok(path) = path() else {
            return Manifest::default();
        };
        let Ok(data) = std::fs::read(&path) else {
            return Manifest::default();
        };
        serde_json::from_slice(&data).unwrap_or_default()
    }

    /// The map written whole, readable only by its owner. A sync saves after every
    /// write it makes: an interrupted run must not leave entries on the key that the
    /// map does not know, since nothing would ever claim them afterwards.
    pub fn save(&self) -> Result<(), Error> {
        let path = path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Value(format!("cannot write the source map: {e}")))?;
        replace_file(&path, &json, 0o600)
    }

    /// This name now belongs to this bucket. The last sync to write a name owns it.
    pub fn claim(&mut self, name: &str, bucket: &str) {
        self.owners.insert(name.to_string(), bucket.to_string());
    }

    /// Whether any source has claimed this name.
    #[must_use]
    pub fn owns(&self, name: &str) -> bool {
        self.owners.contains_key(name)
    }

    /// The name is no longer anyone's: deleted from the key, by a sync or by hand.
    pub fn forget(&mut self, name: &str) {
        self.owners.remove(name);
    }

    /// A renamed entry keeps its source under the new name.
    pub fn rename(&mut self, from: &str, to: &str) {
        if let Some(bucket) = self.owners.remove(from) {
            self.owners.insert(to.to_string(), bucket);
        }
    }

    /// True when this bucket already mirrors `source`. A bucket with no source yet, or
    /// one pointed somewhere else - another 1Password account, another CSV - answers
    /// false, and the caller must not delete anything this run.
    #[must_use]
    pub fn mirrors(&self, bucket: &str, source: &str) -> bool {
        self.sources.get(bucket).is_some_and(|s| s == source)
    }

    /// Remember what this bucket now mirrors.
    pub fn set_source(&mut self, bucket: &str, source: &str) {
        self.sources.insert(bucket.to_string(), source.to_string());
    }

    /// Every name this bucket owns that an item called `base` could have put on the
    /// key: the entry itself, and the `base:otp` / `base:<login>` shapes derived from
    /// it. Asked whenever an item is listed but not read - the login half of a
    /// qualified name cannot be guessed, only looked up here.
    #[must_use]
    pub fn family(&self, bucket: &str, base: &str) -> Vec<String> {
        let prefix = format!("{base}:");
        self.owners
            .iter()
            .filter(|(name, owner)| {
                owner.as_str() == bucket && (name.as_str() == base || name.starts_with(&prefix))
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// What this bucket owns that the source stopped offering and the key still holds.
    /// Everything else is left alone: another bucket's names, and every name the owner
    /// added by hand, which is in no bucket at all.
    #[must_use]
    pub fn to_prune(
        &self,
        bucket: &str,
        offered: &BTreeSet<String>,
        on_device: &BTreeSet<String>,
    ) -> Vec<String> {
        self.owners
            .iter()
            .filter(|(name, owner)| {
                owner.as_str() == bucket
                    && !offered.contains(name.as_str())
                    && on_device.contains(name.as_str())
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// What a put did. A name the source merely offered survives a prune; only a name
/// actually written changes hands between sources, so that a source which offers the
/// name of an entry added by hand never takes it over without touching its content.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Wrote,
    Offered,
}

/// One sync in progress: the counters printed at the end, and every name the source
/// offered since the last time these were taken. Which bucket a name belongs to is
/// the business of the phase that takes them, not of the functions that fill them.
#[derive(Default)]
pub struct SyncRun {
    pub summary: Summary,
    offered: BTreeSet<String>,
    written: BTreeSet<String>,
}

impl SyncRun {
    pub(crate) fn saw(&mut self, name: &str, outcome: Outcome) {
        if outcome == Outcome::Wrote {
            self.written.insert(name.to_string());
        }
        self.offered.insert(name.to_string());
    }

    /// Everything seen since the last call: what the source offered, and what of it
    /// was written.
    fn take(&mut self) -> (BTreeSet<String>, BTreeSet<String>) {
        (
            std::mem::take(&mut self.offered),
            std::mem::take(&mut self.written),
        )
    }
}

/// What one bucket's phase saw, and whether its listing may be trusted to delete from.
pub(crate) struct Phase {
    pub(crate) bucket: &'static str,
    /// Every name the source offered, written or merely present.
    pub(crate) offered: BTreeSet<String>,
    /// Why this bucket must not delete anything this run, when it must not.
    pub(crate) blocked: Option<String>,
}

/// Everything the last unit of work touched, folded into the phase's names and, for
/// what it wrote, into the map on disk. The map is saved as the run goes: an
/// interrupted sync must not leave entries on the key that nothing owns, since a
/// later run would find them already there and never claim them.
pub(crate) fn absorb(
    run: &mut SyncRun,
    bucket: &str,
    map: &mut Manifest,
    offered: &mut BTreeSet<String>,
) -> Result<(), Error> {
    let (seen, written) = run.take();
    let claimed = !written.is_empty();
    for name in written {
        map.claim(&name, bucket);
    }
    offered.extend(seen);
    if claimed {
        map.save()?;
    }
    Ok(())
}

/// Pings the device at most every 30 s during a long sync to reset its auto-lock.
/// Reading the open fields of an item is the ping: it needs the PIN and no gesture, so
/// a long sync never asks the person to touch the board for a heartbeat.
pub(crate) fn keep_unlocked(dev: &mut Device, target: Option<&String>, last: &mut Instant) {
    if last.elapsed() < Duration::from_secs(30) {
        return;
    }
    if let Some(name) = target {
        let _ = dev.get(name, Reach::Open);
    }
    *last = Instant::now();
}

/// Names this bucket brought that its source no longer offers, gone from the key.
/// What could not be deleted stays in the map, so the next run tries again.
pub(crate) fn prune(
    dev: &mut Device,
    map: &mut Manifest,
    phase: &Phase,
    on_device: &BTreeSet<String>,
    ping: Option<&String>,
    ui: &mut dyn SyncUi,
    run: &mut SyncRun,
) -> Result<(), Error> {
    if let Some(reason) = &phase.blocked {
        ui.info(&format!(
            "  {}: deleting nothing this run - {reason}",
            phase.bucket
        ));
        return Ok(());
    }

    let doomed = map.to_prune(phase.bucket, &phase.offered, on_device);
    if doomed.is_empty() {
        return Ok(());
    }

    // Deleting rewrites the whole image each time, so a long pass needs the same
    // auto-lock ping the writes had. If the entry it reads is one of these, the ping
    // simply stops working and the `Locked` arm below asks for the PIN.
    let mut last_ping = Instant::now();

    for name in doomed {
        keep_unlocked(dev, ping, &mut last_ping);
        let mut retried = false;
        loop {
            match dev.delete(&name) {
                Ok(()) => {
                    map.forget(&name);
                    map.save()?;
                    run.summary.deleted += 1;
                    ui.info(&format!("  deleted '{name}' (gone from the source)"));
                    break;
                }
                // Already gone: nothing to delete, nothing left to remember.
                Err(Error::NotFound) => {
                    map.forget(&name);
                    map.save()?;
                    break;
                }
                Err(Error::Locked) if !retried => {
                    retried = true;
                    ui.info("  device locked: re-authenticating PIN...");
                    ui.unlock(dev)?;
                }
                Err(e) => {
                    ui.info(&format!("  could not delete '{name}': {e}"));
                    break;
                }
            }
        }
    }
    Ok(())
}

/// An item worth pinging the device with to hold off its auto-lock: any but an auth
/// secret, which refuses to be read at all, out of a listing already in hand.
pub(crate) fn survivor(entries: &[Stored]) -> Option<String> {
    entries
        .iter()
        .find(|e| e.category != Category::Auth)
        .map(|e| e.name.clone())
}

/// Every name the key holds. A listing that does not come back reads as empty, which
/// makes every deletion below a no-op: nothing is deleted on a guess.
pub(crate) fn device_names(dev: &mut Device) -> BTreeSet<String> {
    dev.list()
        .map(|entries| entries.into_iter().map(|e| e.name).collect())
        .unwrap_or_default()
}

/// Entries the source offers that the key already holds and no source has claimed.
/// A sync can only ever write entries that are not there yet, so without this the map
/// would learn nothing about a key filled before any of it existed - and would mirror
/// it for ever without deleting a thing. Taking a name is not touching the entry: the
/// secret on the key is left exactly as it was.
///
/// The cost is that an entry added by hand under a name the source also offers becomes
/// that source's, and can later be deleted by it. Only the name is shared; the content
/// cannot be compared without a tap.
fn adopt(
    map: &mut Manifest,
    phase: &Phase,
    on_device: &BTreeSet<String>,
    ui: &mut dyn SyncUi,
) -> Result<(), Error> {
    let taken: Vec<String> = phase
        .offered
        .iter()
        .filter(|name| on_device.contains(name.as_str()) && !map.owns(name))
        .cloned()
        .collect();
    if taken.is_empty() {
        return Ok(());
    }
    ui.info(&format!(
        "  {}: {} entries already on the key are this source's",
        phase.bucket,
        taken.len()
    ));
    for name in taken {
        map.claim(&name, phase.bucket);
    }
    map.save()
}

/// The end of every mirroring run: what each source now owns, and what it dropped,
/// gone from the key. Both `vkey op` and `vkey import` end here, so they claim and
/// delete by the same rules.
pub(crate) fn finish(
    dev: &mut Device,
    map: &mut Manifest,
    phases: &[Phase],
    ping: Option<&String>,
    ui: &mut dyn SyncUi,
    run: &mut SyncRun,
) -> Result<(), Error> {
    // Asked again here: this has to be what the key holds now, after the writes.
    let on_device = device_names(dev);
    for phase in phases {
        // Ownership first: what the source offers it keeps, what it dropped it loses.
        // The two sets are disjoint, so nothing is taken only to be deleted at once.
        adopt(map, phase, &on_device, ui)?;
        prune(dev, map, phase, &on_device, ping, ui, run)?;
    }
    Ok(())
}

/// Whatever this run has written now belongs to `bucket`. For a pull of a single item
/// or environment: it claims, but never deletes - one item is not a mirror of a vault.
pub(crate) fn claim_written(run: &mut SyncRun, bucket: &str) -> Result<(), Error> {
    let mut map = Manifest::load();
    let mut ignored = BTreeSet::new();
    absorb(run, bucket, &mut map, &mut ignored)
}

/// The whole map gone, after a wipe: the key holds nothing, so no source owns
/// anything. Left behind, it would make the next hand-added entry look like an
/// abandoned one and hand it to the first sync that came along.
pub fn forget_all() {
    if let Ok(path) = path() {
        let _ = std::fs::remove_file(path);
    }
}

/// A name dropped from the map after a deletion outside a sync (`vkey rm`). The key
/// has already lost the entry, so a map that will not save must not fail the command;
/// a stale map only ever means a later sync deletes less than it could.
pub fn forget(name: &str) {
    let mut map = Manifest::load();
    map.forget(name);
    let _ = map.save();
}

/// The same, for an entry renamed by hand: its source follows the new name.
pub fn renamed(from: &str, to: &str) {
    let mut map = Manifest::load();
    map.rename(from, to);
    let _ = map.save();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    fn manifest(owned: &[(&str, &str)]) -> Manifest {
        let mut m = Manifest::default();
        for (name, bucket) in owned {
            m.claim(name, bucket);
        }
        m
    }

    #[test]
    fn prunes_only_what_the_bucket_owns_and_the_source_dropped() {
        let m = manifest(&[("gone", OP_ITEM), ("kept", OP_ITEM), ("doc", OP_DOC)]);
        let prune = m.to_prune(OP_ITEM, &set(&["kept"]), &set(&["gone", "kept", "doc"]));
        assert_eq!(prune, vec!["gone".to_string()]);
    }

    #[test]
    fn a_hand_added_entry_is_in_no_bucket_and_survives() {
        let m = manifest(&[("synced", OP_ITEM)]);
        let prune = m.to_prune(OP_ITEM, &set(&["synced"]), &set(&["synced", "by-hand"]));
        assert!(prune.is_empty());
    }

    #[test]
    fn a_name_the_source_still_offers_survives_even_when_it_was_skipped() {
        let m = manifest(&[("skipped", OP_ITEM)]);
        let prune = m.to_prune(OP_ITEM, &set(&["skipped"]), &set(&["skipped"]));
        assert!(prune.is_empty());
    }

    #[test]
    fn a_name_already_off_the_key_is_not_a_deletion() {
        let m = manifest(&[("gone", OP_ITEM)]);
        assert!(m.to_prune(OP_ITEM, &set(&[]), &set(&[])).is_empty());
    }

    #[test]
    fn the_last_sync_to_write_a_name_owns_it() {
        let mut m = manifest(&[("shared", FILE)]);
        m.claim("shared", OP_ITEM);
        assert!(m.to_prune(FILE, &set(&[]), &set(&["shared"])).is_empty());
        assert_eq!(
            m.to_prune(OP_ITEM, &set(&[]), &set(&["shared"])),
            vec!["shared".to_string()]
        );
    }

    #[test]
    fn a_forgotten_name_is_nobody_s() {
        let mut m = manifest(&[("gone", OP_ITEM)]);
        m.forget("gone");
        assert!(m.to_prune(OP_ITEM, &set(&[]), &set(&["gone"])).is_empty());
    }

    #[test]
    fn a_rename_carries_the_source_over() {
        let mut m = manifest(&[("old", OP_ITEM)]);
        m.rename("old", "new");
        assert!(m.to_prune(OP_ITEM, &set(&[]), &set(&["old"])).is_empty());
        assert_eq!(
            m.to_prune(OP_ITEM, &set(&[]), &set(&["new"])),
            vec!["new".to_string()]
        );
    }

    #[test]
    fn an_unclaimed_name_the_source_offers_is_adoptable() {
        let mut m = manifest(&[("mine", OP_ITEM)]);
        assert!(m.owns("mine"));
        // Put on the key before any of this existed: no source has it yet.
        assert!(!m.owns("older"));
        m.claim("older", OP_ITEM);
        // Once claimed it prunes like any other.
        assert_eq!(
            m.to_prune(OP_ITEM, &set(&["mine"]), &set(&["mine", "older"])),
            vec!["older".to_string()]
        );
    }

    #[test]
    fn a_family_holds_the_qualified_names_that_cannot_be_guessed() {
        let m = manifest(&[
            ("AWS", OP_ITEM),
            ("AWS:alice", OP_ITEM),
            ("AWS:bob", OP_ITEM),
            ("AWSomeApp", OP_ITEM),
            ("AWS:doc", OP_DOC),
        ]);
        let family = m.family(OP_ITEM, "AWS");
        assert!(family.contains(&"AWS".to_string()));
        assert!(family.contains(&"AWS:alice".to_string()));
        assert!(family.contains(&"AWS:bob".to_string()));
        // A longer name that merely starts with the same letters is not a child, and
        // neither is another bucket's.
        assert!(!family.contains(&"AWSomeApp".to_string()));
        assert!(!family.contains(&"AWS:doc".to_string()));
    }

    #[test]
    fn a_bucket_pointed_at_another_source_does_not_match() {
        let mut m = Manifest::default();
        assert!(!m.mirrors(OP_ITEM, "account-a"));
        m.set_source(OP_ITEM, "account-a");
        assert!(m.mirrors(OP_ITEM, "account-a"));
        assert!(!m.mirrors(OP_ITEM, "account-b"));
    }
}
