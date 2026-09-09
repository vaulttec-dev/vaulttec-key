//! Everything that turns a PIN into keys, and keys into sealed blobs.
//!
//!   pre      = Argon2id(pin, salt, cost)            - memory-hard: GPUs lose their edge
//!   kek      = `DeviceKey::mac`(pre)                 - chip-bound when the board has a key
//!   dek      = HMAC(kek, "vaultkey/dek/v1")          - what actually encrypts
//!   verifier = HMAC(kek, "vaultkey/verify/v1")       - stored, proves the PIN
//!
//! Only the dek stays resident while unlocked; the kek exists just long enough to
//! check the verifier and derive it. Sealed blobs are AES-256-GCM with the entry name
//! as associated data, so a blob copied into another slot fails to open.

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
pub use argon2::Block;
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::hal::DeviceKey;
use crate::oath::printable;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;
/// Four digits are ten thousand guesses, which no key derivation can make expensive.
pub const PIN_MIN: usize = 6;
pub const PIN_MAX: usize = 8;
/// A backup file has no attempt counter: whoever holds it can guess forever, at the
/// speed of their own hardware. Twelve characters is the least that makes the guessing
/// pointless behind Argon2id; the ceiling only bounds the request frame.
pub const PASS_MIN: usize = 12;
pub const PASS_MAX: usize = 128;

/// How many 1 KiB blocks the board must hand over for the key derivation.
pub const KDF_BLOCKS: usize = 128;
/// What the env key is sealed under in the image header: a random key of its own,
/// wrapped by the dek, so a PIN change re-seals sixty bytes instead of every blob.
pub const ENV_KEY_AAD: &[u8] = b"vaultkey/env-key/v1";
/// What a backup item is sealed under, followed by its position in the file: an item
/// moved, repeated or dropped from the middle fails to open on the way back in.
pub const BACKUP_AAD: &[u8] = b"vaultkey/backup/v1";

/// Argon2id cost: memory in KiB and passes over it. Stored per vault, so it can be
/// raised later without breaking existing ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cost {
    pub m_kib: u32,
    pub t: u32,
}

impl Cost {
    /// What a new vault gets: all the memory the board offers, and as many passes as
    /// fit in about a second on the ESP32-C6 - 48 passes measured at 1.2 s there.
    pub const CURRENT: Cost = Cost { m_kib: 128, t: 48 };
    /// The most this firmware will run whatever flash says: a tampered header must not
    /// be able to park the key for hours.
    pub const MAX: Cost = Cost { m_kib: 128, t: 256 };

    /// A cost read from flash. Multiples of four blocks are what Argon2 lays out
    /// exactly; anything above `MAX` or below Argon2's own minimum is refused.
    #[must_use]
    pub const fn from_wire(m_kib: u32, t: u32) -> Option<Cost> {
        if m_kib < 8 || m_kib > Self::MAX.m_kib || !m_kib.is_multiple_of(4) {
            return None;
        }
        if t == 0 || t > Self::MAX.t {
            return None;
        }
        Some(Cost { m_kib, t })
    }
}

const _: () = assert!(
    KDF_BLOCKS == Cost::MAX.m_kib as usize,
    "the board's buffer must hold the largest cost this firmware accepts"
);

/// `PIN_MIN`..=`PIN_MAX` ASCII digits, checked once at the edge. Anything else is not a
/// PIN and never reaches the key derivation or the attempt counter.
#[derive(Clone, Copy)]
pub struct Pin<'a>(&'a [u8]);

impl<'a> Pin<'a> {
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let ok = (PIN_MIN..=PIN_MAX).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_digit);
        ok.then_some(Pin(bytes))
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// `PASS_MIN`..=`PASS_MAX` printable bytes: what a backup is sealed under. Not a PIN:
/// the file it protects can be guessed at offline, so digits alone are not enough.
#[derive(Clone, Copy)]
pub struct Passphrase<'a>(&'a [u8]);

impl<'a> Passphrase<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < PASS_MIN || bytes.len() > PASS_MAX || !printable(bytes) {
            None
        } else {
            Some(Passphrase(bytes))
        }
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// Both keys, zeroized together when dropped. Nothing copies them out.
pub struct Keys {
    pub kek: [u8; KEY_LEN],
    pub dek: [u8; KEY_LEN],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.kek.zeroize();
        self.dek.zeroize();
    }
}

/// HMAC-SHA256, the one the keys and TOTP-SHA256 are made with.
pub(crate) fn hmac(key: &[u8], msg: &[u8], out: &mut [u8; KEY_LEN]) {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    out.copy_from_slice(&mac.finalize().into_bytes());
}

/// Argon2id over `secret`: the memory-hard step under both the PIN and a backup
/// passphrase. None if `mem` is too small for `cost`.
fn argon(
    secret: &[u8],
    salt: &[u8; SALT_LEN],
    cost: Cost,
    mem: &mut [Block],
) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    let blocks = usize::try_from(cost.m_kib).ok()?;
    let mem = mem.get_mut(..blocks)?;
    let params = Params::new(cost.m_kib, cost.t, 1, Some(KEY_LEN)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    let hashed = argon.hash_password_into_with_memory(secret, salt, &mut *out, &mut *mem);
    // The blocks are a function of the secret; they do not stay behind in RAM.
    mem.iter_mut().for_each(Zeroize::zeroize);
    hashed.ok()?;
    Some(out)
}

/// The key a backup is sealed under: the passphrase through Argon2id and nothing
/// else - no chip key, since the file must open on another board.
pub fn backup_key(
    pass: Passphrase<'_>,
    salt: &[u8; SALT_LEN],
    cost: Cost,
    mem: &mut [Block],
) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    argon(pass.as_bytes(), salt, cost, mem)
}

/// The keys for `pin`. None if `mem` is too small for `cost`, or the chip has no key:
/// both are errors the caller reports, never something to work around.
pub fn derive<K: DeviceKey>(
    pin: Pin<'_>,
    salt: &[u8; SALT_LEN],
    cost: Cost,
    key: &mut K,
    mem: &mut [Block],
) -> Option<Keys> {
    let pre = argon(pin.as_bytes(), salt, cost, mem)?;
    let mut k = Keys {
        kek: [0; KEY_LEN],
        dek: [0; KEY_LEN],
    };
    if !key.mac(&pre, &mut k.kek) {
        return None;
    }
    hmac(&k.kek, b"vaultkey/dek/v1", &mut k.dek);
    Some(k)
}

#[must_use]
pub fn verifier_of(kek: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut v = [0u8; KEY_LEN];
    hmac(kek, b"vaultkey/verify/v1", &mut v);
    v
}

#[must_use]
pub fn verifier_matches(kek: &[u8; KEY_LEN], stored: &[u8; KEY_LEN]) -> bool {
    let mut want = verifier_of(kek);
    let ok = want.ct_eq(stored).into();
    want.zeroize();
    ok
}

/// Encrypts `plain` into `out` as nonce | ciphertext | tag. `out` must hold
/// `plain.len() + OVERHEAD` bytes. Returns the sealed length.
pub fn seal<R: RngCore + CryptoRng>(
    dek: &[u8; KEY_LEN],
    rng: &mut R,
    aad: &[u8],
    plain: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < plain.len() + OVERHEAD {
        return None;
    }
    out[NONCE_LEN..NONCE_LEN + plain.len()].copy_from_slice(plain);
    seal_in_place(dek, rng, aad, out, plain.len())
}

/// `seal` for a plaintext already sitting in `buf` at offset `NONCE_LEN`, `plain_len`
/// bytes of it: the nonce goes in front, the tag behind, nothing is copied. For blobs
/// too big to hold twice. Returns the sealed length.
pub fn seal_in_place<R: RngCore + CryptoRng>(
    dek: &[u8; KEY_LEN],
    rng: &mut R,
    aad: &[u8],
    buf: &mut [u8],
    plain_len: usize,
) -> Option<usize> {
    let total = plain_len + OVERHEAD;
    if buf.len() < total {
        return None;
    }
    let (nonce_bytes, rest) = buf.split_at_mut(NONCE_LEN);
    let (ct, tag_bytes) = rest.split_at_mut(plain_len);
    rng.fill_bytes(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(dek).ok()?;
    let nonce = Nonce::try_from(&*nonce_bytes).ok()?;
    let tag = cipher.encrypt_inout_detached(&nonce, aad, ct.into()).ok()?;
    tag_bytes[..TAG_LEN].copy_from_slice(&tag);
    Some(total)
}

/// Reverses `seal`. `out` receives `sealed.len() - OVERHEAD` bytes. A wrong key or a
/// tampered blob leaves `out` zeroed and returns None.
pub fn open(dek: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8], out: &mut [u8]) -> Option<usize> {
    if sealed.len() < OVERHEAD {
        return None;
    }
    let pt_len = sealed.len() - OVERHEAD;
    if out.len() < pt_len {
        return None;
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (ct, tag) = rest.split_at(pt_len);
    let out = &mut out[..pt_len];
    out.copy_from_slice(ct);
    if !decrypt(dek, aad, nonce, out, tag) {
        out.zeroize();
        return None;
    }
    Some(pt_len)
}

/// `open` for a sealed blob that is all of `buf`: the plaintext replaces the
/// ciphertext at offset `NONCE_LEN`, `pt_len` bytes of it. A wrong key or a tampered
/// blob leaves everything past the nonce zeroed and returns None.
pub fn open_in_place(dek: &[u8; KEY_LEN], aad: &[u8], buf: &mut [u8]) -> Option<usize> {
    if buf.len() < OVERHEAD {
        return None;
    }
    let pt_len = buf.len() - OVERHEAD;
    let (nonce, rest) = buf.split_at_mut(NONCE_LEN);
    let (ct, tag) = rest.split_at_mut(pt_len);
    if !decrypt(dek, aad, nonce, ct, tag) {
        rest.zeroize();
        return None;
    }
    Some(pt_len)
}

/// `ct` decrypted in place under `nonce`, checked against `tag`. False - the key or
/// the bytes are wrong - leaves `ct` for the caller to scrub.
fn decrypt(dek: &[u8; KEY_LEN], aad: &[u8], nonce: &[u8], ct: &mut [u8], tag: &[u8]) -> bool {
    let (Ok(cipher), Ok(nonce), Ok(tag)) = (
        Aes256Gcm::new_from_slice(dek),
        Nonce::try_from(nonce),
        Tag::try_from(tag),
    ) else {
        return false;
    };
    cipher
        .decrypt_inout_detached(&nonce, aad, ct.into(), &tag)
        .is_ok()
}
