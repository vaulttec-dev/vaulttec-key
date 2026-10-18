//! The key's FIDO2 side, spoken directly: just enough CTAP2 over hidraw for `vkey auth`
//! to make a credential and try it. `pamu2fcfg` would do the first half, but the 1.1.0
//! that distributions ship insists on an attestation certificate, and this key attests
//! with the credential's own key, as `WebAuthn` allows (docs/roadmap.md, phase 6).
//!
//! And the passkeys the key keeps, through credentialManagement under the key's FIDO
//! PIN - its own, not vkey's: fido-authenticator keeps that PIN as a bare SHA-256, so
//! one PIN for both would hand a flash dump the vault's PIN in seconds. PIN protocol 1:
//! an ECDH agreement, its SHA-256 as the shared key, AES-256-CBC under a zero IV, and an
//! HMAC-SHA-256 cut to 16 bytes.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::boards::BOARDS;
use crate::device::Error;

const PACKET: usize = 64;
const BROADCAST: u32 = 0xFFFF_FFFF;
const CMD_INIT: u8 = 0x06;
const CMD_CBOR: u8 = 0x10;
const CMD_KEEPALIVE: u8 = 0x3B;
const CMD_ERROR: u8 = 0x3F;
const MAKE_CREDENTIAL: u8 = 0x01;
const GET_ASSERTION: u8 = 0x02;
const GET_INFO: u8 = 0x04;
const CLIENT_PIN: u8 = 0x06;
const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
/// clientPin subcommands, and the one permission asked for.
const PIN_KEY_AGREEMENT: i64 = 0x02;
const PIN_SET: i64 = 0x03;
const PIN_CHANGE: i64 = 0x04;
const PIN_TOKEN_WITH_PERMISSIONS: i64 = 0x09;
const PERMISSION_CREDENTIAL_MANAGEMENT: i64 = 0x04;
const PIN_PROTOCOL: i64 = 1;
/// credentialManagement subcommands.
const CREDS_METADATA: u8 = 0x01;
const RPS_BEGIN: u8 = 0x02;
const RPS_NEXT: u8 = 0x03;
const CREDENTIALS_BEGIN: u8 = 0x04;
const CREDENTIALS_NEXT: u8 = 0x05;
const DELETE_CREDENTIAL: u8 = 0x06;
/// The status for "nothing stored": an empty list, not a failure.
const NO_CREDENTIALS: u8 = 0x2E;
/// COSE: ECDH-ES with HKDF-256, what a key-agreement key is labelled.
const COSE_ECDH_ES_HKDF_256: i64 = -25;
/// A FIDO PIN is 4 to 63 bytes, sent padded with zeros to 64.
pub const FIDO_PIN_MIN: usize = 4;
pub const FIDO_PIN_MAX: usize = 63;
const PIN_PADDED: usize = 64;
/// COSE: EC2 keys, P-256, ES256.
const COSE_EC2: i64 = 2;
const COSE_P256: i64 = 1;
const COSE_ES256: i64 = -7;

/// A credential as `pam_u2f` stores it: its id, and the public key as x and y.
pub struct Credential {
    pub id: Vec<u8>,
    pub public: [u8; 64],
}

/// A passkey the key keeps: the site it is for, the account on it, and its id, which is
/// what deleting it takes.
#[derive(Clone)]
pub struct Passkey {
    pub site: String,
    pub user: String,
    pub id: Vec<u8>,
}

/// What the FIDO PIN unlocked: a token that lets credentialManagement through until the
/// key forgets it (a replug, or another PIN).
pub struct Token(Zeroizing<Vec<u8>>);

/// The key's CTAPHID interface on a channel of its own.
pub struct Key {
    hid: File,
    channel: u32,
}

impl Key {
    /// The one vkey on this machine with a FIDO interface.
    pub fn open() -> Result<Key, Error> {
        let path = node()?;
        let hid = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| Error::Value(format!("cannot open {}: {e}", path.display())))?;
        let mut key = Key {
            hid,
            channel: BROADCAST,
        };
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| Error::Value(format!("no randomness: {e}")))?;
        let answer = key.transact(CMD_INIT, &nonce)?;
        let channel = answer
            .strip_prefix(&nonce)
            .and_then(|rest| rest.first_chunk::<4>())
            .ok_or_else(|| Error::Value("the key answered INIT with something else".into()))?;
        key.channel = u32::from_be_bytes(*channel);
        Ok(key)
    }

    /// A non-resident credential for `rp` and `user`, after a tap.
    pub fn make_credential(&mut self, rp: &str, user: &str) -> Result<Credential, Error> {
        let request = Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Bytes(random32()?.to_vec())),
            (
                Cbor::Int(2),
                Cbor::Map(vec![(text("id"), text(rp)), (text("name"), text(rp))]),
            ),
            (
                Cbor::Int(3),
                Cbor::Map(vec![
                    (text("id"), Cbor::Bytes(random32()?.to_vec())),
                    (text("name"), text(user)),
                    (text("displayName"), text(user)),
                ]),
            ),
            (
                Cbor::Int(4),
                Cbor::Array(vec![Cbor::Map(vec![
                    (text("alg"), Cbor::Int(COSE_ES256)),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ]);
        let answer = self.cbor(MAKE_CREDENTIAL, &request)?;
        let auth_data = field(&answer, 2)
            .and_then(Cbor::as_bytes)
            .ok_or_else(|| Error::Value("the key's credential has no authenticator data".into()))?;
        attested(auth_data)
    }

    /// An assertion for `rp` with `credential`, after a tap: whether the key answers a
    /// login the way `pam_u2f` will ask for it.
    pub fn get_assertion(&mut self, rp: &str, credential: &[u8]) -> Result<(), Error> {
        let request = Cbor::Map(vec![
            (Cbor::Int(1), text(rp)),
            (Cbor::Int(2), Cbor::Bytes(random32()?.to_vec())),
            (
                Cbor::Int(3),
                Cbor::Array(vec![Cbor::Map(vec![
                    (text("id"), Cbor::Bytes(credential.to_vec())),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ]);
        let answer = self.cbor(GET_ASSERTION, &request)?;
        let flags = field(&answer, 2)
            .and_then(Cbor::as_bytes)
            .and_then(|d| d.get(32))
            .ok_or_else(|| Error::Value("the key's assertion has no authenticator data".into()))?;
        if flags & 0x01 == 0 {
            return Err(Error::Value(
                "the key answered without the tap it was asked for".into(),
            ));
        }
        Ok(())
    }

    /// Whether the key has a FIDO PIN, as getInfo's `clientPin` option says.
    pub fn pin_is_set(&mut self) -> Result<bool, Error> {
        let info = self
            .cbor_status(GET_INFO, None)?
            .map_err(|CtapError(status)| Error::Value(ctap_error(status)))?;
        let Some(Cbor::Map(options)) = field(&info, 4) else {
            return Ok(false);
        };
        Ok(options
            .iter()
            .any(|(k, v)| *k == text("clientPin") && *v == Cbor::Simple(21)))
    }

    /// The FIDO PIN set where there is none yet.
    pub fn set_pin(&mut self, new: &str) -> Result<(), Error> {
        let (platform, shared) = self.agree()?;
        let new_enc = encrypt(&shared, &padded_pin(new)?)?;
        let auth = authenticate(&*shared, &new_enc)?;
        self.cbor(
            CLIENT_PIN,
            &Cbor::Map(vec![
                (Cbor::Int(1), Cbor::Int(PIN_PROTOCOL)),
                (Cbor::Int(2), Cbor::Int(PIN_SET)),
                (Cbor::Int(3), platform),
                (Cbor::Int(4), Cbor::Bytes(auth)),
                (Cbor::Int(5), Cbor::Bytes(new_enc)),
            ]),
        )
        .map(drop)
    }

    /// The FIDO PIN changed from `old` to `new`. A wrong `old` costs one of its retries.
    pub fn change_pin(&mut self, old: &str, new: &str) -> Result<(), Error> {
        let (platform, shared) = self.agree()?;
        let new_enc = encrypt(&shared, &padded_pin(new)?)?;
        let hash_enc = encrypt(&shared, &pin_hash(old))?;
        let mut signed = new_enc.clone();
        signed.extend_from_slice(&hash_enc);
        let auth = authenticate(&*shared, &signed)?;
        self.cbor(
            CLIENT_PIN,
            &Cbor::Map(vec![
                (Cbor::Int(1), Cbor::Int(PIN_PROTOCOL)),
                (Cbor::Int(2), Cbor::Int(PIN_CHANGE)),
                (Cbor::Int(3), platform),
                (Cbor::Int(4), Cbor::Bytes(auth)),
                (Cbor::Int(5), Cbor::Bytes(new_enc)),
                (Cbor::Int(6), Cbor::Bytes(hash_enc)),
            ]),
        )
        .map(drop)
    }

    /// A token for credentialManagement and nothing else. A wrong PIN costs one of its
    /// retries; three in a row want the key replugged.
    pub fn token(&mut self, pin: &str) -> Result<Token, Error> {
        let (platform, shared) = self.agree()?;
        let hash_enc = encrypt(&shared, &pin_hash(pin))?;
        let answer = self.cbor(
            CLIENT_PIN,
            &Cbor::Map(vec![
                (Cbor::Int(1), Cbor::Int(PIN_PROTOCOL)),
                (Cbor::Int(2), Cbor::Int(PIN_TOKEN_WITH_PERMISSIONS)),
                (Cbor::Int(3), platform),
                (Cbor::Int(6), Cbor::Bytes(hash_enc)),
                (Cbor::Int(9), Cbor::Int(PERMISSION_CREDENTIAL_MANAGEMENT)),
            ]),
        )?;
        let sealed = field(&answer, 2)
            .and_then(Cbor::as_bytes)
            .ok_or_else(|| Error::Value("the key's answer has no PIN token".into()))?;
        Ok(Token(Zeroizing::new(decrypt(&shared, sealed)?)))
    }

    /// How many passkeys the key keeps, and how many more fido-authenticator reckons
    /// fit: its own estimate from the filesystem's free space, two blocks and 400 bytes
    /// apiece after a margin of five, so it errs low.
    pub fn room(&mut self, token: &Token) -> Result<(i64, i64), Error> {
        let answer = self
            .manage(token, CREDS_METADATA, None)?
            .ok_or_else(|| Error::Value("the key did not say how full it is".into()))?;
        let count = |k: i64| field(&answer, k).and_then(Cbor::as_int).unwrap_or(0);
        Ok((count(1), count(2)))
    }

    /// Every passkey the key keeps, site by site.
    pub fn passkeys(&mut self, token: &Token) -> Result<Vec<Passkey>, Error> {
        let mut out = Vec::new();
        let Some(first) = self.manage(token, RPS_BEGIN, None)? else {
            return Ok(out);
        };
        // An empty key may say so with NO_CREDENTIALS or, as fido-authenticator 0.3
        // does, with a total of none and no site.
        let total = field(&first, 5).and_then(Cbor::as_int).unwrap_or(1);
        if total == 0 {
            return Ok(out);
        }
        let mut sites = vec![first];
        for _ in 1..total {
            if let Some(next) = self.manage(token, RPS_NEXT, None)? {
                sites.push(next);
            }
        }
        for site in &sites {
            let name = printable(
                field(site, 3)
                    .and_then(|rp| text_field(rp, "id"))
                    .unwrap_or("?"),
            );
            let hash = field(site, 4)
                .and_then(Cbor::as_bytes)
                .ok_or_else(|| Error::Value("the key named a site without its hash".into()))?;
            let params = Cbor::Map(vec![(Cbor::Int(1), Cbor::Bytes(hash.to_vec()))]);
            let Some(first) = self.manage(token, CREDENTIALS_BEGIN, Some(params))? else {
                continue;
            };
            let total = field(&first, 9).and_then(Cbor::as_int).unwrap_or(1);
            let mut creds = vec![first];
            for _ in 1..total {
                if let Some(next) = self.manage(token, CREDENTIALS_NEXT, None)? {
                    creds.push(next);
                }
            }
            for c in &creds {
                let user = field(c, 6);
                let shown = printable(
                    user.and_then(|u| text_field(u, "name"))
                        .or_else(|| user.and_then(|u| text_field(u, "displayName")))
                        .unwrap_or(""),
                );
                let id = field(c, 7)
                    .and_then(|d| bytes_field(d, "id"))
                    .ok_or_else(|| {
                        Error::Value("the key listed a passkey without its id".into())
                    })?;
                out.push(Passkey {
                    site: name.clone(),
                    user: shown,
                    id: id.to_vec(),
                });
            }
        }
        Ok(out)
    }

    /// The passkey with `id` erased from the key. What the site holds stays there: the
    /// account still names this passkey until it is removed on the site too.
    pub fn delete_passkey(&mut self, token: &Token, id: &[u8]) -> Result<(), Error> {
        let params = Cbor::Map(vec![(
            Cbor::Int(2),
            Cbor::Map(vec![
                (text("id"), Cbor::Bytes(id.to_vec())),
                (text("type"), text("public-key")),
            ]),
        )]);
        self.manage(token, DELETE_CREDENTIAL, Some(params))
            .map(drop)
    }

    /// One credentialManagement subcommand. The first of a listing and every change
    /// carry the token's HMAC over the subcommand and its parameters; the "next" ones
    /// continue what was already allowed. None when the key holds nothing to list.
    fn manage(
        &mut self,
        token: &Token,
        sub: u8,
        params: Option<Cbor>,
    ) -> Result<Option<Cbor>, Error> {
        let mut request = vec![(Cbor::Int(1), Cbor::Int(i64::from(sub)))];
        if !matches!(sub, RPS_NEXT | CREDENTIALS_NEXT) {
            let mut signed = vec![sub];
            if let Some(p) = &params {
                p.encode(&mut signed);
            }
            if let Some(p) = params {
                request.push((Cbor::Int(2), p));
            }
            request.push((Cbor::Int(3), Cbor::Int(PIN_PROTOCOL)));
            request.push((Cbor::Int(4), Cbor::Bytes(authenticate(&token.0, &signed)?)));
        }
        match self.cbor_status(CREDENTIAL_MANAGEMENT, Some(&Cbor::Map(request)))? {
            Ok(answer) => Ok(Some(answer)),
            Err(CtapError(NO_CREDENTIALS)) => Ok(None),
            Err(CtapError(status)) => Err(Error::Value(ctap_error(status))),
        }
    }

    /// A fresh ECDH agreement with the key: the platform's public half as COSE, and the
    /// shared key, SHA-256 of the shared point's x.
    fn agree(&mut self) -> Result<(Cbor, Zeroizing<[u8; 32]>), Error> {
        let answer = self.cbor(
            CLIENT_PIN,
            &Cbor::Map(vec![
                (Cbor::Int(1), Cbor::Int(PIN_PROTOCOL)),
                (Cbor::Int(2), Cbor::Int(PIN_KEY_AGREEMENT)),
            ]),
        )?;
        let key = field(&answer, 1)
            .ok_or_else(|| Error::Value("the key sent no key-agreement key".into()))?;
        let coord = |k: i64| {
            field(key, k)
                .and_then(Cbor::as_bytes)
                .filter(|b| b.len() == 32)
        };
        let (Some(x), Some(y)) = (coord(-2), coord(-3)) else {
            return Err(Error::Value(
                "the key's key-agreement key is malformed".into(),
            ));
        };
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);
        let peer = PublicKey::from_sec1_bytes(&sec1)
            .map_err(|_| Error::Value("the key's key-agreement key is not on P-256".into()))?;
        // The scalar from the OS random source; the odd value outside the group is drawn
        // again rather than reduced.
        let secret = loop {
            if let Ok(s) = SecretKey::from_slice(&*Zeroizing::new(random32()?)) {
                break s;
            }
        };
        let point = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        let shared = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(point.raw_secret_bytes())));
        let public = secret.public_key().to_encoded_point(false);
        let (Some(px), Some(py)) = (public.x(), public.y()) else {
            return Err(Error::Value("no public point".into()));
        };
        let platform = Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Int(COSE_EC2)),
            (Cbor::Int(3), Cbor::Int(COSE_ECDH_ES_HKDF_256)),
            (Cbor::Int(-1), Cbor::Int(COSE_P256)),
            (Cbor::Int(-2), Cbor::Bytes(px.to_vec())),
            (Cbor::Int(-3), Cbor::Bytes(py.to_vec())),
        ]);
        Ok((platform, shared))
    }

    /// A CTAP2 command and its answer, the status byte checked.
    fn cbor(&mut self, command: u8, request: &Cbor) -> Result<Cbor, Error> {
        self.cbor_status(command, Some(request))?
            .map_err(|CtapError(status)| Error::Value(ctap_error(status)))
    }

    /// The answer, or the key's CTAP2 status when it refused: the transport failing is
    /// the outer error, the key saying no the inner one.
    fn cbor_status(
        &mut self,
        command: u8,
        request: Option<&Cbor>,
    ) -> Result<Result<Cbor, CtapError>, Error> {
        let mut payload = vec![command];
        if let Some(r) = request {
            r.encode(&mut payload);
        }
        let answer = self.transact(CMD_CBOR, &payload)?;
        let (&status, body) = answer
            .split_first()
            .ok_or_else(|| Error::Value("the key answered with nothing".into()))?;
        if status != 0 {
            return Ok(Err(CtapError(status)));
        }
        if body.is_empty() {
            return Ok(Ok(Cbor::Map(Vec::new())));
        }
        Cbor::decode(body)
            .filter(|(_, rest)| rest.is_empty())
            .map(|(v, _)| Ok(v))
            .ok_or_else(|| Error::Value("the key's answer is not CBOR".into()))
    }

    /// One CTAPHID message out and its answer back, keepalives skipped.
    fn transact(&mut self, command: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
        let len = u16::try_from(data.len()).map_err(|_| Error::BadArg)?;
        let mut report = [0u8; PACKET + 1];
        let mut head = Vec::with_capacity(PACKET);
        head.extend_from_slice(&self.channel.to_be_bytes());
        head.push(0x80 | command);
        head.extend_from_slice(&len.to_be_bytes());
        let first = data.len().min(PACKET - 7);
        head.extend_from_slice(&data[..first]);
        report[1..=head.len()].copy_from_slice(&head);
        self.hid.write_all(&report)?;
        for (seq, chunk) in (0u8..).zip(data[first..].chunks(PACKET - 5)) {
            let mut report = [0u8; PACKET + 1];
            report[1..5].copy_from_slice(&self.channel.to_be_bytes());
            report[5] = seq;
            report[6..6 + chunk.len()].copy_from_slice(chunk);
            self.hid.write_all(&report)?;
        }

        loop {
            let packet = self.packet()?;
            if packet[..4] != self.channel.to_be_bytes() && command != CMD_INIT {
                continue;
            }
            let cmd = packet[4] & 0x7F;
            if cmd == CMD_KEEPALIVE {
                continue;
            }
            if cmd == CMD_ERROR {
                return Err(Error::Value(format!(
                    "the key refused the request (CTAPHID error {:#04x})",
                    packet[7]
                )));
            }
            let total = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(&packet[7..7 + total.min(PACKET - 7)]);
            let mut next = 0u8;
            while out.len() < total {
                let more = self.packet()?;
                // Another program's channel shares the hidraw node: not ours to read.
                if more[..4] != packet[..4] {
                    continue;
                }
                if more[4] != next {
                    return Err(Error::Value(format!(
                        "the key sent packet {} of its answer where {next} was due",
                        more[4]
                    )));
                }
                next = next.wrapping_add(1);
                let take = (total - out.len()).min(PACKET - 5);
                out.extend_from_slice(&more[5..5 + take]);
            }
            return Ok(out);
        }
    }

    fn packet(&mut self) -> Result<[u8; PACKET], Error> {
        let mut packet = [0u8; PACKET];
        let n = self.hid.read(&mut packet)?;
        if n != PACKET {
            return Err(Error::Value(format!("the key sent a {n}-byte packet")));
        }
        Ok(packet)
    }
}

/// The hidraw node of a vkey board: the one whose HID id names a board's USB pair and
/// whose reports are FIDO's - the key is a keyboard too (`vkey login`), on another node.
fn node() -> Result<PathBuf, Error> {
    // Usage page 0xF1D0, the first item of a FIDO report descriptor.
    const FIDO_PAGE: [u8; 3] = [0x06, 0xD0, 0xF1];
    let mut found = Vec::new();
    for entry in fs::read_dir("/sys/class/hidraw")? {
        let entry = entry?;
        let uevent = fs::read_to_string(entry.path().join("device/uevent")).unwrap_or_default();
        let board = BOARDS.iter().any(|b| {
            uevent.contains(&format!(
                "HID_ID=0003:0000{:04X}:0000{:04X}",
                b.usb_vid, b.usb_pid
            ))
        });
        let fido = fs::read(entry.path().join("device/report_descriptor"))
            .is_ok_and(|d| d.starts_with(&FIDO_PAGE));
        if board && fido {
            found.push(PathBuf::from("/dev").join(entry.file_name()));
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(Error::Value(
            "no key with passkeys is plugged in (the nRF52840 board)".into(),
        )),
        _ => Err(Error::Value(
            "more than one key is plugged in: leave one".into(),
        )),
    }
}

/// The credential in makeCredential's authenticator data:
/// `rpIdHash(32) | flags | counter(4) | aaguid(16) | idLen(2) | id | COSE key`.
fn attested(auth_data: &[u8]) -> Result<Credential, Error> {
    let bad = |what: &str| Error::Value(format!("the key's credential {what}"));
    let flags = *auth_data.get(32).ok_or_else(|| bad("is too short"))?;
    if flags & 0x40 == 0 {
        return Err(bad("carries no public key"));
    }
    let rest = auth_data
        .get(37 + 16..)
        .ok_or_else(|| bad("is too short"))?;
    let (len, rest) = rest
        .split_first_chunk::<2>()
        .ok_or_else(|| bad("is too short"))?;
    let (id, rest) = rest
        .split_at_checked(usize::from(u16::from_be_bytes(*len)))
        .ok_or_else(|| bad("is cut short"))?;
    let (cose, _) = Cbor::decode(rest).ok_or_else(|| bad("has no COSE key"))?;
    let int = |k: i64| field(&cose, k).and_then(Cbor::as_int);
    if int(1) != Some(COSE_EC2) || int(3) != Some(COSE_ES256) || int(-1) != Some(COSE_P256) {
        return Err(bad("is not a P-256 key"));
    }
    let coord = |k: i64| {
        field(&cose, k)
            .and_then(Cbor::as_bytes)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
    };
    let (Some(x), Some(y)) = (coord(-2), coord(-3)) else {
        return Err(bad("has a malformed public key"));
    };
    let mut public = [0u8; 64];
    public[..32].copy_from_slice(&x);
    public[32..].copy_from_slice(&y);
    Ok(Credential {
        id: id.to_vec(),
        public,
    })
}

fn ctap_error(status: u8) -> String {
    let why = match status {
        0x27 => "the key refused",
        0x2D => "the request was cancelled",
        0x2E => "the key has no such credential",
        0x2F => "nobody tapped the key in time",
        0x31 => "wrong FIDO PIN",
        0x32 => "the FIDO PIN is blocked: only a FIDO reset (every passkey gone) clears it",
        0x33 | 0x34 => "three wrong FIDO PINs in a row: replug the key and try again",
        0x35 => "the key has no FIDO PIN yet: set one in /settings → passkey PIN",
        0x36 => "the key's FIDO PIN is needed",
        0x37 => "the key does not take that FIDO PIN (4 to 63 characters)",
        _ => "the key refused the request",
    };
    format!("{why} (CTAP2 status {status:#04x})")
}

/// A CTAP2 status other than success: the key answered, and said no.
struct CtapError(u8);

/// AES-256-CBC under the zero IV, as PIN protocol 1 has it; `data` is whole blocks.
fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = data.to_vec();
    cbc::Encryptor::<aes::Aes256>::new(key.into(), &[0u8; 16].into())
        .encrypt_padded::<NoPadding>(&mut buf, data.len())
        .map_err(|_| Error::Value("not whole AES blocks".into()))?;
    Ok(buf)
}

fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = data.to_vec();
    let len = cbc::Decryptor::<aes::Aes256>::new(key.into(), &[0u8; 16].into())
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| Error::Value("the key's ciphertext is not whole AES blocks".into()))?
        .len();
    buf.truncate(len);
    Ok(buf)
}

/// HMAC-SHA-256 under `key`, its first 16 bytes: PIN protocol 1's `pinUvAuthParam`.
fn authenticate(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| Error::Value("no HMAC key".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes()[..16].to_vec())
}

/// The first 16 bytes of the PIN's SHA-256: what the key compares with what it stored.
fn pin_hash(pin: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Sha256::digest(pin.as_bytes())[..16].to_vec())
}

/// A new PIN padded with zeros to 64 bytes; its length checked as the key will.
fn padded_pin(pin: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(FIDO_PIN_MIN..=FIDO_PIN_MAX).contains(&pin.len()) {
        return Err(Error::Value(format!(
            "a FIDO PIN is {FIDO_PIN_MIN} to {FIDO_PIN_MAX} characters"
        )));
    }
    let mut out = Zeroizing::new(vec![0u8; PIN_PADDED]);
    out[..pin.len()].copy_from_slice(pin.as_bytes());
    Ok(out)
}

/// A name a site chose, with what a terminal would act on rather than show - escape
/// sequences, line breaks - turned into `?`: these names are printed.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The text under key `k` of a CBOR map keyed by text.
fn text_field<'a>(map: &'a Cbor, k: &str) -> Option<&'a str> {
    let Cbor::Map(entries) = map else {
        return None;
    };
    entries.iter().find_map(|(key, v)| match (key, v) {
        (Cbor::Text(name), Cbor::Text(t)) if name == k => Some(t.as_str()),
        _ => None,
    })
}

fn bytes_field<'a>(map: &'a Cbor, k: &str) -> Option<&'a [u8]> {
    let Cbor::Map(entries) = map else {
        return None;
    };
    entries.iter().find_map(|(key, v)| match (key, v) {
        (Cbor::Text(name), Cbor::Bytes(b)) if name == k => Some(b.as_slice()),
        _ => None,
    })
}

fn random32() -> Result<[u8; 32], Error> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| Error::Value(format!("no randomness: {e}")))?;
    Ok(b)
}

fn text(s: &str) -> Cbor {
    Cbor::Text(s.to_string())
}

/// The value under integer key `k` of a CBOR map.
fn field(map: &Cbor, k: i64) -> Option<&Cbor> {
    let Cbor::Map(entries) = map else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_int() == Some(k))
        .map(|(_, v)| v)
}

/// CBOR, the part CTAP2 uses here. Maps are written in the order given, which the
/// requests above give canonically: integers ascending, then shorter text first.
#[derive(Debug, PartialEq)]
enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Simple(u8),
}

impl Cbor {
    fn as_int(&self) -> Option<i64> {
        match self {
            Cbor::Int(n) => Some(*n),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Cbor::Int(n) if *n >= 0 => head(out, 0, n.unsigned_abs()),
            Cbor::Int(n) => head(out, 1, (n + 1).unsigned_abs()),
            Cbor::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Cbor::Text(t) => {
                head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Cbor::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.encode(out);
                }
            }
            Cbor::Map(entries) => {
                head(out, 5, entries.len() as u64);
                for (k, v) in entries {
                    k.encode(out);
                    v.encode(out);
                }
            }
            Cbor::Simple(s) => out.push(0xE0 | s),
        }
    }

    fn decode(b: &[u8]) -> Option<(Cbor, &[u8])> {
        Self::decode_at(b, 0)
    }

    /// Nesting is bounded: a hostile answer must not run the stack out.
    fn decode_at(input: &[u8], depth: u8) -> Option<(Cbor, &[u8])> {
        if depth > 8 {
            return None;
        }
        let (&first, mut rest) = input.split_first()?;
        let (major, info) = (first >> 5, first & 0x1F);
        let arg: u64 = match info {
            0..=23 => u64::from(info),
            FOLLOWS_1 => {
                let (byte, tail) = rest.split_first()?;
                rest = tail;
                u64::from(*byte)
            }
            FOLLOWS_2 => {
                let (bytes, tail) = rest.split_first_chunk::<2>()?;
                rest = tail;
                u64::from(u16::from_be_bytes(*bytes))
            }
            FOLLOWS_4 => {
                let (bytes, tail) = rest.split_first_chunk::<4>()?;
                rest = tail;
                u64::from(u32::from_be_bytes(*bytes))
            }
            FOLLOWS_8 => {
                let (bytes, tail) = rest.split_first_chunk::<8>()?;
                rest = tail;
                u64::from_be_bytes(*bytes)
            }
            _ => return None,
        };
        match major {
            0 => Some((Cbor::Int(i64::try_from(arg).ok()?), rest)),
            1 => Some((Cbor::Int(-1 - i64::try_from(arg).ok()?), rest)),
            2 | 3 => {
                let (bytes, tail) = rest.split_at_checked(usize::try_from(arg).ok()?)?;
                let value = if major == 2 {
                    Cbor::Bytes(bytes.to_vec())
                } else {
                    Cbor::Text(String::from_utf8(bytes.to_vec()).ok()?)
                };
                Some((value, tail))
            }
            4 => {
                let mut items = Vec::new();
                for _ in 0..arg {
                    let (item, tail) = Self::decode_at(rest, depth + 1)?;
                    items.push(item);
                    rest = tail;
                }
                Some((Cbor::Array(items), rest))
            }
            5 => {
                let mut entries = Vec::new();
                for _ in 0..arg {
                    let (key, tail) = Self::decode_at(rest, depth + 1)?;
                    let (value, tail) = Self::decode_at(tail, depth + 1)?;
                    entries.push((key, value));
                    rest = tail;
                }
                Some((Cbor::Map(entries), rest))
            }
            7 => Some((Cbor::Simple(u8::try_from(arg).ok()?), rest)),
            _ => None,
        }
    }
}

/// The additional-information values that say how many bytes of argument follow.
const FOLLOWS_1: u8 = 0x18;
const FOLLOWS_2: u8 = 0x19;
const FOLLOWS_4: u8 = 0x1A;
const FOLLOWS_8: u8 = 0x1B;

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let major = major << 5;
    if let Ok(small) = u8::try_from(arg)
        && small < FOLLOWS_1
    {
        out.push(major | small);
    } else if let Ok(byte) = u8::try_from(arg) {
        out.extend_from_slice(&[major | FOLLOWS_1, byte]);
    } else if let Ok(short) = u16::try_from(arg) {
        out.push(major | FOLLOWS_2);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(arg) {
        out.push(major | FOLLOWS_4);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(major | FOLLOWS_8);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_round_trips_what_ctap2_sends() {
        let v = Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Bytes(vec![7; 32])),
            (Cbor::Int(-3), Cbor::Int(-7)),
            (
                text("alg"),
                Cbor::Array(vec![Cbor::Int(300), Cbor::Simple(21)]),
            ),
        ]);
        let mut out = Vec::new();
        v.encode(&mut out);
        assert_eq!(
            out[..3],
            [0xA3, 0x01, 0x58],
            "a map of three, key 1, bytes(24..)"
        );
        assert_eq!(Cbor::decode(&out), Some((v, &[][..])));
    }

    #[test]
    fn a_credential_comes_out_of_authenticator_data() {
        let mut cose = Vec::new();
        Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Int(COSE_EC2)),
            (Cbor::Int(3), Cbor::Int(COSE_ES256)),
            (Cbor::Int(-1), Cbor::Int(COSE_P256)),
            (Cbor::Int(-2), Cbor::Bytes(vec![1; 32])),
            (Cbor::Int(-3), Cbor::Bytes(vec![2; 32])),
        ])
        .encode(&mut cose);
        let mut data = vec![0u8; 32];
        data.push(0x41); // UP and AT
        data.extend_from_slice(&[0, 0, 0, 1]);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&[9, 9, 9]);
        data.extend_from_slice(&cose);
        let c = attested(&data).expect("parses");
        assert_eq!(c.id, [9, 9, 9]);
        assert_eq!(c.public[..32], [1; 32]);
        assert_eq!(c.public[32..], [2; 32]);
        data[32] = 0x01;
        assert!(attested(&data).is_err(), "no AT flag, no key");
    }

    #[test]
    fn a_hostile_answer_nested_too_deep_is_refused() {
        let deep = [0x81u8; 64];
        assert_eq!(Cbor::decode(&deep), None);
    }

    #[test]
    fn a_new_fido_pin_is_padded_to_64_and_held_to_its_length() {
        let p = padded_pin("1234").expect("four is the shortest");
        assert_eq!(p.len(), 64, "padded to 64");
        assert_eq!(&p[..5], b"1234\0", "zeros after the PIN");
        assert!(padded_pin("123").is_err(), "three is too short");
        assert!(
            padded_pin(&"9".repeat(64)).is_err(),
            "64 leaves no zero to end it"
        );
    }

    #[test]
    fn aes_cbc_under_the_zero_iv_round_trips_whole_blocks() {
        let key = [7u8; 32];
        let data = [1u8; 32];
        let sealed = encrypt(&key, &data).expect("whole blocks");
        assert_ne!(sealed, data, "encrypted");
        assert_eq!(decrypt(&key, &sealed).expect("opens"), data, "back again");
        assert!(
            encrypt(&key, &[0u8; 15]).is_err(),
            "a partial block is refused"
        );
    }

    #[test]
    fn the_pin_auth_is_the_hmac_cut_to_16_bytes() {
        let full = <Hmac<Sha256> as KeyInit>::new_from_slice(b"k")
            .expect("any key")
            .chain_update(b"data")
            .finalize()
            .into_bytes();
        assert_eq!(authenticate(b"k", b"data").expect("hmac"), full[..16]);
        assert_eq!(pin_hash("1234").len(), 16, "the PIN hash is cut to 16 too");
    }
}
