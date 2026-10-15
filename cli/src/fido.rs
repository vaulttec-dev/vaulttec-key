//! The key's FIDO2 side, spoken directly: just enough CTAP2 over hidraw for `vkey auth`
//! to make a credential and try it. `pamu2fcfg` would do the first half, but the 1.1.0
//! that distributions ship insists on an attestation certificate, and this key attests
//! with the credential's own key, as `WebAuthn` allows (docs/roadmap.md, phase 6).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

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
/// COSE: EC2 keys, P-256, ES256.
const COSE_EC2: i64 = 2;
const COSE_P256: i64 = 1;
const COSE_ES256: i64 = -7;

/// A credential as `pam_u2f` stores it: its id, and the public key as x and y.
pub struct Credential {
    pub id: Vec<u8>,
    pub public: [u8; 64],
}

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

    /// A CTAP2 command and its answer, the status byte checked.
    fn cbor(&mut self, command: u8, request: &Cbor) -> Result<Cbor, Error> {
        let mut payload = vec![command];
        request.encode(&mut payload);
        let answer = self.transact(CMD_CBOR, &payload)?;
        let (&status, body) = answer
            .split_first()
            .ok_or_else(|| Error::Value("the key answered with nothing".into()))?;
        if status != 0 {
            return Err(Error::Value(ctap_error(status)));
        }
        Cbor::decode(body)
            .filter(|(_, rest)| rest.is_empty())
            .map(|(v, _)| v)
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
            while out.len() < total {
                let more = self.packet()?;
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

/// The hidraw node of a vkey board: the one whose HID id names a board's USB pair.
fn node() -> Result<PathBuf, Error> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/sys/class/hidraw")? {
        let entry = entry?;
        let uevent = fs::read_to_string(entry.path().join("device/uevent")).unwrap_or_default();
        let ours = BOARDS.iter().any(|b| {
            uevent.contains(&format!(
                "HID_ID=0003:0000{:04X}:0000{:04X}",
                b.usb_vid, b.usb_pid
            ))
        });
        if ours {
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
        0x36 => "the key's FIDO PIN is needed",
        _ => "the key refused the request",
    };
    format!("{why} (CTAP2 status {status:#04x})")
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
}
