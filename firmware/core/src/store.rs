//! Persistent state in raw flash, power-cut safe, no filesystem.
//!
//! The board says where (a [`Layout`]: three regions the bootloader will never touch);
//! this module says how:
//!
//!   attempts   one word per failed PIN, cleared 1->0 without an erase
//!   state A  \ salt, KDF cost, verifier and every item, packed, as ONE image,
//!   state B  / written alternately
//!
//! One image, because a PIN change re-seals every item under a new key: with the header
//! and the items in separate places, a power cut between the two writes would leave
//! items no PIN can open. Every image carries a magic, a sequence number and a CRC.
//! Readers take the valid copy with the higher sequence; writers overwrite the other.
//!
//! Items are **packed, not slotted**. A TOTP seed is twenty bytes and an SSH key is
//! three kilobytes; fixed slots would have to be as big as the biggest, and an `add`
//! rewrites the whole image - so fixed slots would make every write cost what the
//! largest item might have been. Packed, a write costs what the vault actually holds.
//!
//! An image never sits in RAM. What RAM keeps is an [`Index`] - name, category, offset
//! and length per item, ~10 KiB for 256 of them - and the bodies are streamed through
//! the caller's buffer, the way the CRC already was. That is what pays for items that
//! no longer fit in 256 bytes.
//!
//! The magic word is written **last**, after the items and the CRC: until it lands the
//! copy reads as blank, so a torn write is not a copy a reader must reason about.
//!
//! All access goes through the `NorFlash` traits on purpose: a "convenient" write that
//! does read-erase-rewrite of the sector would turn the attempt counter's "one word,
//! no erase" into "erase first" - and a power cut between that erase and the write
//! would hand every attempt back.

use crc::{CRC_32_ISO_HDLC, Crc};
use embedded_storage::nor_flash::NorFlash;
use zeroize::{Zeroize, Zeroizing};

use crate::item::ITEM_MAX;
use crate::oath::{NAME_MAX, Name, len_u8, len_u16};
use crate::vault::{Cost, KEY_LEN, OVERHEAD, SALT_LEN};

pub const MAX_ENTRIES: usize = 256;
pub const MAX_ATTEMPTS: u8 = 8;
/// Every region below is this many bytes; flash erases in these units.
pub const SECTOR: u32 = 4096;
/// One image copy. Two of these and the attempt counter are the whole store.
pub const STATE_SECTORS: u32 = 53;
/// A sealed item with room for the AEAD overhead: what the board's buffer holds.
pub const ITEM_BUF_LEN: usize = ITEM_MAX + OVERHEAD;
const _: () = assert!(
    ITEM_BUF_LEN.is_multiple_of(4),
    "item bodies are written in words"
);

/// Where the three regions live. Each must start on a sector boundary; `state_a` and
/// `state_b` are `STATE_SECTORS` long, `attempts` one sector.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub attempts: u32,
    pub state_a: u32,
    pub state_b: u32,
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
/// How much of an image a CRC pass reads per driver call.
const CRC_CHUNK: usize = 1024;
/// Bump the digit whenever the image layout changes, so an old image is refused
/// instead of misread.
const MAGIC: [u8; 4] = *b"VKS7";

/// Why the store could not do what was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// Flash holds something, but neither copy is an image this firmware understands.
    /// Nothing may be written over it without an explicit wipe.
    Corrupt,
    /// The image has no room for another item, or for one this big.
    Full,
    /// The flash driver refused a read, write or erase.
    Flash(E),
}

/// Salt, KDF cost, key binding and verifier: everything needed to check a PIN.
///
/// There is no env key any more. It existed because `.env` blobs lived in a region of
/// their own and were not re-sealed when the PIN changed; now they are items like any
/// other, sealed under the DEK and re-sealed with the rest.
#[derive(Clone, Copy)]
pub struct Header {
    pub salt: [u8; SALT_LEN],
    pub cost: Cost,
    /// Whether the keys were derived with a chip-only key mixed in.
    pub bound: bool,
    pub verifier: [u8; KEY_LEN],
}

impl Zeroize for Header {
    fn zeroize(&mut self) {
        self.salt.zeroize();
        self.verifier.zeroize();
    }
}

/// A name copied out of an index slot, for a caller who asked by position and not by
/// name: the index may be rebuilt by the time the caller looks.
#[derive(Clone, Copy)]
pub struct StoredName {
    bytes: [u8; NAME_MAX],
    len: u8,
}

impl StoredName {
    pub(crate) fn of(name: Name<'_>) -> Self {
        let name = name.as_bytes();
        let mut s = StoredName {
            bytes: [0; NAME_MAX],
            len: len_u8(name.len()),
        };
        s.bytes[..name.len()].copy_from_slice(name);
        s
    }

    #[must_use]
    pub fn get(&self) -> Name<'_> {
        Name::trusted(&self.bytes[..usize::from(self.len)])
    }
}

/// Where one item is in the image and what it is called. The body stays in flash.
#[derive(Clone, Copy)]
pub struct Slot {
    name: [u8; NAME_MAX],
    name_len: u8,
    /// [`crate::item::Category`] as a wire byte. The store does not interpret it: a
    /// category it cannot name is still an item it must keep and hand back.
    pub category: u8,
    /// Where the sealed body starts, from the top of the image.
    off: u32,
    len: u16,
}

impl Slot {
    const EMPTY: Slot = Slot {
        name: [0; NAME_MAX],
        name_len: 0,
        category: 0,
        off: 0,
        len: 0,
    };

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name_len == 0
    }

    #[must_use]
    pub fn name(&self) -> Name<'_> {
        Name::trusted(&self.name[..usize::from(self.name_len)])
    }

    /// The name's bytes as a copy, for a caller that must let go of the slot before
    /// using them - `save_keep` hands the store back to itself between the two.
    const fn name_bytes(&self) -> [u8; NAME_MAX] {
        self.name
    }

    #[must_use]
    pub const fn sealed_len(&self) -> usize {
        self.len as usize
    }

    /// How many bytes this item takes in the image, head and padding included.
    const fn packed(&self) -> usize {
        Image::item_len(self.name_len as usize, self.len as usize)
    }
}

/// What RAM knows about the image: the header, and where every item is.
pub struct Index {
    pub header: Option<Header>,
    slots: [Slot; MAX_ENTRIES],
    count: usize,
}

impl Index {
    #[must_use]
    pub const fn empty() -> Index {
        Index {
            header: None,
            slots: [Slot::EMPTY; MAX_ENTRIES],
            count: 0,
        }
    }

    #[must_use]
    pub fn find(&self, name: Name<'_>) -> Option<usize> {
        self.used_slots().position(|s| s.name() == name)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[must_use]
    pub fn get(&self, i: usize) -> Option<&Slot> {
        self.slots[..self.count].get(i)
    }

    /// The items, in the order the image holds them.
    pub fn used_slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots[..self.count].iter()
    }

    /// Whether one more item of this size would fit, counting the item it replaces -
    /// `replacing` - as room that comes back.
    #[must_use]
    pub fn room_for(&self, name: Name<'_>, sealed_len: usize, replacing: Option<usize>) -> bool {
        let freed = replacing.and_then(|i| self.get(i)).map_or(0, Slot::packed);
        if replacing.is_none() && self.count >= MAX_ENTRIES {
            return false;
        }
        let want = Image::item_len(name.as_bytes().len(), sealed_len);
        self.bytes_used() + want - freed + 4 <= (SECTOR * STATE_SECTORS) as usize
    }

    /// The image's length as the slots describe it, CRC excluded.
    fn bytes_used(&self) -> usize {
        Image::HEAD + self.used_slots().map(Slot::packed).sum::<usize>()
    }
}

/// Back to `Index::empty()`, in place: no header, no slots, nothing left behind.
impl Zeroize for Index {
    fn zeroize(&mut self) {
        for slot in &mut self.slots {
            *slot = Slot::EMPTY; // a store the table is read after: never elided
        }
        self.count = 0;
        if let Some(h) = self.header.as_mut() {
            h.zeroize();
        }
        self.header = None;
    }
}

impl Drop for Index {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The byte layout of an image, in one place so the reader and the writer cannot drift:
///
/// ```text
/// image := magic[4] | seq u32 | used u32 | pad u32 | header | item* | crc u32
/// header:= flags u8 | pad[3] | salt | m_kib u32 | t u32 | verifier
/// item  := name_len u8 | category u8 | sealed_len u16le | name | pad | sealed | pad
/// ```
///
/// The name is padded so a body always starts on a word: bodies are the big writes and
/// the flash driver only takes words. Flags: bit 0 = a PIN is set, bit 1 = chip-bound.
struct Image;

impl Image {
    const FLAG_PIN: u8 = 0x01;
    const FLAG_BOUND: u8 = 0x02;
    const H_FLAGS: usize = 0;
    const H_SALT: usize = 4;
    const H_M_KIB: usize = Self::H_SALT + SALT_LEN;
    const H_T: usize = Self::H_M_KIB + 4;
    const H_VERIFIER: usize = Self::H_T + 4;
    const HDR_BYTES: usize = Self::H_VERIFIER + KEY_LEN;
    /// Magic, sequence, length, padding and header: what a save writes before the
    /// first item.
    const HEAD: usize = 16 + Self::HDR_BYTES;
    /// An item's own head, before its name.
    const ITEM_HEAD: usize = 4;

    /// Where an item's body starts, measured from the item's own head.
    const fn body_at(name_len: usize) -> usize {
        (Self::ITEM_HEAD + name_len).next_multiple_of(4)
    }

    const fn item_len(name_len: usize, sealed_len: usize) -> usize {
        Self::body_at(name_len) + sealed_len.next_multiple_of(4)
    }
}

const _: () = assert!(
    Image::HEAD.is_multiple_of(4),
    "images are written in whole words, one piece at a time"
);
const _: () = assert!(
    Image::HEAD + Image::item_len(NAME_MAX, ITEM_BUF_LEN) + 4 <= (SECTOR * STATE_SECTORS) as usize,
    "one item of the largest size must fit an image"
);
const _: () = assert!(
    ITEM_BUF_LEN <= u16::MAX as usize,
    "an item's length is a u16 in the image"
);

/// An offset within a region, as a flash address needs it.
fn off32(off: usize) -> u32 {
    const _: () = assert!(
        (SECTOR * STATE_SECTORS) as usize <= u32::MAX as usize,
        "every offset into a region is cast to a flash address"
    );
    #[expect(clippy::cast_possible_truncation, reason = "asserted above")]
    {
        off as u32
    }
}

/// The newest copy: its sequence number, its address, and how long its image is.
type Newest = (u32, u32, u32);

/// A flash address `off` bytes into a region.
fn at(base: u32, off: usize) -> u32 {
    base + off32(off)
}

/// Sectors that hold `bytes`, never more than a copy has.
fn sectors_of(bytes: u32) -> u32 {
    bytes.div_ceil(SECTOR).min(STATE_SECTORS)
}

pub struct Store<F: NorFlash> {
    flash: F,
    at: Layout,
    /// The newest image copy - (sequence, address) - as of the last `load` or `save`,
    /// so a write need not re-check both copies' CRCs to find its target. Only *which*
    /// copy is newer is remembered, never what it holds; `wipe` forgets.
    current: Option<(u32, u32)>,
    /// An image being written. It is state rather than a borrow because a restore
    /// writes one item per host request: the session outlives the call that opened it,
    /// and a whole backup still lands as one image.
    saving: Option<Saving>,
}

/// One image being written. Items are appended in order; nothing is visible to a reader
/// until `save_finish` writes the magic word.
struct Saving {
    /// The copy being replaced, which `save_keep` copies out of.
    source: Option<u32>,
    target: u32,
    seq: u32,
    head: Zeroizing<[u8; Image::HEAD]>,
    /// Sectors the replaced image occupied, so a shorter one still erases its tail.
    stale: u32,
    at: usize,
    /// Sectors of the target erased so far.
    erased: u32,
    count: usize,
}

impl<F: NorFlash> Store<F> {
    /// Panics at boot on a flash whose geometry this layout does not fit: a wrong
    /// board definition must fail loudly, not corrupt silently.
    pub fn new(flash: F, at: Layout) -> Self {
        assert!(
            F::ERASE_SIZE == SECTOR as usize,
            "store expects 4 KiB sectors"
        );
        assert!(
            4_usize.is_multiple_of(F::WRITE_SIZE) && 4_usize.is_multiple_of(F::READ_SIZE),
            "store reads and writes in 4-byte words"
        );
        for region in [at.attempts, at.state_a, at.state_b] {
            assert!(
                region.is_multiple_of(SECTOR),
                "regions start on sector boundaries"
            );
        }
        Store {
            flash,
            at,
            current: None,
            saving: None,
        }
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), Error<F::Error>> {
        self.flash.read(addr, buf).map_err(Error::Flash)
    }

    fn erase(&mut self, from: u32, sectors: u32) -> Result<(), Error<F::Error>> {
        self.flash
            .erase(from, from + SECTOR * sectors)
            .map_err(Error::Flash)
    }

    /// Plain write: only clears bits, never erases. Callers erase first when they need
    /// to, and never when they must not.
    fn write(&mut self, addr: u32, buf: &[u8]) -> Result<(), Error<F::Error>> {
        self.flash.write(addr, buf).map_err(Error::Flash)
    }

    /// Bytes at `off` into a region, where the length need not be a whole word: the
    /// tail comes through a scratch word rather than past the end of `out`.
    fn read_unaligned(&mut self, addr: u32, out: &mut [u8]) -> Result<(), Error<F::Error>> {
        let len = out.len();
        let head = len - len % 4;
        self.read(addr, &mut out[..head])?;
        if head < len {
            let mut tail = [0u8; 4];
            self.read(at(addr, head), &mut tail)?;
            out[head..].copy_from_slice(&tail[..len - head]);
            tail.zeroize();
        }
        Ok(())
    }

    // --- A/B image -------------------------------------------------------------

    /// The head of one copy: (sequence, length), or None if it is blank or not an
    /// image this firmware wrote. No CRC - callers that need one check it themselves.
    fn image_head(&mut self, addr: u32) -> Result<Option<(u32, u32)>, Error<F::Error>> {
        let mut head = [0u8; 16];
        self.read(addr, &mut head)?;
        if head[..4] != MAGIC {
            return Ok(None);
        }
        let seq = u32::from_le_bytes(word(&head[4..8]));
        let used = u32::from_le_bytes(word(&head[8..12]));
        if (used as usize) < Image::HEAD + 4 || used > SECTOR * STATE_SECTORS {
            return Ok(None);
        }
        Ok(Some((seq, used)))
    }

    /// Checks one copy. Ok(Some((seq, used))) if its magic and CRC check out, Ok(None)
    /// if the copy is blank or was never finished, Err(Corrupt) if the magic is there
    /// and the CRC is not - flash that holds something this firmware cannot read.
    fn image_seq(&mut self, addr: u32) -> Result<Option<(u32, u32)>, Error<F::Error>> {
        let Some((seq, used)) = self.image_head(addr)? else {
            return Ok(None);
        };
        let end = used as usize - 4;
        let mut digest = CRC.digest();
        let mut chunk = [0u8; CRC_CHUNK];
        let mut off = 0;
        while off < end {
            let n = (end - off).min(chunk.len());
            self.read(at(addr, off), &mut chunk[..n])?;
            digest.update(&chunk[..n]);
            off += n;
        }
        chunk.zeroize(); // a chunk held the verifier
        let mut stored = [0u8; 4];
        self.read(at(addr, end), &mut stored)?;
        if digest.finalize() != u32::from_le_bytes(stored) {
            return Err(Error::Corrupt);
        }
        Ok(Some((seq, used)))
    }

    /// The newest valid copy: Ok(Some((seq, address, used))), Ok(None) when the flash
    /// is blank, Err when it holds something this firmware cannot read.
    fn newest(&mut self) -> Result<Option<Newest>, Error<F::Error>> {
        let (first, second) = (self.at.state_a, self.at.state_b);
        let read_first = self.image_seq(first);
        let read_second = self.image_seq(second);
        // One damaged copy next to one good one is the expected aftermath of a power
        // cut mid-write; the good one wins. Two damaged copies are not.
        match (read_first, read_second) {
            (Ok(Some((one, _))), Ok(Some((two, used)))) if two > one => {
                Ok(Some((two, second, used)))
            }
            (Ok(Some((one, used))), _) => Ok(Some((one, first, used))),
            (_, Ok(Some((two, used)))) => Ok(Some((two, second, used))),
            (Ok(None), Ok(None)) => Ok(None),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }

    /// Whether the newer-looking copy says a PIN is set - from its first twenty bytes,
    /// no CRC. For the status line, which is asked every second: a torn image answers
    /// wrong here for exactly as long as it takes the next real operation to `load` and
    /// refuse it properly. `Ok(false)` on a blank flash.
    pub fn has_pin(&mut self) -> Result<bool, Error<F::Error>> {
        let mut best: Option<(u32, bool)> = None;
        for addr in [self.at.state_a, self.at.state_b] {
            let mut head = [0u8; 20];
            self.read(addr, &mut head)?;
            if head[..4] != MAGIC {
                continue;
            }
            let seq = u32::from_le_bytes(word(&head[4..8]));
            if best.is_none_or(|(s, _)| seq > s) {
                best = Some((seq, head[16 + Image::H_FLAGS] & Image::FLAG_PIN != 0));
            }
        }
        Ok(best.is_some_and(|(_, pin)| pin))
    }

    /// A header with a cost this firmware will not run is as unusable as a bad CRC:
    /// refused, not rounded down.
    fn header_of(h: &[u8; Image::HDR_BYTES]) -> Result<Option<Header>, Error<F::Error>> {
        if h[Image::H_FLAGS] & Image::FLAG_PIN == 0 {
            return Ok(None);
        }
        let mut hdr = Header {
            salt: [0; SALT_LEN],
            cost: Cost::from_wire(
                u32::from_le_bytes(word(&h[Image::H_M_KIB..Image::H_T])),
                u32::from_le_bytes(word(&h[Image::H_T..Image::H_VERIFIER])),
            )
            .ok_or(Error::Corrupt)?,
            bound: h[Image::H_FLAGS] & Image::FLAG_BOUND != 0,
            verifier: [0; KEY_LEN],
        };
        hdr.salt.copy_from_slice(&h[Image::H_SALT..Image::H_M_KIB]);
        hdr.verifier
            .copy_from_slice(&h[Image::H_VERIFIER..Image::HDR_BYTES]);
        Ok(Some(hdr))
    }

    /// Loads the newest copy's header and item table into `out`; a blank flash leaves
    /// it empty. On any error `out` is empty too: half an index is not an index. The
    /// item bodies stay in flash - [`Store::read_item`] fetches one when it is needed.
    pub fn load(&mut self, out: &mut Index) -> Result<(), Error<F::Error>> {
        out.zeroize();
        let r = self.load_into(out);
        if r.is_err() {
            out.zeroize();
        }
        r
    }

    fn load_into(&mut self, out: &mut Index) -> Result<(), Error<F::Error>> {
        let newest = self.newest()?;
        self.current = newest.map(|(seq, addr, _)| (seq, addr));
        let Some((_, addr, used)) = newest else {
            return Ok(());
        };
        let mut hdr = [0u8; Image::HDR_BYTES];
        self.read(at(addr, 16), &mut hdr)?;
        let header = Self::header_of(&hdr);
        hdr.zeroize();
        out.header = header?;

        // The CRC already proved these are the bytes that were written, so an item head
        // that does not parse here is this firmware disagreeing with itself: refuse the
        // whole image rather than skip an item and later write the rest back without it.
        let mut off = Image::HEAD;
        let end = used as usize - 4;
        while off < end {
            let mut head = [0u8; Image::ITEM_HEAD];
            self.read(at(addr, off), &mut head)?;
            let name_len = usize::from(head[0]);
            let sealed_len = usize::from(u16::from_le_bytes([head[2], head[3]]));
            let packed = Image::item_len(name_len, sealed_len);
            if name_len == 0
                || name_len > NAME_MAX
                || sealed_len == 0
                || sealed_len > ITEM_BUF_LEN
                || off + packed > end
                || out.count == MAX_ENTRIES
            {
                return Err(Error::Corrupt);
            }
            let mut name = [0u8; NAME_MAX];
            self.read_unaligned(at(addr, off + Image::ITEM_HEAD), &mut name[..name_len])?;
            if Name::new(&name[..name_len]).is_none() {
                return Err(Error::Corrupt);
            }
            let slot = &mut out.slots[out.count];
            slot.name = name;
            slot.name_len = head[0];
            slot.category = head[1];
            slot.off = off32(off + Image::body_at(name_len));
            slot.len = len_u16(sealed_len);
            out.count += 1;
            off += packed;
        }
        Ok(())
    }

    /// The sealed body of one item into `buf`, and how many bytes it is.
    pub fn read_item(&mut self, slot: &Slot, buf: &mut [u8]) -> Result<usize, Error<F::Error>> {
        let (_, addr) = self.current.ok_or(Error::Corrupt)?;
        let len = slot.sealed_len();
        let out = buf.get_mut(..len).ok_or(Error::Corrupt)?;
        self.read_unaligned(addr + slot.off, out)?;
        Ok(len)
    }

    /// Begins rewriting the image into the copy that is not current. The old copy stays
    /// the one a reader finds until `save_finish` writes the magic word, so a power cut
    /// costs at most this write. Refuses to write over flash it cannot read: that needs
    /// an explicit wipe. An unfinished session is simply dropped - `save_begin` again,
    /// or a `load`, and the half-written copy stays magicless and therefore blank.
    pub fn save_begin(&mut self, header: Option<&Header>) -> Result<(), Error<F::Error>> {
        let current = match self.current {
            Some(c) => Some(c),
            None => self.newest()?.map(|(seq, addr, _)| (seq, addr)),
        };
        let (seq, current_addr) = current.unwrap_or((0, self.at.state_b));
        let target = if current_addr == self.at.state_a {
            self.at.state_b
        } else {
            self.at.state_a
        };
        // How much of the target the image being replaced occupied: what must be erased
        // even if the new image is shorter, so no tail of the old one stays readable.
        // Unreadable contents mean erasing the copy whole - it is not ours to trust.
        let stale = self
            .image_head(target)?
            .map_or(STATE_SECTORS, |(_, used)| sectors_of(used));
        let source = current.map(|(_, addr)| addr);
        self.current = None; // nothing is newest until this write is whole

        let mut head = Zeroizing::new([0u8; Image::HEAD]);
        head[..4].copy_from_slice(&MAGIC);
        head[4..8].copy_from_slice(&seq.wrapping_add(1).to_le_bytes());
        // The length goes in at `finish`, once the items are in.
        if let Some(hdr) = header {
            let h = &mut head[16..];
            h[Image::H_FLAGS] = Image::FLAG_PIN | if hdr.bound { Image::FLAG_BOUND } else { 0 };
            h[Image::H_SALT..Image::H_M_KIB].copy_from_slice(&hdr.salt);
            h[Image::H_M_KIB..Image::H_T].copy_from_slice(&hdr.cost.m_kib.to_le_bytes());
            h[Image::H_T..Image::H_VERIFIER].copy_from_slice(&hdr.cost.t.to_le_bytes());
            h[Image::H_VERIFIER..].copy_from_slice(&hdr.verifier);
        }
        self.saving = Some(Saving {
            source,
            target,
            seq: seq.wrapping_add(1),
            head,
            stale,
            at: Image::HEAD,
            erased: 0,
            count: 0,
        });
        self.room(0)
    }

    /// Whether an image is being written.
    #[must_use]
    pub const fn saving(&self) -> bool {
        self.saving.is_some()
    }

    /// Forgets a session without finishing it: the target copy has no magic word, so
    /// the copy being replaced is still the one a reader takes.
    pub fn save_abort(&mut self) {
        self.saving = None;
    }

    /// Erases far enough ahead to write `bytes` at the session's current offset.
    /// Sectors are erased as the image grows into them: a write costs the vault's
    /// size, not the region's.
    fn room(&mut self, bytes: usize) -> Result<(), Error<F::Error>> {
        let s = self.saving.as_ref().ok_or(Error::Corrupt)?;
        let (mut erased, target, end) = (s.erased, s.target, s.at + bytes + 4);
        if end > (SECTOR * STATE_SECTORS) as usize {
            return Err(Error::Full);
        }
        let want = sectors_of(off32(end));
        while erased < want {
            self.erase(target + erased * SECTOR, 1)?;
            erased += 1;
        }
        if let Some(s) = self.saving.as_mut() {
            s.erased = erased;
        }
        Ok(())
    }

    /// Appends an item to the session: its head and name in one word-aligned write,
    /// then its body.
    pub fn save_put(
        &mut self,
        name: Name<'_>,
        category: u8,
        sealed: &[u8],
    ) -> Result<(), Error<F::Error>> {
        let s = self.saving.as_ref().ok_or(Error::Corrupt)?;
        let name = name.as_bytes();
        if s.count == MAX_ENTRIES || sealed.is_empty() || sealed.len() > ITEM_BUF_LEN {
            return Err(Error::Full);
        }
        let body_at = Image::body_at(name.len());
        let packed = body_at + sealed.len().next_multiple_of(4);
        self.room(packed)?;
        let (target, off) = {
            let s = self.saving.as_ref().ok_or(Error::Corrupt)?;
            (s.target, s.at)
        };

        let mut head = Zeroizing::new([0u8; Image::body_at(NAME_MAX)]);
        head[0] = len_u8(name.len());
        head[1] = category;
        head[2..4].copy_from_slice(&len_u16(sealed.len()).to_le_bytes());
        head[Image::ITEM_HEAD..Image::ITEM_HEAD + name.len()].copy_from_slice(name);
        self.write(at(target, off), &head[..body_at])?;

        let whole = sealed.len() - sealed.len() % 4;
        self.write(at(target, off + body_at), &sealed[..whole])?;
        if whole < sealed.len() {
            let mut tail = Zeroizing::new([0u8; 4]);
            tail[..sealed.len() - whole].copy_from_slice(&sealed[whole..]);
            self.write(at(target, off + body_at + whole), &*tail)?;
        }
        if let Some(s) = self.saving.as_mut() {
            s.at += packed;
            s.count += 1;
        }
        Ok(())
    }

    /// One item of the copy being replaced, into `buf`: what a caller re-seals under a
    /// new PIN before putting it back.
    pub fn save_read(&mut self, slot: &Slot, buf: &mut [u8]) -> Result<usize, Error<F::Error>> {
        let addr = self
            .saving
            .as_ref()
            .and_then(|s| s.source)
            .ok_or(Error::Corrupt)?;
        let len = slot.sealed_len();
        let out = buf.get_mut(..len).ok_or(Error::Corrupt)?;
        self.read_unaligned(addr + slot.off, out)?;
        Ok(len)
    }

    /// An item carried over unchanged, through the caller's buffer.
    pub fn save_keep(&mut self, slot: &Slot, buf: &mut [u8]) -> Result<(), Error<F::Error>> {
        let n = self.save_read(slot, buf)?;
        let name = slot.name_bytes();
        let name = Name::trusted(&name[..usize::from(slot.name_len)]);
        self.save_put(name, slot.category, &buf[..n])
    }

    /// Writes the CRC and then the magic word, erases whatever the replaced image left
    /// beyond the new one, and loads `index` from what was written.
    pub fn save_finish(&mut self, index: &mut Index) -> Result<(), Error<F::Error>> {
        let Some(s) = self.saving.as_ref() else {
            return Err(Error::Corrupt);
        };
        let (target, body_end, seq, stale) = (s.target, s.at, s.seq, s.stale);
        let used = off32(body_end + 4);
        self.room(4)?;
        let mut head = self
            .saving
            .as_ref()
            .map(|s| s.head.clone())
            .ok_or(Error::Corrupt)?;
        head[8..12].copy_from_slice(&used.to_le_bytes());

        // The head is digested from RAM and the items from flash: what the CRC covers
        // is what actually landed, not what was meant to.
        let mut digest = CRC.digest();
        digest.update(&*head);
        let mut chunk = [0u8; CRC_CHUNK];
        let mut off = Image::HEAD;
        while off < body_end {
            let n = (body_end - off).min(chunk.len());
            self.read(at(target, off), &mut chunk[..n])?;
            digest.update(&chunk[..n]);
            off += n;
        }
        chunk.zeroize();
        self.write(at(target, body_end), &digest.finalize().to_le_bytes())?;

        // Last: with the magic in place the copy becomes the one a reader takes.
        self.write(target, &*head)?;

        let full = sectors_of(used);
        if stale > full {
            self.erase(target + full * SECTOR, stale - full)?;
        }
        self.saving = None;
        self.current = Some((seq, target));
        self.load(index)
    }

    // --- failed-attempt counter -------------------------------------------------

    /// Failed attempts since the last success: zeroed words at the start of the
    /// sector. A read error is an error, not zero attempts.
    pub fn attempts_used(&mut self) -> Result<u8, Error<F::Error>> {
        let mut words = [0u8; 4 * MAX_ATTEMPTS as usize];
        self.read(self.at.attempts, &mut words)?;
        let used = words.chunks(4).take_while(|w| *w != [0xFF; 4]).count();
        Ok(u8::try_from(used).unwrap_or(MAX_ATTEMPTS))
    }

    /// Spends one attempt: a single word goes 0xFFFFFFFF -> 0, no erase involved, so a
    /// power cut at any point cannot give the attempt back. Returns attempts used.
    pub fn spend_attempt(&mut self) -> Result<u8, Error<F::Error>> {
        let used = self.attempts_used()?;
        if used >= MAX_ATTEMPTS {
            return Ok(used);
        }
        self.write(self.at.attempts + u32::from(used) * 4, &[0, 0, 0, 0])?;
        Ok(used + 1)
    }

    pub fn reset_attempts(&mut self) -> Result<(), Error<F::Error>> {
        self.erase(self.at.attempts, 1)
    }

    /// Everything gone: both state copies and the attempt counter. Every region is
    /// tried even if one fails; the first failure is what comes back.
    pub fn wipe(&mut self) -> Result<(), Error<F::Error>> {
        self.current = None;
        let mut first = Ok(());
        for (from, sectors) in [
            (self.at.state_a, STATE_SECTORS),
            (self.at.state_b, STATE_SECTORS),
            (self.at.attempts, 1),
        ] {
            if let Err(e) = self.erase(from, sectors) {
                first = first.and(Err(e));
            }
        }
        first
    }
}

/// Four bytes as an array, for the little-endian reads above.
fn word(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}
