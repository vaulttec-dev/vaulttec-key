//! An item: a name, a category and a list of fields.
//!
//! What the key used to store was one secret under one kind, and the kind answered two
//! questions at once - what the thing is, and what may leave the device. A mirror of a
//! whole 1Password vault needs those apart: a credit card carries a number anyone with
//! the PIN may read and a CVV that needs a tap, in one item.
//!
//! So the **class** of a field, not the category of the item, decides what comes out.
//! A host that writes a seed as `Open` gains nothing - it holds that seed already; the
//! class guards the next read, not this write.
//!
//! An item is never a struct in RAM: at 32 fields of 4 KiB a struct would be 128 KiB,
//! and the chip has 512 KiB for everything. It lives packed in a buffer, and [`Item`]
//! is a view over those bytes - parsed once, at the edge, and trusted afterwards, the
//! way `Name` and `Entry` already are.

use zeroize::Zeroize;

use crate::oath::{len_u8, len_u16, printable, take_len_prefixed};

/// A field's section and label: what 1Password shows beside the value.
pub const LABEL_MAX: usize = 64;
/// The longest a single field may be. A project's `.env` is the reason it is this big:
/// it is one field, it used to have a region of its own with 8000 bytes in it, and
/// shrinking what the key can hold is not something a change of shape may do quietly.
pub const VALUE_MAX: usize = 8128;
/// Fields in one item. An Identity - the fattest 1Password category - has twenty.
pub const FIELDS_MAX: usize = 32;
/// A packed item, whole: the biggest field plus room for its head, its label and the
/// other fields beside it. The board's buffer holds one of these plus the AEAD
/// overhead, as it held one `.env` blob before.
pub const ITEM_MAX: usize = 8192;
const _: () = assert!(
    VALUE_MAX + 64 <= ITEM_MAX,
    "an item must hold the biggest field with its head and label"
);

/// What a field may do when the host asks for it. The one thing in this module that is
/// about security rather than shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    /// The PIN is enough: a login, a URL, an account number, an issuer.
    Open = 1,
    /// A tap: a password, a CVV, a private key, a note.
    Secret = 2,
    /// A tap yields a code computed from it; the seed itself only under the export
    /// gesture, which is the backup gesture - a secret leaving the key whole.
    Seed = 3,
}

impl Class {
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Open),
            2 => Some(Self::Secret),
            3 => Some(Self::Seed),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

/// The field type 1Password gives a field. Carried because the mirror runs both ways:
/// `op item create` takes the JSON `op item get` hands out, and a field's type is what
/// makes it that field rather than a note about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FieldKind {
    String = 1,
    Concealed = 2,
    Otp = 3,
    Date = 4,
    MonthYear = 5,
    Menu = 6,
    Url = 7,
    Email = 8,
    Phone = 9,
    Address = 10,
    Reference = 11,
    /// An attachment. The key holds the bytes of one, but 1Password will not take them
    /// back as an attachment: `op item create` reads a file from disk, not from stdin.
    File = 12,
}

impl FieldKind {
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::String),
            2 => Some(Self::Concealed),
            3 => Some(Self::Otp),
            4 => Some(Self::Date),
            5 => Some(Self::MonthYear),
            6 => Some(Self::Menu),
            7 => Some(Self::Url),
            8 => Some(Self::Email),
            9 => Some(Self::Phone),
            10 => Some(Self::Address),
            11 => Some(Self::Reference),
            12 => Some(Self::File),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

/// What kind of thing the item is. The numbers are 1Password's own template ids, so
/// there is no table to keep in step: `001` is a Login there and here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Category {
    Login = 1,
    CreditCard = 2,
    SecureNote = 3,
    Identity = 4,
    Password = 5,
    Document = 6,
    SoftwareLicense = 100,
    BankAccount = 101,
    Database = 102,
    DriverLicense = 103,
    OutdoorLicense = 104,
    Membership = 105,
    Passport = 106,
    RewardProgram = 107,
    SocialSecurityNumber = 108,
    WirelessRouter = 109,
    Server = 110,
    EmailAccount = 111,
    ApiCredential = 112,
    MedicalRecord = 113,
    SshKey = 114,
    CryptoWallet = 115,
    /// A project's `.env`, which 1Password has no category for.
    Env = 200,
    /// An Ed25519 seed for `vkey auth`. Sealed under the chip key, never the DEK, and
    /// the one category whose item the device refuses to hand back at all.
    Auth = 201,
}

impl Category {
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Login),
            2 => Some(Self::CreditCard),
            3 => Some(Self::SecureNote),
            4 => Some(Self::Identity),
            5 => Some(Self::Password),
            6 => Some(Self::Document),
            100 => Some(Self::SoftwareLicense),
            101 => Some(Self::BankAccount),
            102 => Some(Self::Database),
            103 => Some(Self::DriverLicense),
            104 => Some(Self::OutdoorLicense),
            105 => Some(Self::Membership),
            106 => Some(Self::Passport),
            107 => Some(Self::RewardProgram),
            108 => Some(Self::SocialSecurityNumber),
            109 => Some(Self::WirelessRouter),
            110 => Some(Self::Server),
            111 => Some(Self::EmailAccount),
            112 => Some(Self::ApiCredential),
            113 => Some(Self::MedicalRecord),
            114 => Some(Self::SshKey),
            115 => Some(Self::CryptoWallet),
            200 => Some(Self::Env),
            201 => Some(Self::Auth),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

/// One field of an item, pointing into the packed bytes it was parsed from.
#[derive(Clone, Copy, Debug)]
pub struct Field<'a> {
    pub class: Class,
    pub kind: FieldKind,
    section: &'a [u8],
    label: &'a [u8],
    value: &'a [u8],
}

impl<'a> Field<'a> {
    /// The section is empty for a field 1Password keeps outside one; the label never
    /// is. Both are printable, because they are shown in a list and typed at a prompt;
    /// the value is any bytes at all - a private key is not text.
    #[must_use]
    pub const fn new(
        class: Class,
        kind: FieldKind,
        section: &'a [u8],
        label: &'a [u8],
        value: &'a [u8],
    ) -> Option<Field<'a>> {
        if section.len() > LABEL_MAX || !printable(section) {
            return None;
        }
        if label.is_empty() || label.len() > LABEL_MAX || !printable(label) {
            return None;
        }
        if value.is_empty() || value.len() > VALUE_MAX {
            return None;
        }
        Some(Field {
            class,
            kind,
            section,
            label,
            value,
        })
    }

    #[must_use]
    pub const fn section(&self) -> &'a [u8] {
        self.section
    }

    #[must_use]
    pub const fn label(&self) -> &'a [u8] {
        self.label
    }

    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// What this field costs packed, so a writer can refuse before it starts.
    #[must_use]
    pub const fn packed_len(&self) -> usize {
        Packed::FIELD_HEAD + self.section.len() + self.label.len() + self.value.len()
    }
}

/// The byte layout, in one place so the reader and the writer cannot drift apart:
///
/// ```text
/// item  := category u8 | count u8 | field*
/// field := class u8 | kind u8 | section_len u8 | section
///                             | label_len u8   | label
///                             | value_len u16le| value
/// ```
struct Packed;

impl Packed {
    const HEAD: usize = 2;
    const FIELD_HEAD: usize = 2 + 1 + 1 + 2;
}

/// A packed item, checked once. Every accessor below may then trust the bytes.
#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
    category: Category,
    count: usize,
    fields: &'a [u8],
}

impl<'a> Item<'a> {
    /// None unless `bytes` is an item this module could have written: a known
    /// category, a field count that matches what follows, and every field valid.
    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Item<'a>> {
        let (head, fields) = bytes.split_at_checked(Packed::HEAD)?;
        let category = Category::from_wire(head[0])?;
        let count = usize::from(head[1]);
        if count > FIELDS_MAX {
            return None;
        }
        let item = Item {
            category,
            count,
            fields,
        };
        // Walking it now is what lets everything downstream skip the checking.
        let mut seen = 0;
        let mut rest = fields;
        while seen < count {
            let (_, tail) = Self::take_field(rest)?;
            rest = tail;
            seen += 1;
        }
        if !rest.is_empty() {
            return None;
        }
        Some(item)
    }

    #[must_use]
    pub const fn category(&self) -> Category {
        self.category
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The fields in the order they were written, which is the order 1Password gave
    /// them: an item put back together has to read like the one that was taken apart.
    #[must_use]
    pub const fn fields(&self) -> Fields<'a> {
        Fields {
            left: self.count,
            rest: self.fields,
        }
    }

    /// The first field of a class, which is how the device answers "the password of
    /// this item" without the host naming a label.
    #[must_use]
    pub fn first(&self, class: Class) -> Option<Field<'a>> {
        self.fields().find(|f| f.class == class)
    }

    /// One field and what follows it, or None if the bytes are not a field.
    fn take_field(p: &'a [u8]) -> Option<(Field<'a>, &'a [u8])> {
        let (head, rest) = p.split_at_checked(2)?;
        let class = Class::from_wire(head[0])?;
        let kind = FieldKind::from_wire(head[1])?;
        let (section, rest) = take_len_prefixed(rest)?;
        let (label, rest) = take_len_prefixed(rest)?;
        let (len, rest) = rest.split_at_checked(2)?;
        let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
        let (value, rest) = rest.split_at_checked(len)?;
        Some((Field::new(class, kind, section, label, value)?, rest))
    }
}

/// The fields of an [`Item`], in order.
#[derive(Clone, Debug)]
pub struct Fields<'a> {
    left: usize,
    rest: &'a [u8],
}

impl<'a> Iterator for Fields<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        if self.left == 0 {
            return None;
        }
        // `Item::parse` walked these bytes already: they are fields, all of them.
        let (field, rest) = Item::take_field(self.rest)?;
        self.rest = rest;
        self.left -= 1;
        Some(field)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for Fields<'_> {}

/// Packs fields into a caller's buffer. The buffer is the board's one big buffer, so
/// nothing here allocates and nothing here is copied twice.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
    count: usize,
}

impl<'a> Writer<'a> {
    /// None if the buffer could not hold even an empty item.
    #[must_use]
    pub fn new(buf: &'a mut [u8], category: Category) -> Option<Writer<'a>> {
        if buf.len() < Packed::HEAD {
            return None;
        }
        buf[0] = category.wire();
        buf[1] = 0;
        Some(Writer {
            buf,
            at: Packed::HEAD,
            count: 0,
        })
    }

    /// False if the item is full or the buffer is: the caller says so to the host
    /// rather than writing a shorter item than it was asked for.
    pub fn push(&mut self, f: &Field<'_>) -> bool {
        if self.count == FIELDS_MAX || self.at + f.packed_len() > self.buf.len() {
            return false;
        }
        let mut at = self.at;
        let mut put = |bytes: &[u8]| {
            self.buf[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&[f.class.wire(), f.kind.wire(), len_u8(f.section().len())]);
        put(f.section());
        put(&[len_u8(f.label().len())]);
        put(f.label());
        put(&len_u16(f.value().len()).to_le_bytes());
        put(f.value());
        self.at = at;
        self.count += 1;
        self.buf[1] = len_u8(self.count);
        true
    }

    /// How many bytes of the buffer the item takes.
    #[must_use]
    pub const fn finish(self) -> usize {
        self.at
    }
}

impl Zeroize for Writer<'_> {
    fn zeroize(&mut self) {
        self.buf.zeroize();
        self.at = Packed::HEAD;
        self.count = 0;
    }
}
