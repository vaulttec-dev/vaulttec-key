//! An item as the host works with it: owned fields, and the packing the firmware reads.
//!
//! `vaultkey_core::item` is the shape on the wire and in flash - a view over bytes,
//! because the device has no allocator. This side does have one, so an item here is a
//! `Vec` of owned fields, packed only when it is about to be sent and unpacked as soon
//! as it arrives. Every value lives in memory that scrubs itself.
//!
//! The mapping to and from 1Password lives here too, in one function each way: a
//! field's `purpose` and `type` decide its class, and its class decides what the device
//! will ever hand back.

use vaultkey_core::item::{
    Category, Class, Field, FieldKind, ITEM_MAX, Item as Packed, LABEL_MAX, VALUE_MAX, Writer,
};
use zeroize::Zeroizing;

use crate::device::Error;

/// One field of an item, owned. `section` and `kind` are carried because the mirror
/// runs both ways: `op item create` takes the JSON `op item get` hands out, and a
/// field's section and type are what make it that field rather than a note about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedField {
    pub class: Class,
    pub kind: FieldKind,
    pub section: String,
    pub label: String,
    pub value: Zeroizing<Vec<u8>>,
}

impl OwnedField {
    /// A field with no section, which is where most fields live.
    #[must_use]
    pub fn new(class: Class, kind: FieldKind, label: &str, value: &[u8]) -> OwnedField {
        OwnedField {
            class,
            kind,
            section: String::new(),
            label: label.to_string(),
            value: Zeroizing::new(value.to_vec()),
        }
    }

    /// The value as text, for the fields that are text: a login, a URL, a note.
    #[must_use]
    pub fn text(&self) -> Zeroizing<String> {
        Zeroizing::new(String::from_utf8_lossy(&self.value).into_owned())
    }
}

/// An item: what it is, and what it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub category: Category,
    pub fields: Vec<OwnedField>,
}

impl Item {
    #[must_use]
    pub const fn new(category: Category) -> Item {
        Item {
            category,
            fields: Vec::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, field: OwnedField) -> Item {
        self.fields.push(field);
        self
    }

    /// The first field of a class - the password of a login, the seed of a TOTP entry -
    /// which is how the CLI asks without knowing what 1Password called it.
    #[must_use]
    pub fn first(&self, class: Class) -> Option<&OwnedField> {
        self.fields.iter().find(|f| f.class == class)
    }

    /// A field by label, case-insensitively: `username` and `Username` are one field.
    #[must_use]
    pub fn by_label(&self, label: &str) -> Option<&OwnedField> {
        self.fields
            .iter()
            .find(|f| f.label.eq_ignore_ascii_case(label))
    }

    /// The bytes the firmware stores, built by the firmware's own writer so the two
    /// cannot disagree about the layout.
    pub fn pack(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut buf = Zeroizing::new(vec![0u8; ITEM_MAX]);
        let mut w = Writer::new(&mut buf, self.category)
            .ok_or_else(|| Error::Value("the item buffer is too small".into()))?;
        for f in &self.fields {
            let field = Field::new(
                f.class,
                f.kind,
                f.section.as_bytes(),
                f.label.as_bytes(),
                &f.value,
            )
            .ok_or_else(|| {
                Error::Value(format!(
                    "field '{}': a label is 1..{LABEL_MAX} printable bytes and a value 1..{VALUE_MAX}",
                    f.label
                ))
            })?;
            if !w.push(&field) {
                return Err(Error::Value(format!(
                    "the item does not fit: {} is one field too many, or too big",
                    f.label
                )));
            }
        }
        let n = w.finish();
        let mut out = Zeroizing::new(buf[..n].to_vec());
        out.shrink_to_fit();
        Ok(out)
    }

    /// An item as the device sent it back.
    pub fn unpack(bytes: &[u8]) -> Result<Item, Error> {
        let packed = Packed::parse(bytes)
            .ok_or_else(|| Error::Value("the device sent a malformed item".into()))?;
        Ok(Item {
            category: packed.category(),
            fields: packed
                .fields()
                .map(|f| OwnedField {
                    class: f.class,
                    kind: f.kind,
                    section: String::from_utf8_lossy(f.section()).into_owned(),
                    label: String::from_utf8_lossy(f.label()).into_owned(),
                    value: Zeroizing::new(f.value().to_vec()),
                })
                .collect(),
        })
    }
}

/// What a category is called in English, for a list and for `op --category`.
#[must_use]
pub fn category_name(c: Category) -> &'static str {
    match c {
        Category::Login => "login",
        Category::CreditCard => "credit card",
        Category::SecureNote => "secure note",
        Category::Identity => "identity",
        Category::Password => "password",
        Category::Document => "document",
        Category::SoftwareLicense => "software license",
        Category::BankAccount => "bank account",
        Category::Database => "database",
        Category::DriverLicense => "driver license",
        Category::OutdoorLicense => "outdoor license",
        Category::Membership => "membership",
        Category::Passport => "passport",
        Category::RewardProgram => "reward program",
        Category::SocialSecurityNumber => "social security number",
        Category::WirelessRouter => "wireless router",
        Category::Server => "server",
        Category::EmailAccount => "email account",
        Category::ApiCredential => "api credential",
        Category::MedicalRecord => "medical record",
        Category::SshKey => "ssh key",
        Category::CryptoWallet => "crypto wallet",
        Category::Env => "env",
        Category::Auth => "auth",
    }
}

/// The class a 1Password field belongs in. The one place that decides, so a field that
/// hides a secret cannot become an open one by arriving through another code path.
///
/// A one-time password is a seed: the device computes codes from it and only the export
/// gesture lets the seed itself out. Anything concealed is a secret. Everything else is
/// open - a login, a URL, an account number are shown beside the name in any manager.
#[must_use]
pub const fn class_of(kind: FieldKind) -> Class {
    match kind {
        FieldKind::Otp => Class::Seed,
        FieldKind::Concealed => Class::Secret,
        FieldKind::String
        | FieldKind::Date
        | FieldKind::MonthYear
        | FieldKind::Menu
        | FieldKind::Url
        | FieldKind::Email
        | FieldKind::Phone
        | FieldKind::Address
        | FieldKind::Reference
        | FieldKind::File => Class::Open,
    }
}

/// A 1Password field type by the name its JSON uses.
#[must_use]
pub fn field_kind_of(text: &str) -> FieldKind {
    match text.to_ascii_uppercase().as_str() {
        "CONCEALED" => FieldKind::Concealed,
        "OTP" => FieldKind::Otp,
        "DATE" => FieldKind::Date,
        "MONTH_YEAR" => FieldKind::MonthYear,
        "MENU" => FieldKind::Menu,
        "URL" => FieldKind::Url,
        "EMAIL" => FieldKind::Email,
        "PHONE" => FieldKind::Phone,
        "ADDRESS" => FieldKind::Address,
        "REFERENCE" => FieldKind::Reference,
        "FILE" => FieldKind::File,
        // A type this CLI has not met is text until proven otherwise; `purpose` and the
        // concealed flag are what actually decide the class, and both are checked above.
        _ => FieldKind::String,
    }
}

/// The name 1Password's JSON uses for a field type, for an item written back.
#[must_use]
pub const fn field_kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::String => "STRING",
        FieldKind::Concealed => "CONCEALED",
        FieldKind::Otp => "OTP",
        FieldKind::Date => "DATE",
        FieldKind::MonthYear => "MONTH_YEAR",
        FieldKind::Menu => "MENU",
        FieldKind::Url => "URL",
        FieldKind::Email => "EMAIL",
        FieldKind::Phone => "PHONE",
        FieldKind::Address => "ADDRESS",
        FieldKind::Reference => "REFERENCE",
        FieldKind::File => "FILE",
    }
}

/// The 1Password category name (`op --category`) for an item written back. `Env` and
/// `Auth` have no category there: an `.env` goes back as a secure note, and an auth
/// seed never goes back at all.
#[must_use]
pub const fn op_category(c: Category) -> Option<&'static str> {
    Some(match c {
        Category::Login => "Login",
        Category::CreditCard => "Credit Card",
        Category::SecureNote | Category::Env => "Secure Note",
        Category::Identity => "Identity",
        Category::Password => "Password",
        Category::Document => "Document",
        Category::SoftwareLicense => "Software License",
        Category::BankAccount => "Bank Account",
        Category::Database => "Database",
        Category::DriverLicense => "Driver License",
        Category::OutdoorLicense => "Outdoor License",
        Category::Membership => "Membership",
        Category::Passport => "Passport",
        Category::RewardProgram => "Reward Program",
        Category::SocialSecurityNumber => "Social Security Number",
        Category::WirelessRouter => "Wireless Router",
        Category::Server => "Server",
        Category::EmailAccount => "Email Account",
        Category::ApiCredential => "API Credential",
        Category::MedicalRecord => "Medical Record",
        Category::SshKey => "SSH Key",
        Category::CryptoWallet => "Crypto Wallet",
        Category::Auth => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_item_survives_the_round_trip_through_the_firmware_layout() {
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
            ));
        let packed = item.pack().expect("packs");
        assert_eq!(Item::unpack(&packed).expect("unpacks"), item);
    }

    #[test]
    fn the_class_comes_from_the_field_type_and_nowhere_else() {
        assert_eq!(class_of(FieldKind::Otp), Class::Seed, "a seed is a seed");
        assert_eq!(class_of(FieldKind::Concealed), Class::Secret);
        assert_eq!(class_of(FieldKind::String), Class::Open);
        assert_eq!(
            class_of(field_kind_of("unheard-of")),
            Class::Open,
            "an unknown type is text, and text is open - it is `purpose` and the \
             concealed flag that make something a secret"
        );
    }

    #[test]
    fn an_item_too_big_for_the_device_is_refused_here() {
        let big = vec![b'x'; VALUE_MAX + 1];
        let item = Item::new(Category::SecureNote).with(OwnedField::new(
            Class::Secret,
            FieldKind::Concealed,
            "note",
            &big,
        ));
        assert!(
            item.pack().is_err(),
            "a field past VALUE_MAX is caught before the wire, not by the device"
        );
    }
}
