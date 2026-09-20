//! The item parser, against the bytes a hostile host may send. Everything downstream -
//! `device.rs` deciding what a tap releases - trusts what `Item::parse` returned, so
//! what matters here is that it returns nothing for anything it did not write itself.

use vaultkey_core::item::{
    Category, Class, FIELDS_MAX, Field, FieldKind, Item, LABEL_MAX, VALUE_MAX, Writer,
};

/// A buffer big enough for anything these tests pack.
fn buf() -> Vec<u8> {
    vec![0u8; 16384]
}

fn field<'a>(class: Class, label: &'a [u8], value: &'a [u8]) -> Field<'a> {
    Field::new(class, FieldKind::String, b"", label, value).expect("a valid field")
}

#[test]
fn what_was_written_is_what_comes_back() {
    let mut bytes = buf();
    let mut w = Writer::new(&mut bytes, Category::CreditCard).expect("room");
    assert!(
        w.push(
            &Field::new(
                Class::Open,
                FieldKind::String,
                b"Card Details",
                b"number",
                b"4111111111111111"
            )
            .expect("valid")
        )
    );
    assert!(
        w.push(
            &Field::new(
                Class::Secret,
                FieldKind::Concealed,
                b"Card Details",
                b"cvv",
                b"123"
            )
            .expect("valid")
        )
    );
    let n = w.finish();

    let item = Item::parse(&bytes[..n]).expect("parses");
    assert_eq!(item.category(), Category::CreditCard);
    assert_eq!(item.len(), 2);

    let fields: Vec<_> = item.fields().collect();
    assert_eq!(fields.len(), 2, "the iterator counts what was written");
    assert_eq!(fields[0].label(), b"number");
    assert_eq!(fields[0].section(), b"Card Details");
    assert_eq!(fields[0].class, Class::Open, "a card number needs no tap");
    assert_eq!(fields[1].value(), b"123");
    assert_eq!(fields[1].class, Class::Secret, "a CVV does");

    // The order is 1Password's, because an item put back together has to read like
    // the one that was taken apart.
    assert_eq!(
        item.fields()
            .map(|f| f.label().to_vec())
            .collect::<Vec<_>>(),
        vec![b"number".to_vec(), b"cvv".to_vec()]
    );
}

#[test]
fn the_class_is_found_without_the_host_naming_a_label() {
    let mut bytes = buf();
    let mut w = Writer::new(&mut bytes, Category::Login).expect("room");
    assert!(w.push(&field(Class::Open, b"username", b"me@example.com")));
    assert!(w.push(&field(Class::Secret, b"password", b"hunter2")));
    assert!(w.push(&field(
        Class::Seed,
        b"one-time password",
        b"JBSWY3DPEHPK3PXP"
    )));
    let n = w.finish();

    let item = Item::parse(&bytes[..n]).expect("parses");
    assert_eq!(
        item.first(Class::Secret).expect("a password").value(),
        b"hunter2"
    );
    assert_eq!(
        item.first(Class::Seed).expect("a seed").label(),
        b"one-time password"
    );
    assert!(
        Item::parse(&bytes[..n])
            .expect("parses")
            .first(Class::Open)
            .is_some()
    );
}

#[test]
fn nothing_the_writer_would_refuse_is_a_field() {
    assert!(
        Field::new(Class::Open, FieldKind::String, b"", b"", b"x").is_none(),
        "a field with no label cannot be asked for by name"
    );
    assert!(
        Field::new(Class::Open, FieldKind::String, b"", b"label", b"").is_none(),
        "an empty value is not a field, it is the absence of one"
    );
    assert!(
        Field::new(Class::Open, FieldKind::String, b"", b"a\nb", b"x").is_none(),
        "a newline in a label would break the list it is shown in"
    );
    assert!(
        Field::new(
            Class::Open,
            FieldKind::String,
            b"",
            &[b'x'; LABEL_MAX + 1],
            b"x"
        )
        .is_none(),
        "a label past LABEL_MAX"
    );
    assert!(
        Field::new(
            Class::Open,
            FieldKind::String,
            b"",
            b"key",
            &[b'x'; VALUE_MAX + 1]
        )
        .is_none(),
        "a value past VALUE_MAX"
    );
    // A value is any bytes at all: an SSH private key is not text.
    assert!(
        Field::new(
            Class::Secret,
            FieldKind::String,
            b"",
            b"key",
            &[0u8, 0xff, b'\n']
        )
        .is_some()
    );
}

#[test]
fn a_truncated_or_padded_item_is_not_an_item() {
    let mut bytes = buf();
    let mut w = Writer::new(&mut bytes, Category::Login).expect("room");
    assert!(w.push(&field(Class::Secret, b"password", b"hunter2")));
    let n = w.finish();
    assert!(Item::parse(&bytes[..n]).is_some(), "the whole of it parses");

    for cut in 1..n {
        assert!(
            Item::parse(&bytes[..cut]).is_none(),
            "an item cut at {cut} of {n} bytes must not parse"
        );
    }

    let mut padded = bytes[..n].to_vec();
    padded.push(0);
    assert!(
        Item::parse(&padded).is_none(),
        "bytes past the last field are not padding, they are a malformed item"
    );
}

#[test]
fn a_count_that_lies_is_refused() {
    let mut bytes = buf();
    let mut w = Writer::new(&mut bytes, Category::Login).expect("room");
    assert!(w.push(&field(Class::Secret, b"password", b"hunter2")));
    let n = w.finish();

    let mut more = bytes[..n].to_vec();
    more[1] = 2; // says two fields, carries one
    assert!(Item::parse(&more).is_none());

    let mut fewer = bytes[..n].to_vec();
    fewer[1] = 0; // says none, carries one
    assert!(Item::parse(&fewer).is_none());

    let mut far_too_many = bytes[..n].to_vec();
    far_too_many[1] = u8::try_from(FIELDS_MAX).expect("fits") + 1;
    assert!(Item::parse(&far_too_many).is_none());
}

#[test]
fn an_unknown_category_class_or_kind_is_refused() {
    let mut bytes = buf();
    let mut w = Writer::new(&mut bytes, Category::Login).expect("room");
    assert!(w.push(&field(Class::Secret, b"password", b"hunter2")));
    let n = w.finish();

    let mut bad_category = bytes[..n].to_vec();
    bad_category[0] = 250;
    assert!(
        Item::parse(&bad_category).is_none(),
        "a category the firmware does not know is not treated as some default"
    );

    let mut bad_class = bytes[..n].to_vec();
    bad_class[2] = 9;
    assert!(
        Item::parse(&bad_class).is_none(),
        "an unknown class must never fall through to Open"
    );

    let mut bad_kind = bytes[..n].to_vec();
    bad_kind[3] = 99;
    assert!(Item::parse(&bad_kind).is_none());
}

#[test]
fn the_writer_stops_rather_than_writing_less_than_it_was_asked_for() {
    let mut small = vec![0u8; 32];
    let mut w = Writer::new(&mut small, Category::Login).expect("room for an empty item");
    assert!(w.push(&field(Class::Open, b"username", b"me")));
    assert!(
        !w.push(&field(Class::Secret, b"password", &[b'x'; 64])),
        "a field that does not fit is refused, not truncated"
    );
    let n = w.finish();
    let item = Item::parse(&small[..n]).expect("what did fit is still a whole item");
    assert_eq!(item.len(), 1);

    let mut bytes = buf();
    let mut w = Writer::new(&mut bytes, Category::Identity).expect("room");
    for _ in 0..FIELDS_MAX {
        assert!(w.push(&field(Class::Open, b"field", b"value")));
    }
    assert!(
        !w.push(&field(Class::Open, b"one too many", b"value")),
        "FIELDS_MAX is a limit, not a suggestion"
    );
}

#[test]
fn an_empty_item_is_a_valid_item() {
    // The device stores one while a restore is filling it in.
    let mut bytes = buf();
    let w = Writer::new(&mut bytes, Category::Env).expect("room");
    let n = w.finish();
    let item = Item::parse(&bytes[..n]).expect("parses");
    assert!(item.is_empty());
    assert_eq!(item.fields().count(), 0);
    assert!(item.first(Class::Secret).is_none());
}

#[test]
fn an_item_with_corrupt_second_field_is_refused() {
    let mut bytes = buf();
    let mut w = Writer::new(&mut bytes, Category::Login).expect("room");
    let f1 = field(Class::Open, b"username", b"alice");
    let f2 = field(Class::Secret, b"password", b"hunter2");
    assert!(w.push(&f1));
    assert!(w.push(&f2));
    let n = w.finish();
    assert!(Item::parse(&bytes[..n]).is_some());

    let second_field_start = 2 + f1.packed_len();
    for cut in second_field_start..n {
        assert!(
            Item::parse(&bytes[..cut]).is_none(),
            "cut at {cut} inside second field must not parse"
        );
    }

    let mut bad_class = bytes[..n].to_vec();
    bad_class[second_field_start] = 99;
    assert!(
        Item::parse(&bad_class).is_none(),
        "invalid class in second field must not parse"
    );

    let mut bad_kind = bytes[..n].to_vec();
    bad_kind[second_field_start + 1] = 99;
    assert!(
        Item::parse(&bad_kind).is_none(),
        "invalid kind in second field must not parse"
    );
}
