# Items: a record of fields, not a record of one secret

Decision of 2026-09-19. The key mirrors a 1Password vault whole - every category, every
field - and can write an entry back into 1Password through `op`. That does not fit the
shape the store has today, so this is what replaces it and why.

What the maintainer chose, and what this document then has to answer for:

- **All 22 categories**, not only the ones that hold a password. A passport and a credit
  card go on the key too.
- **A TOTP seed may leave the device in the clear**, under a gesture of its own, so an
  entry can be written back into 1Password complete. `threat-model.md` loses the claim
  that a seed never leaves; the claim it keeps is narrower and is spelled out there.

---

## Why the present shape cannot carry it

| | Today | What a full mirror needs |
|---|---|---|
| Secret per entry | `SECRET_MAX` 256 B | An Identity or a Credit Card is 15-20 fields, 600-1200 B |
| Slot in flash | `Record::SIZE` 324 B, fixed | Variable: a TOTP seed is 20 B, an SSH key is 3 KB |
| Entries | 256 fixed slots, 83 KB image | The same 66 items would take ~70 KB packed |
| Room for the image | `state_a`..`state_b` = 86 KB, 3 KB spare | - |
| Image in RAM | `State` is 83 KB of the ~512 KB SRAM | A bigger fixed table does not fit beside 128 KB of Argon2 |
| `.env` blobs | 16 slots of their own region, 256 KB | One more kind of item, not a region |

A bigger `SECRET_MAX` is not the answer: the whole image is rewritten on every `add`,
and 512-byte slots were measured at 1.7 s per write. The fix is to stop paying for
slots that are not used.

## The model

An item is a name, a category and a list of fields. A field carries its own class, and
**the class - not the category - decides what may leave the device**:

```
Item { name: Name, category: Category, fields: [Field] }
Field { section: Label, label: Label, kind: FieldKind, class: Class, value: [u8] }

Class::Open    the PIN is enough           login, URL, account number, issuer
Class::Secret  a tap                       password, CVV, private key, note
Class::Seed    a tap yields a CODE;        TOTP seed
               the seed itself only under
               the export gesture
```

`section` and `kind` are carried because the mirror runs both ways. `op item create`
takes the same item JSON that `op item get` hands out, so an item written back is the
item that was read - but only if what 1Password used to shape it survived the trip:
fields live in sections, and a field's own type (`string`, `concealed`, `otp`, `date`,
`menu`) is what makes it that field rather than a note about it. Dropping them would
turn every exported item flat.

`class` is ours and `kind` is theirs: `concealed` and `otp` map onto `Secret` and
`Seed`, everything else onto `Open`, and the mapping lives in one function.

This keeps the property the device has always had - the host asks, the device decides -
while ending the rule that one entry means one secret. `Kind` today answers two
questions at once ("what is this" and "what may come out"); splitting them is what lets
a Credit Card carry an open number and a concealed CVV in one item.

The single `match` on class stays in `device.rs`, where the single `match` on kind is.

A host that writes a seed with `Class::Open` gains nothing: it already holds the seed it
is writing. The class protects a later read, not the write.

## The store

One image replaces the table and the env region both:

```
header | item | item | ... | end marker | CRC
item  := len u16 | name | category | field count | sealed fields
```

- **Packed, not slotted.** An item costs what it holds.
- **Only the used sectors are written.** 66 items of ~1 KB is 17 sectors, ~0.8 s - less
  than today's fixed 21 sectors, and it grows with the vault rather than with its
  maximum.
- **A/B copies, sequence and CRC are unchanged**: a PIN change still re-seals everything
  in one atomic write, and that is why the header and the items stay one image.
- **RAM holds an index, not the image**: name, category, offset, length - 256 items is
  ~10 KB against today's 83 KB. The body is streamed through the existing 8 KB buffer,
  the way the CRC is streamed today.

The freed 73 KB of RAM is what pays for items that no longer fit in 256 bytes.

Region sizes come from the board's `Layout` as they do now; the env region is folded
into the image, which gives two copies of ~217 KB.

## The protocol

An item can be several kilobytes, so the commands that carry one are streamed, exactly
as `ExportBegin`/`ExportNext` already are:

```
ItemGet    name          -> field count, then ItemNext per field, classes obeyed
ItemPut    name          -> ItemField per field, then ItemEnd; written as one image
```

`List` keeps returning name and category only - it is the shell's tick, and it must stay
one frame.

## Gestures

Unchanged, plus one:

| Gesture | What it releases |
|---|---|
| tap (amber) | `Open` and `Secret` fields; a code from a `Seed` field |
| double tap (blue) | backup, and now **export**: `Seed` fields in the clear |
| hold 5 s (red) | wipe |

Export is not a new gesture but the backup one, because it is the same act: the whole of
a secret leaving the key. A tap never exports a seed.

## Migration

The flash format changes, so a key holding secrets cannot be updated in place:

1. `vkey backup` with the **old** firmware - the file is in the old format.
2. Flash the new firmware; the key comes up with no PIN and no entries.
3. `vkey restore` reads an old-format `.vkb` and writes items in the new one: a TOTP
   entry becomes one `Seed` field, a password entry becomes `login` (Open), `password`
   (Secret), `note` (Secret), an `.env` blob becomes one `Secret` field.

`restore` keeps reading old backups after this: a backup is the only copy of a key that
has been wiped.

## Order of work

Each step leaves a key that works.

1. **Core model and store** - `Field`, `Class`, `Category`, packed image, index in RAM,
   old-format restore. The protocol keeps its current shape where it can.
2. **Streamed item commands** - `ItemGet`/`ItemPut`, and `device.rs` deciding by class.
3. **CLI** - the shell shows and edits fields; the table gets a column that says how many
   fields an item has.
4. **Import** - all 22 categories out of 1Password, every field kept with its label and
   class; `op`'s own `purpose`/`type` map onto `Class`.
5. **Export** - `vkey export op [name]` through `op item create`/`op item edit`, under the
   double tap for anything with a `Seed` field. The item is rebuilt as the JSON `op`
   hands out and piped back in; a `.env` goes back as a Secure Note, not a Document,
   because a note is text and stays editable.

## What does not come back

Attachments. `op item create` takes a file only as a path on disk (`Name[file]=...`),
and the key is not a file store: a Document item's bytes can be held, but 1Password
will not take them back as that item's attachment. Items that are only an attachment -
the maintainer's three signing-key documents - are named in the import summary and left
where they are.

## What this costs, honestly

- ~3-4k lines of the 12.5k in the repo are touched.
- The key must be wiped and restored once.
- `threat-model.md` loses a claim it has made since the start. A key that can write its
  secrets back into a cloud manager is a key whose secrets are only as safe as that
  manager - the hardware no longer bounds them. That is the maintainer's decision of
  2026-09-19, made with the trade-off named.
