# Items: a record of fields

Decision of 2026-09-19: the key mirrors a 1Password vault whole, all 22 categories, and can
write an item back through `op`. The design notes and migration plan are
`git show 72172f3:docs/items-v2.md`.

```
Item  { name, category, fields: [Field] }      up to 32 fields, ITEM_MAX 8192 B packed
Field { class, kind, section, label, value }   value up to VALUE_MAX 8056 B
```

- **The class decides what leaves**, not the category: `Open` on the PIN, `Secret` on a
  tap, `Seed` a code on a tap and the seed only on the double tap. The one `match` on class
  is in `device.rs`.
- `section` and `kind` are 1Password's and are kept so an item written back is the item
  that was read; `concealed` maps to `Secret`, `otp` to `Seed`, the rest to `Open`.
- The image is packed (`name_len | category | sealed_len | name | sealed`), not slotted: a
  write costs the vault's size, not its maximum. RAM holds an index, never the image.
- A `.env` is an `Env` item with one secret field; no separate region.

Not mirrored: Document items (a file; the key is no file store). Their sync was removed
2026-10-15, restorable from `7c50caf`.
