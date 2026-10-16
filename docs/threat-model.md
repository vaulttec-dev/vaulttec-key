# Threat model

What the key does and does not protect against, so nobody relies on a guarantee it does not
give. Revisited on every hardware or firmware change. Reporting: [`SECURITY.md`](../SECURITY.md).
The long version, with every measurement and date, is at commit `72172f3`.

## The device

A USB key running its own firmware (`firmware/core` plus a board folder). It holds TOTP
seeds, passwords, notes and `.env` files under AES-256-GCM, keyed from an 8-digit PIN that is
never stored. Secret fields need a button gesture; eight wrong PINs wipe the vault.
**Neither board is a secure element or a certified device.**

| | nRF52840 MDK Dongle (the key) | ESP32-C6-Zero (test board) |
|---|---|---|
| Chip key | none: the vault rests on the PIN and Argon2 alone | eFuse HMAC key (burned 2026-09-08), read-protected, no copy kept |
| Debug port | UICR `APPROTECT` written (2026-10-15) | JTAG off by eFuse |
| Boot | our UF2 bootloader fork runs only Ed25519-signed images, serves no flash back, writes only 0x1000..0x97000 | Secure Boot v2 (RSA-3072, 2026-09-09) |
| Flash copy | needs a voltage glitch at boot (revision 2 lacks the IN-133 fix) | download mode is open: anyone can erase or rewrite flash |
| Offline PIN search after a copy | all 10^8 PINs in ~28 core-hours (0.97 ms a guess at `t`=20) | impossible without the chip |
| Passkeys | yes (FIDO2) | never: its USB is a fixed Serial/JTAG, no HID |

Phases 3-5 of [`roadmap.md`](roadmap.md) were the conditions for real secrets on the nRF;
they are met. **Accepted, not fixed** (maintainer, 2026-10-13): someone who takes the nRF and
has glitching gear reads the flash, takes the passkeys at once and the PIN in hours. A chip
key would fall to the same glitch, so there is none (phase 5). A revision-3 chip would
change that answer.

Flash Encryption on the C6 is not used: the vault is already AEAD under the eFuse HMAC, it
is written as raw words through `esp-storage`, which FE does not support, and FE would hide
only open-source code.

## Key derivation

```
pre      = Argon2id(PIN, salt; 128 KiB, t = board KDF_COST: 20 nRF, 48 C6)
KEK      = DeviceKey::mac(pre)        eFuse HMAC on the C6, Unbound on the nRF
DEK      = HMAC(KEK, "vaultkey/dek/v1")
verifier = HMAC(KEK, "vaultkey/verify/v1")
item     = AES-256-GCM(DEK), AAD = name + category
backup   = Argon2id(passphrase, fresh salt), no chip key
```

Only salt, cost and sealed items live in flash; everything derived lives in RAM while
unlocked and is zeroized on lock.

| Choice | Reason |
|---|---|
| Argon2id, 128 KiB on the stack | All the RAM there is beside the vault and passkeys. It buys time, not memory bandwidth: against a stolen `.vkb` it is the whole defence, hence the passphrase rule |
| `t` in the header, bounded | A forged header cannot park the key for hours |
| Not `scrypt`, not `balloon-hash` | `scrypt` needs `alloc`; `balloon-hash` doubles the crypto crates |
| PIN exactly 8 digits | On the C6 the counter can be erased through download mode and the PIN guessed through the real firmware at ~1.3 s a try: 6 digits ~15 days, 7 ~5 months, 8 ~4 years. Length is the only lever; a slower KDF slows every honest unlock. A wrong-length PIN is refused before the wire and costs no attempt |
| The header records the binding and cost | Firmware that would derive differently answers `Incompatible` instead of burning attempts |
| Category in the AAD | It sits in flash as plaintext; a rewritten category byte makes the item open for nobody |
| The attempt is spent before the check | Cutting power mid-check buys no free attempt |

## Gestures and field classes

| Gesture | LED | Releases |
|---|---|---|
| Tap | amber | a code, an item's secret fields, a `.env`, a passkey, a `vkey auth` login, a signed commit |
| Hold 5 s | red | wipe; a restore from a `.vkb`; on the nRF erasing every passkey |
| Double tap | blue | a backup; an export or seed readout |

A tap never wipes or exports, a hold never exports, a double tap never wipes: a hostile host
cannot swap a code request for a wipe or an export. A password is on the same tap as a code
(2026-09-08, not coming back): a host asking for one while the owner expects a code gets
it, but only by name, only unlocked, one per press. Confirmation is a fresh press with a
release after the request.

The **field's class**, not the item's category, decides what may leave:

| Class | Leaves | Gesture |
|---|---|---|
| `Open` | the value: login, URL, account number | PIN only |
| `Secret` | the value: password, CVV, note, private key, `.env` | tap |
| `Seed` | a code on a tap; the seed only on export | tap / double tap |

The host names a reach per request and gets only those fields; an unknown reach is refused.
A host writing a seed as `Open` gains nothing: it already holds it.

**A seed can leave in the clear** (maintainer, 2026-09-19): `vkey export` writes an item
back into 1Password through `op item create`, which takes a plaintext `otpauth://` URI.
After an export the seed is as safe as 1Password and the host, not this device. The double
tap keeps it from happening behind the owner's back; it does not make it safe.

## Backup and restore

`vkey backup` reseals every item on the device under a passphrase key (Argon2id, no chip
key, so the file opens on another board) and the host only assembles ciphertext into a
`.vkb`. Each item's AAD is `BACKUP_AAD` plus its index: a reordered or altered item does not
open; a truncated file restores what it holds and says so.

- With the passphrase, the file is every secret. Twelve characters is the floor the frame
  enforces; the CLI asks for five or six random words, never an invented phrase.
- On the nRF the file also carries Trussed's sectors: every passkey, the key wrapping
  non-resident credentials (`vkey auth`, commit signing), the signature counters. Restored
  onto another nRF52840 they make a clone that answers every site and this host's `sudo`.
  A deliberate break from FIDO's no-export rule (maintainer, 2026-10-15).
- Restore replaces the vault and passkeys under the PIN and the 5 s hold, so a host that
  knows the PIN cannot swap in its own. `restore --only`, `add` and `rm` stay PIN-only, so
  such a host can still delete items one by one, never the passkeys.
- An older backup winds signature counters back; a site may take the key for a clone.
- A restore cut short leaves Trussed's region torn: it is formatted on the next start
  (the `sudo` credential with it) until the restore runs again.

Rejected: a raw flash image as backup (8 digits fall offline, and it is bound to the chip).

## Passkeys (nRF only)

Trussed and `fido-authenticator` keep them in their own littlefs at 0xC8000..0xF4000.

- **Not sealed under the PIN.** Private keys and the credential-wrapping key sit as they are;
  a flash copy yields them in minutes. Blocks of the pre-2026-10-16 filesystem
  (0xD8000..0xEC000) stay readable in a dump until littlefs reuses them.
- **A tap is enough, locked or not.** The FIDO PIN gates what a site asks it to gate and
  encrypts nothing. It is stored as the first 16 bytes of its SHA-256, so a flash copy finds
  an 8-digit FIDO PIN in under a second; that is why it is separate from vkey's PIN
  (maintainer, 2026-10-16). Eight wrong FIDO PINs block FIDO until a reset.
- **Nothing leaves over USB**: no CTAP command returns a private key. U2F (CTAP1) is not
  served: its 250 ms presence poll cannot wait for a fresh tap.
- **authenticatorReset** needs the 5 s hold within 10 s of plugging in. The vault's wipe does
  not touch passkeys.
- **Origin binding** stops phishing for passkeys only; TOTP and passwords stay phishable.
- With the FIDO PIN, malware can list and erase passkeys: denial of service, not a sign-in.

Rejected: one PIN for vkey and FIDO; the firmware reading fido-authenticator's files to list
passkeys under vkey's PIN (a second path around the authenticator, more code on the key).

### `vkey auth` — sudo and the lock screen with a tap, through `pam_u2f`

`sudo vkey auth enable` makes a non-resident credential for `pam://<host>` (a tap), tries it
(another tap), writes its public half to root's `/etc/u2f_mappings` and one
`auth sufficient pam_u2f.so` line into each PAM service it knows, keeping `*.before-vkey`.
It speaks CTAP2 itself because `pamu2fcfg` 1.1.0 refuses a self-attesting key. The password
stays a way in.

| | |
|---|---|
| Laptop and key stolen together | The lock screen opens with a tap. Disk encryption protects a powered-off laptop, not this. Do not leave the key in the port |
| Someone at the unlocked laptop, key in | Root with one tap |
| Malware as the user | Can start `sudo` and wait for a reflex tap (same amber as a code). Can also put its own `sudo` first in PATH and catch the password; nothing the user runs can stop that |
| Malware rewriting `vkey` | `enable`/`disable` refuse to run as root from a binary anyone but root can change and name `/usr/local/sbin/vkey`; `/settings` keeps that copy current |
| Another FIDO key already mapped | Refused when the user's line holds more than one credential. A single hand-mapped key is taken for vkey's and replaced |
| Flash copy or `.vkb` with passphrase | Answers this host's logins |
| Nobody taps | The password prompt comes after 30 s |
| COSMIC greeter | Shares `cosmic-greeter`, so a tap may log in there; the keyring then stays locked |

The scheme before (Ed25519 under the chip key, command `Respond` 0x19, category 201) was
removed 2026-10-15, restorable from `4bd49f3`; both numbers stay unused. An old `.vkb` may
hold its item; a restore leaves it in the file. Rejected: USB presence as proof, PIN plus
tap, rotating HMAC challenge-response, a PAM `cdylib`, a scheme of our own beside `pam_u2f`.

### Git commits signed with a tap

`vkey commits enable` makes an `ecdsa-sk` key on the nRF, keeps its handle in
`~/.config/vkey/commit-signing-key` and points git's global signing at it; it refuses to
overwrite another signing setup. `disable` unsets only `commit.gpgsign`.

| | |
|---|---|
| A signature proves | Someone touched this key while a process with the handle asked. Not who, not what: the tap does not show the commit |
| Malware as the user | Can sign anything and wait for a reflex tap |
| Key and laptop stolen | Sign as the user until the key is removed from GitHub |
| The handle file | Useless without the key; not in the `.vkb` |
| Flash copy or `.vkb` | With the handle file, another board signs too |
| authenticatorReset | Ends the key unless restored from a `.vkb` at the current layout (44 sectors) |

## What it protects against

| Threat | Verdict |
|---|---|
| Malware copying the secret database | Yes, unless the owner exports: one item per press, never in bulk |
| Silent background codes | Yes: a held or taped-down button does not count |
| A wipe disguised as a code request | Yes: different gesture and LED |
| A password request disguised as a code request | No, same tap by design |
| A thief using the protocol | Yes: PIN, attempt counter, wipe |

## What it does not protect against

| Threat | Why not |
|---|---|
| Phishing of TOTP and passwords | A property of TOTP; only passkeys are origin-bound |
| The value you just received | It crosses USB, the terminal, optionally the clipboard |
| A host fully compromised at the moment of use | It waits for your press; there is no display to show what you confirm |
| A breach at the service | TOTP is a shared secret |
| Physical attack with equipment | See the board table; both chips can be glitched (ESP32: Espressif AR2023-007) |
| A state actor, supply chain | Out of reach of a small project |

Where secrets leak on the host:

- **Clipboard.** A copied password is cleared after 30 s, but a clipboard manager (GPaste,
  Klipper, CopyQ, Windows history) has already stored it, usually on disk. The clear empties
  whatever is there 30 s later, and it does not run if the terminal closes or the graphical
  session ends first.
- **Scrollback.** A revealed value stays in the terminal, `tmux` buffer or session log until
  closed.
- **`.env`.** `vkey get app > .env` puts it back on disk; run `env $(vkey get app) cmd`
  instead. A pasted `.env` went through the clipboard, which the CLI does not clear.
- **CSV import.** The export is plaintext on disk before and after; the CLI does not delete
  it. Export to `/dev/shm`. `vkey op` needs no file.
- **Recovery codes** on the key are a copy, not a backup: keep them on paper.

**Sync deletes.** A 1Password or CSV sync removes entries its source no longer offers,
without asking. It reaches only names that source owns (`~/.config/vaultkey/sources.json`,
0600, which names entries in the clear). A hand-added entry under a name the source also
offers becomes the source's. No deletion on `--tag`, `--vault`, a single item, a failed or
empty listing, an unknown account or file, or a lost map. Rejected: the source as a flash
byte (outside the AEAD tag, so flippable).

## Known limitations

1. **Not a secure element** on either board (above).
2. **C6 download mode stays open on purpose**: no other update path. The PIN costs ~4 years
   through the firmware with the counter erased.
3. **Signing keys are part of the model.** The C6's Secure Boot key (`vkey-signing`) and the
   fork's key (`vkey-signing-nrf`, fingerprint `a1700ebd539b0bfc`) both live on the nRF, each
   with a `.vkb` copy. Losing the C6 key freezes its firmware; leaking either lets the holder
   sign firmware the board runs. The fork moves to a new key only through an update signed
   with the old one. For 1 h 17 min on 2026-10-14 the fork's key sat on a board that served
   its flash.
4. **C6: 4 KiB at 0x3F000..0x40000 is not covered by the signature** (espflash has no
   `--secure-pad-v2`). Nothing maps it; it matters only with another bug. Padding the `.bin`
   afterwards breaks boot; the fix is `esptool elf2image --secure-pad-v2`, tested on a board.
5. **No FIDO certification.** The AAGUID is fido-authenticator's placeholder.
6. **No display.**
7. **No recovery** beyond the `.vkb`. Keep the services' own second way in.
8. **RUSTSEC-2026-0344 is ignored** (`ruzstd` via `espflash`; vkey never parses an ELF). It
   goes when `ruzstd` ≥ 0.9.1 arrives or `espflash` leaves the CLI.
9. **A signed nRF image can be downgraded** to an older signed one.

## Honest comparison

| | This key | Phone app | YubiKey 5 |
|---|---|---|---|
| Seed leaves in the clear | only on an explicit export | cloud backup, export | no |
| Press per code | yes | no | yes |
| PIN with wipe | 8 digits, Argon2id | phone passcode | OATH password |
| Passwords, `.env` | yes | separate app | no |
| Physical attack | glitchable, see above | no protection | secure element, not absolute (EUCLEAK, 2024) |
| Passkeys | nRF only | yes | yes |
| Open, reflashable | yes | no | no |

## Marketing wording rules

Breaking these rules is, by our own definition, project failure.

**Must not be written:**

- "phishing-proof" / "protects against phishing" — TOTP does not do this
- "safer than YubiKey"
- "military grade", "unbreakable", "hardware-grade security"
- "certified", "FIDO compliant"
- "qualified electronic signature carrier"

**Can be written:**

- "a secret leaves in the clear only on an explicit double tap; the backup is a file
  encrypted on the key itself, no cloud"
- "every code needs a physical button"
- "an open key you can audit and reflash yourself"
- "not a secure element — the threat model is in the documentation", linking here

## Sources

- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) · [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226)
- [ESP32-C3/C6 fault injection — Courk](https://courk.cc/esp32-c3-c6-fault-injection) · [Espressif AR2023-007](https://www.espressif.com/en/news/ESP32_FIA_Analysis)
- [EUCLEAK — NinjaLab](https://ninjalab.io/wp-content/uploads/2024/09/20240903_eucleak.pdf)
- [Nordic IN-133](https://infocenter.nordicsemi.com/pdf/in_133_v1.0.pdf) · [IN-141](https://infocenter.nordicsemi.com/pdf/in_141_v1.1.pdf)
