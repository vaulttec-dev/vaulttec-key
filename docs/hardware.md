# Waveshare ESP32-C6-Zero (test board)

The test board, not a fallback (2026-10-14): no feature is built for it, it takes
`check --wipe-everything` for core changes. Everything here was measured on the board.
The long version, with the full Secure Boot burn procedure, is
`git show 72172f3:docs/hardware.md`.

## The board

| | |
|---|---|
| Chip | ESP32-C6FH4 rev v0.1, RISC-V 160 MHz, 4 MB flash |
| USB | fixed Serial/JTAG, `303a:1001`, `/dev/ttyACM*`; carries both the protocol and logs, hence the `VTC2` magic |
| Button | GPIO9, active low, label `BOOT` |
| LED | WS2812 on GPIO8, channel order **RGB** (`color_order::Rgb`) |
| USB D−/D+ | GPIO12/13: never reconfigure, the port disappears |

**No HID, so no passkeys, ever**: the USB block cannot be another class, and software USB
gives 8-byte packets where CTAPHID needs 64. **No radio code**: `build-vaultkey.sh` fails if
`esp-radio` appears in `firmware/Cargo.lock`.

## Flash

```
0x000000  bootloader.bin | bootloader-sb.signed.bin
0x00C000  partition table (factory only; the SB bootloader does not fit below 0x8000)
0x010000  vaultkey.bin | vaultkey.signed.bin
0x110000  attempt counter (1 sector), copy A (53), copy B (53)
0x17B000
```

The vault is raw flash past `factory`, not a partition. Flash only through `vkey setup`:
`espflash flash` writes its own bootloader and table at 0x8000 and stops a Secure Boot
board from booting.

## eFuse state (irreversible)

- **2026-09-08:** `BLOCK_KEY0` = 32 random bytes, purpose `HMAC_UP`, read-protected, no copy;
  `DIS_USB_JTAG = DIS_PAD_JTAG = 1`.
- **2026-09-09, Secure Boot v2:** `BLOCK_KEY1` = digest of `firmware/secure-boot/public.pem`
  (`SECURE_BOOT_DIGEST0`), `SECURE_BOOT_EN`, `DIS_DIRECT_BOOT`, `SECURE_BOOT_KEY_REVOKE1/2`,
  `RD_DIS` write-protected. Download mode and Serial/JTAG stay enabled.

The signing key is `vkey-signing` (RSA-3072), an `.env` item on the nRF and in a `.vkb`;
`tools/sign-vaultkey.sh` signs with it (PIN and a tap). `vkey setup` asks the ROM
(`GET_SECURITY_INFO`) whether Secure Boot is on, because a Secure Boot bootloader on a plain
chip burns eFuses by itself. It flashes without the espflash stub. A fork of the project
makes its own key with `tools/signing-key.sh` and never burns this digest.

**Never:**
- burn an eFuse without the maintainer running `espefuse` personally after `summary`;
- burn `DIS_USB_SERIAL_JTAG*`, `DIS_DOWNLOAD_MODE` or `ENABLE_SECURITY_DOWNLOAD`;
- enable `SECURE_BOOT_AGGRESSIVE_REVOKE` or pass `--do-not-confirm`;
- guess the PIN.

Rejected: Flash Encryption (`docs/threat-model.md`); `BOOTLOADER_LOG_LEVEL_NONE` to fit
below 0x8000 (it hides proof the bootloader burned nothing).

## Traps

| Symptom | Cure |
|---|---|
| Gone from `lsusb` | GPIO12/13 were reconfigured: hold BOOT, tap RESET, release |
| `cat /dev/ttyACM0` silent | Read logs with `espflash monitor` |
| Old state after flashing | Flashing keeps the vault: `vkey setup --erase` |
| "no permission" / "port busy" | Join `dialout` and re-login, or `sg dialout -c '...'` |
| "resource busy", nobody holds it | ModemManager; add a udev rule with `ENV{ID_MM_DEVICE_IGNORE}="1"` for `303a:1001` |
| RNG not random | `TrngSource::new(RNG, ADC1)` must live for the whole run |
| Amber shows green | The LED is RGB, not GRB |
