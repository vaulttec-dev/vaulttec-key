# Security policy

## Reporting a vulnerability

Use a private report on GitHub: **Security → Report a vulnerability** in this repository.
It reaches the maintainer only and does not create a public issue.

**Do not open a public issue** for anything in the cryptography, PIN handling, secret
storage or the host protocol.

| | |
|---|---|
| Acknowledgement | within 5 business days |
| Initial assessment | within 14 days |
| Coordinated disclosure | 90 days from acknowledgement, by default |

A small project with no round-the-clock team. Promising faster would be dishonest. There
is no bounty; public credit in the release notes is offered gladly if you want it.

## Scope

| In scope | Out of scope |
|---|---|
| Firmware in `firmware/` | Physical attacks with equipment: power glitching, side channels, flash extraction |
| The CLI in `cli/` and the tools in `tools/` | Attacks requiring full control of the host at the moment of a legitimate button press |
| A code or a signature produced without a button press | Vulnerabilities in the ESP32 itself or in `esp-hal` — report those to Espressif, and tell us so we can update |
| Bypassing or brute-forcing the PIN over the protocol | |
| Extracting secrets by software means | |

Out of scope does not mean uninteresting: it means already known, and documented with its
consequences in [docs/threat-model.md](docs/threat-model.md). Read the limitations there
before reporting — the ESP32 is not a secure element, and no resistance to physical
attack is claimed.
