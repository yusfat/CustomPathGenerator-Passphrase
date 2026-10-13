
# CustomPathGenerator-Passphrase

**High-entropy custom path & passphrase generator for offline custody**

> Assume breach. Verify recovery. Never trust a single factor.

![Security](https://img.shields.io/badge/Security-Defense%20in%20Depth-red)
![FinTech](https://img.shields.io/badge/FinTech-Digital%20Asset%20Custody-blue)
![Python](https://img.shields.io/badge/Python-3.12+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**At least 200 levels deep · Non-standard · Advanced users only**

---

## Why this exists

Seed phrases alone are no longer enough.

**February 2025, Bybit (approx $1.5B):** A compromised UI led signers to approve what they saw, not what they signed. The seed was not the only failure mode.

**2025, Coldcard weak-RNG reports:** Trusted hardware can still produce weak seed material. A well-stored seed is still weak if entropy at generation was weak.

**Lesson:** Even when you do many things right, the seed can be exposed or weak. A second, independent, high-entropy factor reduces single-point failure.

This tool generates that offline factor: a long, high-entropy string for use as a **BIP39 passphrase** and/or an experimental **custom derivation path**, on top of a standard seed you already protect properly.

---

## Recommended Security Setup: Air-Gap + Multisig

This is not a hot wallet tool. For maximum security, use it as part of an offline custody workflow.

### 1. Air-Gapped Generation (Required for serious funds)
1. Run this generator on a fully offline, air-gapped computer (never connected to internet).
2. Generate your custom path and passphrase offline.
3. Export ONLY the public keys (xpub, zpub) to your online device via QR or USB.
4. Never expose xpriv, mnemonic, or this generated factor on an online machine.

### 2. Multisig Vault (Prevents bricked funds)
Do not rely on one exotic path. Use it to create distinct cosigners:

- **2-of-3 example:** Generate 3 different custom paths on 3 different offline devices.
- Store each path/passphrase separately from its seed.
- Result: One compromised seed or one lost path does not compromise the vault.

This is why multisig matters here: a single lost custom factor can mean permanent loss. Multisig removes that single point of failure.

### 3. Offline Signing Workflow
1. Build the transaction online using xpubs (watch-only wallet).
2. Move the PSBT to your air-gapped device.
3. Sign offline using seed + custom path/passphrase.
4. Return signed PSBT to online device to broadcast.

Your private keys never leave the offline environment.

---

## What it is (and is not)

| It is | It is not |
| :--- | :--- |
| An offline entropy tool for advanced users | A wallet, exchange, or custodian |
| A generator of long high-entropy strings | Guaranteed BIP32 support in every app |
| Useful as a BIP39 passphrase (25th word) | Audited financial software |
| Local Python, no network for core generation | Protection against phishing or blind signing |

**Recommended use order**
1. BIP39 passphrase (widest compatibility)
2. Custom path only where the wallet truly accepts it
3. Separate path + separate passphrase for stronger separation
4. Same string for both only if you accept less separation

**If you lose the factor(s), funds can be gone forever.**

---

## How it works

### Path construction
1. Input string → **SHA3-512** → key bytes
2. About **220 to 299** segments under `m/`
3. Early levels prefer hardened indices (`'`), later levels often hardened (approx 75%)
4. **HMAC-SHA3-512** drives index digits and noise
5. Noise from invisibles, spaces, emoji/symbols, multi-script characters, non-ASCII letters, ASCII (excluding `/ \ " '`)
6. Minimum length **2000** characters

### Salts (`main.py`)

| Mode | Behavior |
| :--- | :--- |
| Beginner / pure random | Fresh **system salt** only |
| Personal salt | Your salt (50+ chars) + fresh system salt |
| Salt chaining | Multiple layers (SHA3-512 fold), optional hidden random layers + system salt |

**System salt:** random bytes → **PBKDF2-HMAC-SHA3-512** (high iteration count) → hex mixed into generator input. Not printed.

**Critical recovery rule:** Because system salt is new every run, re-typing only a personal salt will NOT recreate the same path. Always save the **final printed output** and any separate passphrase.

### Optional separate passphrase
High-entropy string for use as an extra factor (e.g. BIP39 passphrase), stored and labeled separately from the path output.

---

## Risk model

| Risk | Without a second factor | With this factor (if wallet uses it) |
| :--- | :--- | :--- |
| Seed exposed | Seed alone moves funds | Attacker still needs your saved path/passphrase |
| Weak RNG at seed generation | Vendor trust only | External high-entropy factor raises attack cost |
| Blind / malicious signing | See is not equal to sign | Does NOT replace verifying transactions |
| Self-lockout | - | Mandatory small-amount recovery test before real funds |

**Practice:** Dedicated or air-gapped machine when stakes are high, multisig so one exotic factor cannot brick the whole vault, seed offline, path/passphrase in a password manager never stored with the seed.

---

## Safety protocol (Do this every time)

1. Generate offline
2. Test wallet with seed + saved factor(s)
3. Send a trivial amount only
4. Wipe / remove wallet data
5. Recover using ONLY what you stored (check full length, Unicode can drop in bad copy/paste)
6. Fund more only after recovery works

---

## Wallet notes (author-tested)

| Wallet | Role |
| :--- | :--- |
| AirGap Vault | Custom path + passphrase |
| TokenPocket | Custom path + passphrase |
| BlueWallet | Passphrase only |
| Electrum | Passphrase only |

Re-check on your device and version. Support can change.

---

## Project layout

```text
main.py
custompath/
  __init__.py
  config.py
  crypto.py
  generator.py
  pools.py
  sanitizer.py
  ui.py
README.md
LICENSE

