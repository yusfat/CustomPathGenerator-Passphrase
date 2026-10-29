### ⚠️ Security Model - Read This Before Using

## 🔐 Security & Non-Determinism (Important)

This generator is **intentionally non-deterministic**.

Even if you enter the exact same personal salt (Option 2) or the same salt-chain layers (Option 3), you will **never** get the same path again. This is by design and is a security feature, not a bug.

### Why it is non-deterministic
- A fresh, high-entropy **system salt** is generated on every run (64 random bytes + PBKDF2-HMAC-SHA3-512 with 4,000,000 iterations). The system salt is never shown and is discarded after use.
- Additional pure-random decisions are made with Python’s `secrets` module:
  - Number of path levels (randomly 220–299)
  - Whether later levels are hardened
  - Exact length and placement of noise
  - Chance to insert noise inside large index numbers

### What this means for you
- You **cannot** regenerate a previous path by re-typing your personal salt.
- The **only** way to recover the wallet is to have saved the final printed output.
- A weak personal salt is still safe because it is always mixed with a strong, unique system salt + extra randomness.
- An attacker who somehow obtains only your personal salt still cannot recreate the path.

### Risk summary
| Risk | Status |
|------|--------|
| Attacker tries to predict the path from a weak personal salt | Blocked (system salt + secrets) |
| Attacker tries to force the same output | Impossible (non-deterministic) |
| You lose the final printed path | Funds permanently lost (by design) |
| You try to re-run with the same personal salt | Different path every time |

**Mandatory rule:**  
Always save the **final printed path** (and any separate passphrase) immediately in a secure password manager. Never rely on being able to regenerate it.

---
### Refer to the README.md as well ...

---

### 🪤🎉🎊Custom Path vs Passphrase: What Actually Secures You?

This tool generates two different types of secrets. They are NOT equal but you can use the output for both - the reason for the noise entropy (emojis etc.)in the first place, thereby serving a 2-in-1 purpose(s).

#### A: Custom Derivation Path `m/.../...`
Example: `m/243'/50'/72'/2032710863'/75'/365'`

**What DOES NOT add cryptographic security:**
- Emojis 😀🔑, multi-script letters, spaces, letters like `xyz`
Most wallets (Trust Wallet, MetaMask, etc) do *NOT* even allow users to input or user custom paths (and even passphrase features currently do not exist). As proven in our tests:
`m/243😀'/50🔑9'/72'` -> wallet reads it as `m/243'/509'/72'` or `m/243'/50'/72'` on TokenPocket...
Screenshot proof: importing `m/243👨‍👩‍👧/50🔑9'/72'/20327...` shows "Wallet already exists" when `m/243'/50'/72'/20327...` exists. The noise is stripped. It contributes **0 entropy** to the path.

**What DOES add security in the path:**
- Large, non-standard numbers within `0 to 2^31-1` (e.g., `2032710863'`, `77824'`)
Reason: Bots and brute-force tools only scan standard paths like `m/44'/60'/0'/0/0` up to `m/44'/60'/10'`. A path like `m/243'/50'/72'/2032710863'/75'/365'` will never be found by automated scanners. The search space for an attacker is `~ (2^31)^N` where N = depth. Large values increase that search space.

> Rule: In custom path, only digits `0-9`, `/`, and `'` matter. Everything else is cosmetic and may cause loss.

#### B: Passphrase (BIP39 25th word) - RECOMMENDED FOR THIS TOOL'S NOISE
Example: `i6ri6rktdmtw4ektdtme🐯/772430'/👨‍👩‍👧` but any noise before the first digit will break the tested wallets but you do not need to worry about that because the author has enforced a rule to not place noises before digits...

When the SAME string is used as a **passphrase**, not as a path, EVERY character matters and contribute to difficuly of stealing your crypto even when your seedphrase has been unknowingly compromised ( it is recommended you do not store seedphrase, derivation path and passphrase at exactly same location, and you should use this tool offline, and if possible as part of a well planned *multisig* wallet on a *crypto dedicated machine/phone/device* ):
- Emojis, Cyrillic `Д/Л`, CJK `日`, symbols `&$#`, letters, numbers all contribute to full cryptographic entropy. The passphrase is hashed via PBKDF2, no sanitization.
- `passphrase = "hello"` vs `passphrase = "hello😀"` = two completely different wallets.
- This is where layered noise (emojis + multi-script + symbols + large digits) actually increases entropy.

**Comparison:**

| Feature | In Custom Path | In Passphrase |
| :--- | :--- | :--- |
| Emojis 😀 | 0 security, stripped | Full security, adds entropy |
| Letters/Unicode И/日 | 0 security, stripped | Full security, adds entropy |
| Large numbers < 2^31 | High security (obscurity) | High security (entropy) |
| Recoverability | Low if noise included | Low if not backed up 100% exact |

### Why "Advanced Users Only" & "At Least 200 Levels Deep"

- 200+ levels breaks compatibility with 99% of wallets. Most limit to 5-10 levels or 255 chars. This tool can generate 2200 (2150 is a safe maximum limit) chars (see test).
- Unicode normalization: `👨‍👩‍👧` copied from phone to paper can become `?` or `👨👩`. If you lose one byte, funds are lost forever.
- You MUST back up the EXACT final string with manual copy-paste and store it offline, UTF-8 preserved. Forgetting or mis-storing = unrecoverable.

This tool is for **Defense in Depth**: Assume breach. Your 12 words are found. The attacker still needs your exact custom path + exact passphrase. This is FinTech / Digital Asset Custody level security, not for beginners.

**DO NOT use the beef test phrase from preview on mainnet. Verify recovery on a clean device before funding.**

> Assume breach. Verify recovery. Never trust a single factor.