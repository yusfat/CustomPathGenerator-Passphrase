## Security & Non-Determinism (Important)

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