# ===== custompath/crypto.py =====

# custompath/crypto.py

import secrets
import hashlib
import hmac
import string
from .pools import *

BANNED = {'/', '\\', '"', "'"}
SAFE_PUNCT = ''.join(c for c in string.punctuation if c not in BANNED)
YUSFAT_ASCII_NOISE = list(string.ascii_letters + string.digits + SAFE_PUNCT)

YUSFAT_NOISE_POOL = (
    YUSFAT_ASCII_NOISE
    + EMOJI_POOL
    + EXTRA_UNIQUE_EMOJIS
    + SCRIPTS
    + INVISIBLES
    + SAFE_EMOJIS
    + NON_ASCII_LETTERS
    + SCRIPT_1
    + SCRIPT_2
    + SCRIPT_3
    + (SCRIPT_4 if 'SCRIPT_4' in globals() else [])
    + EMOJI_POOL_3
)

def smart_flatten(pool):
    # Keep multi-codepoint emojis together when possible
    result = []
    for item in pool:
        if isinstance(item, str) and len(item) > 1 and not item.isascii():
            result.append(item)
        else:
            result.extend(list(item))
    return result

# Build the pools only once when the module loads
FLAT_INVISIBLES = tuple(set(smart_flatten(INVISIBLES)))
FLAT_SPACES     = tuple(set(smart_flatten(SPACES)))
FLAT_EMOJI      = tuple(set(smart_flatten(EMOJI_POOL + EMOJI_POOL_3 + SAFE_EMOJIS)))
FLAT_EXTRA      = tuple(set(smart_flatten(EXTRA_UNIQUE_EMOJIS)))
FLAT_SCRIPTS    = tuple(set(smart_flatten(
    SCRIPTS + SCRIPT_1 + SCRIPT_2 + SCRIPT_3 +
    (SCRIPT_4 if 'SCRIPT_4' in globals() else [])
)))
FLAT_NON_ASCII  = tuple(set(smart_flatten(NON_ASCII_LETTERS)))
FLAT_YUSFAT     = tuple(set(smart_flatten(YUSFAT_NOISE_POOL)))

def make_system_salt():
    # Fresh high-entropy salt every run (never shown to the user)
    salt = secrets.token_bytes(64)
    stretched = hashlib.pbkdf2_hmac(
        'sha3_512',
        salt,
        secrets.token_bytes(64),
        4000000
    )
    return stretched, stretched.hex()

def make_random_salt(min_len=60, max_len=180):
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return ''.join(secrets.choice(YUSFAT_NOISE_POOL) for _ in range(length))

def pick_from(seq, salt_bytes, counter):
    if not seq:
        return ''
    h = hmac.new(salt_bytes, str(counter).encode(), hashlib.sha3_512).digest()
    return seq[int.from_bytes(h[:8], 'big') % len(seq)]

def make_noise(salt_bytes, counter, min_len=1, max_len=4):
    # Noise is tied to the system salt through HMAC
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    parts = []

    for _ in range(length):
        r = int.from_bytes(
            hmac.new(salt_bytes, f"n{counter}".encode(), hashlib.sha3_512).digest()[:1],
            'big'
        ) % 100
        counter += 1

        if r < 12:
            char = pick_from(FLAT_INVISIBLES, salt_bytes, counter)
        elif r < 22:
            char = pick_from(FLAT_SPACES, salt_bytes, counter)
        elif r < 38:
            char = pick_from(FLAT_EMOJI, salt_bytes, counter)
        elif r < 52:
            char = pick_from(FLAT_EXTRA, salt_bytes, counter)
        elif r < 70:
            char = pick_from(FLAT_SCRIPTS, salt_bytes, counter)
        elif r < 85:
            char = pick_from(FLAT_NON_ASCII, salt_bytes, counter)
        else:
            char = pick_from(FLAT_YUSFAT, salt_bytes, counter)

        parts.append(char)
        counter += 1

    return ''.join(parts), counter