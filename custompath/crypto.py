# ====================== custompath/crypto.py ======================
import secrets
import hashlib
import hmac
import os
import string
from .pools import *

BANNED = {'/', '\\', '"', "'"}
SAFE_PUNCT = ''.join(c for c in string.punctuation if c not in BANNED)
YUSFAT_ASCII_NOISE = list(string.ascii_letters + string.digits + SAFE_PUNCT)

# Combined pool at MODULE LEVEL (visible to every function)
YUSFAT_NOISE_POOL = (
    YUSFAT_ASCII_NOISE
    + EMOJI_POOL
    + EXTRA_UNIQUE_EMOJIS
    + SCRIPTS
    + INVISIBLES
    + SAFE_EMOJIS +
    NON_ASCII_LETTERS +
    SCRIPT_1 +
    SCRIPT_2 +
    SCRIPT_3 + 
    SCRIPT_4 +
    EMOJI_POOL_3

)


def make_system_salt() -> tuple[bytes, str]:
    salt = secrets.token_bytes(64)          # Strong random salt
    stretched = hashlib.pbkdf2_hmac('sha3_512', salt, secrets.token_bytes(64), 4000000)
    return stretched, stretched.hex()


def make_random_salt(min_len=60, max_len=180) -> str:
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return ''.join(secrets.choice(YUSFAT_NOISE_POOL) for _ in range(length))


def pick_from(seq, salt_bytes, counter):
    h = hmac.new(salt_bytes, str(counter).encode(), hashlib.sha3_512).digest()
    return seq[int.from_bytes(h[:8], 'big') % len(seq)]


def make_noise(salt_bytes, counter, min_len=12, max_len=55):
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    parts = []
    for _ in range(length):
        r = int.from_bytes(hmac.new(salt_bytes, f"n{counter}".encode(), hashlib.sha3_512).digest()[:1], 'big') % 100
        counter += 1
        if r < 15:
            parts.append(pick_from(INVISIBLES, salt_bytes, counter))
        elif r < 28:
            parts.append(pick_from(SPACES, salt_bytes, counter))
        elif r < 43:
            parts.append(pick_from(EMOJI_POOL, salt_bytes, counter))
        elif r < 58:
            parts.append(pick_from(EXTRA_UNIQUE_EMOJIS, salt_bytes, counter))
        elif r < 78:
            parts.append(pick_from(SCRIPTS, salt_bytes, counter))
        else:
            parts.append(pick_from(YUSFAT_NOISE_POOL, salt_bytes, counter))
        counter += 1
    return ''.join(parts), counter