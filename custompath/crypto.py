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

# Combined pool at MODULE LEVEL
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

def flatten_pool(pool):
    """Turn any mix of strings/lists into a flat list of single characters."""
    result = []
    for item in pool:
        result.extend(list(item))
    return result

def make_system_salt() -> tuple[bytes, str]:
    salt = secrets.token_bytes(64)
    stretched = hashlib.pbkdf2_hmac('sha3_512', salt, secrets.token_bytes(64), 4000000)
    return stretched, stretched.hex()

def make_random_salt(min_len=60, max_len=180) -> str:
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return ''.join(secrets.choice(YUSFAT_NOISE_POOL) for _ in range(length))

def pick_from(seq, salt_bytes, counter):
    h = hmac.new(salt_bytes, str(counter).encode(), hashlib.sha3_512).digest()
    return seq[int.from_bytes(h[:8], 'big') % len(seq)]

def make_noise(salt_bytes, counter, min_len=1, max_len=4):
    # Flatten all pools
    flat_invisibles   = flatten_pool(INVISIBLES)
    flat_spaces       = flatten_pool(SPACES)
    flat_emoji        = flatten_pool(EMOJI_POOL)
    flat_extra        = flatten_pool(EXTRA_UNIQUE_EMOJIS)
    flat_scripts      = flatten_pool(SCRIPTS)
    flat_safe         = flatten_pool(SAFE_EMOJIS)
    flat_non_ascii    = flatten_pool(NON_ASCII_LETTERS)
    flat_script1      = flatten_pool(SCRIPT_1)
    flat_script2      = flatten_pool(SCRIPT_2)
    flat_script3      = flatten_pool(SCRIPT_3)
    flat_script4      = flatten_pool(SCRIPT_4) if 'SCRIPT_4' in globals() else []
    flat_emoji3       = flatten_pool(EMOJI_POOL_3)
    flat_yusfat       = flatten_pool(YUSFAT_NOISE_POOL)

    length = secrets.randbelow(max_len - min_len + 1) + min_len
    parts = []

    for _ in range(length):
        r = int.from_bytes(hmac.new(salt_bytes, f"n{counter}".encode(), hashlib.sha3_512).digest()[:1], 'big') % 100
        counter += 1

        if r < 12:
            char = secrets.choice(flat_invisibles)
        elif r < 22:
            char = secrets.choice(flat_spaces)
   
        elif r < 38:
            char = secrets.choice(flat_emoji + flat_emoji3 + flat_safe)
        elif r < 52:
            char = secrets.choice(flat_extra)
        elif r < 70:
            char = secrets.choice(flat_scripts + flat_script1 + flat_script2 + flat_script3 + flat_script4)
        elif r < 85:
            char = secrets.choice(flat_non_ascii)
        else:
            char = secrets.choice(flat_yusfat)

        parts.append(char)

    return ''.join(parts)