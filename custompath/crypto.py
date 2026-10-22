#===== custompath/crypto.py =====

# custompath/crypto.py

import secrets
import hashlib
import hmac
import string
from .pools import *

BANNED = {'/', '\\', '"', "'"}
SAFE_PUNCT = ''.join(c for c in string.punctuation if c not in BANNED)
YUSFAT_ASCII_NOISE = list(string.ascii_letters + string.digits + SAFE_PUNCT)

# Full original pool (used for paths and services that allow everything)
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
    result = []
    for item in pool:
        if isinstance(item, str) and len(item) > 1 and not item.isascii():
            result.append(item)
        else:
            result.extend(list(item))
    return result

# Pre-built pools (loaded once)
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
FLAT_STANDARD   = tuple(set(YUSFAT_ASCII_NOISE))          # letters + digits + normal specials only

def make_system_salt():
    salt = secrets.token_bytes(64)
    stretched = hashlib.pbkdf2_hmac(
        'sha3_512',
        salt,
        secrets.token_bytes(64),
        4000000
    )
    return stretched, stretched.hex()

def make_random_salt(min_len=60, max_len=180, pool=None):
    if pool is None:
        pool = YUSFAT_NOISE_POOL
    if not pool:
        pool = FLAT_STANDARD
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return ''.join(secrets.choice(pool) for _ in range(length))

def pick_from(seq, salt_bytes, counter):
    if not seq:
        return ''
    h = hmac.new(salt_bytes, str(counter).encode(), hashlib.sha3_512).digest()
    return seq[int.from_bytes(h[:8], 'big') % len(seq)]

def make_noise(salt_bytes, counter, min_len=1, max_len=4):
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

def build_password_pool(allow_emoji=True, allow_invisible=True, allow_space=True, standard_only=False):
    """Build a character pool according to the rules the user selected."""
    if standard_only:
        pool = list(FLAT_STANDARD)
    else:
        pool = list(FLAT_STANDARD)
        if allow_emoji:
            pool.extend(FLAT_EMOJI)
            pool.extend(FLAT_EXTRA)
            pool.extend(FLAT_SCRIPTS)
            pool.extend(FLAT_NON_ASCII)
        if allow_invisible:
            pool.extend(FLAT_INVISIBLES)
        if allow_space:
            pool.extend(FLAT_SPACES)
    # remove duplicates while keeping order
    seen = set()
    clean = []
    for c in pool:
        if c not in seen:
            seen.add(c)
            clean.append(c)
    return clean if clean else list(FLAT_STANDARD)

def make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=True, standard_only=False):
    """Generate a high-entropy password that respects the chosen limits."""
    pool = build_password_pool(allow_emoji, allow_invisible, allow_space, standard_only)
    # always use at least 80% of the allowed maximum for strength
    min_len = max(16, int(max_len * 0.8))
    return make_random_salt(min_len=min_len, max_len=max_len, pool=pool)