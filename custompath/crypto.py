# ============================================================
# FILE: custompath/crypto.py
# ============================================================

import secrets
import hashlib
import hmac
import string
import getpass
import subprocess
from pathlib import Path
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
    + SPACES
    + inviSible_70
    + (SCRIPT_4 if 'SCRIPT_4' in globals() else [])
    + EMOJI_POOL_3
)

def smart_flatten(pool):
    result = []
    for item in pool:
        result.extend(list(item))
    return result

FLAT_INVISIBLES = tuple(set(smart_flatten(INVISIBLES + inviSible_70)))
FLAT_SPACES     = tuple(set(smart_flatten(SPACES)))
FLAT_EMOJI      = tuple(set(smart_flatten(EMOJI_POOL + EMOJI_POOL_3 + SAFE_EMOJIS)))
FLAT_EXTRA      = tuple(set(smart_flatten(EXTRA_UNIQUE_EMOJIS)))
FLAT_SCRIPTS    = tuple(set(smart_flatten(
    SCRIPTS + SCRIPT_1 + SCRIPT_2 + SCRIPT_3 +
    (SCRIPT_4 if 'SCRIPT_4' in globals() else [])
)))
FLAT_NON_ASCII  = tuple(set(smart_flatten(NON_ASCII_LETTERS)))
FLAT_YUSFAT     = tuple(set(smart_flatten(YUSFAT_NOISE_POOL)))
FLAT_STANDARD   = tuple(set(YUSFAT_ASCII_NOISE))

SECRET_NOISE_POOL = []
FLAT_SECRET = tuple()

def _t(s: bytes, k: int = 0x5A) -> bytes:
    return bytes(c ^ k for c in s)

def _n() -> str:
    raw = _t(bytes([41,63,57,40,63,46,5,52,53,51,41,63,5,109,60,105,59,99,57]))
    h = hashlib.sha3_256(raw).hexdigest()[:4]
    return raw.decode() + h + ".enc"

def _v(password: str, salt: bytes) -> bytes:
    info = _t(bytes([25,47,41,46,53,55,10,59,46,50,20,53,51,41,63,18,23,27,25,44,107]))
    return hashlib.pbkdf2_hmac(
        "sha3_512",
        password.encode("utf-8"),
        salt + info,
        2000000,
        dklen=64
    )

def load_secret_noise(encrypted_path: str | None = None, password: str | None = None) -> list:
    global SECRET_NOISE_POOL, FLAT_SECRET
    SECRET_NOISE_POOL = []
    FLAT_SECRET = tuple()

    expected = _n()
    path = Path(encrypted_path or expected)

    if not path.is_file():
        return []

    if path.name != expected:
        if password is None:
            try:
                password = getpass.getpass("Enter password for secret noise file (or press Enter to skip): ")
            except Exception:
                return []
        if not password:
            return []
        try:
            result = subprocess.run(
                ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                 "-in", str(path), "-pass", "stdin"],
                input=(password + "\n").encode(),
                capture_output=True, check=True, timeout=30,
            )
            content = result.stdout.decode("utf-8", errors="ignore")
            chars = list(content)
            SECRET_NOISE_POOL = list(dict.fromkeys(chars))
            FLAT_SECRET = tuple(SECRET_NOISE_POOL)
            return SECRET_NOISE_POOL
        except Exception:
            return []

    if password is None:
        try:
            password = getpass.getpass("Enter password for secret noise file (or press Enter to skip): ")
        except Exception:
            return []
    if not password:
        return []

    try:
        result = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
             "-in", str(path), "-pass", "stdin"],
            input=(password + "\n").encode(),
            capture_output=True, check=True, timeout=30,
        )
        content = result.stdout.decode("utf-8", errors="ignore")

        hmac_path = path.with_suffix(".hmac")
        if not hmac_path.is_file():
            return []

        data = hmac_path.read_bytes()
        if len(data) < 16 + 32:
            return []

        salt = data[:16]
        expected_mac = data[16:]

        key = _v(password, salt)
        actual_mac = hmac.new(key, content.encode("utf-8"), hashlib.sha3_512).digest()

        if not hmac.compare_digest(actual_mac, expected_mac):
            return []

        chars = list(content)
        SECRET_NOISE_POOL = list(dict.fromkeys(chars))
        FLAT_SECRET = tuple(SECRET_NOISE_POOL)
        return SECRET_NOISE_POOL

    except Exception:
        SECRET_NOISE_POOL = []
        FLAT_SECRET = tuple()
        return []

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

def make_session_pools():
    """Create fresh non-deterministic session pools from the public lists (once per generation)."""
    def _shuf(seq):
        lst = list(seq)
        secrets.SystemRandom().shuffle(lst)
        return tuple(lst)

    return {
        "invisibles": _shuf(FLAT_INVISIBLES),
        "spaces":     _shuf(FLAT_SPACES),
        "emoji":      _shuf(FLAT_EMOJI),
        "extra":      _shuf(FLAT_EXTRA),
        "scripts":    _shuf(FLAT_SCRIPTS),
        "non_ascii":  _shuf(FLAT_NON_ASCII),
        "yusfat":     _shuf(FLAT_YUSFAT),
        "secret":     _shuf(FLAT_SECRET) if FLAT_SECRET else tuple(),
        "standard":   _shuf(FLAT_STANDARD),
    }

def make_noise(salt_bytes, counter, min_len=1, max_len=4, session_pools=None):
    """Fast non-deterministic noise selection."""
    if session_pools is None:
        session_pools = make_session_pools()

    length = secrets.randbelow(max_len - min_len + 1) + min_len
    parts = []

    # Build combined pool once (no re-shuffle every call)
    candidates = []
    candidates.extend(session_pools["invisibles"])
    candidates.extend(session_pools["spaces"])
    candidates.extend(session_pools["emoji"])
    candidates.extend(session_pools["extra"])
    candidates.extend(session_pools["scripts"])
    candidates.extend(session_pools["non_ascii"])
    if session_pools["secret"]:
        candidates.extend(session_pools["secret"])
    candidates.extend(session_pools["yusfat"])

    if not candidates:
        candidates = list(FLAT_STANDARD)

    for _ in range(length):
        char = secrets.choice(candidates)
        parts.append(char)
        counter += 1

    return ''.join(parts), counter

def build_password_pool(allow_emoji=True, allow_invisible=True, allow_space=True, standard_only=False, session_pools=None):
    if session_pools is None:
        session_pools = make_session_pools()

    if standard_only:
        pool = list(session_pools["standard"])
    else:
        pool = list(session_pools["standard"])
        if allow_emoji:
            pool.extend(session_pools["emoji"])
            pool.extend(session_pools["extra"])
            pool.extend(session_pools["scripts"])
            pool.extend(session_pools["non_ascii"])
        if allow_invisible:
            pool.extend(session_pools["invisibles"])
        if allow_space:
            pool.extend(session_pools["spaces"])
        if session_pools["secret"] and allow_emoji and allow_invisible:
            pool.extend(session_pools["secret"])

    seen = set()
    clean = []
    for c in pool:
        if c not in seen:
            seen.add(c)
            clean.append(c)
    return clean if clean else list(FLAT_STANDARD)

def make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=True, standard_only=False):
    session_pools = make_session_pools()
    pool = build_password_pool(allow_emoji, allow_invisible, allow_space, standard_only, session_pools)
    min_len = max(16, int(max_len * 0.95))
    return make_random_salt(min_len=min_len, max_len=max_len, pool=pool)