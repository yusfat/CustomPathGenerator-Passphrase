#===== custompath/crypto.py =====

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
    + SPACES
    + inviSible_70
    + (SCRIPT_4 if 'SCRIPT_4' in globals() else [])
    + EMOJI_POOL_3
)

def smart_flatten(pool):
    """Turn any mix of strings/lists into a flat list of single characters."""
    result = []
    for item in pool:
        result.extend(list(item))
    return result

# Pre-built pools (loaded once) #cleaner, more secure / zero bias
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
FLAT_STANDARD   = tuple(set(YUSFAT_ASCII_NOISE))          # letters + digits + normal specials only

# ---- Optional secret noise pool (password-protected, additive) ----
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

    # ---------- old style (any name that is not the special one) ----------
    if path.name != expected:
        # original behaviour – no HMAC required
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

    # ---------- new style (exact expected name + HMAC with per-file salt) ----------
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
        if len(data) < 16 + 32:          # salt + at least some MAC
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
        elif r < 68:
            char = pick_from(FLAT_SCRIPTS, salt_bytes, counter)
        elif r < 80:
            char = pick_from(FLAT_NON_ASCII, salt_bytes, counter)
        elif r < 95 and FLAT_SECRET:          # MORE FREQUENT use of secret pool (~15% slice)
            char = pick_from(FLAT_SECRET, salt_bytes, counter)
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
        # ---- additive: include secret pool when available and full noise is allowed ----
        if FLAT_SECRET and allow_emoji and allow_invisible:
            pool.extend(FLAT_SECRET)
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
    min_len = max(16, int(max_len * 0.95))
    return make_random_salt(min_len=min_len, max_len=max_len, pool=pool)