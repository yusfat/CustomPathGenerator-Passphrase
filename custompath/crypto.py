# ====================== custompath/crypto.py ======================
import secrets
import hashlib
import hmac
import string
from .config import *

def generate_strong_salt(min_len: int = 60, max_len: int = 180) -> str:
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    chars = string.ascii_letters + string.digits + EMOJI_POOL + EXTRA_UNIQUE_EMOJIS
    return ''.join(secrets.choice(chars) for _ in range(length))

def multi_layer_salt(base_salt: str, layers: int = 8, iterations: int = 100000) -> str:
    current = base_salt.encode()
    for _ in range(max(3, min(layers, 15))):
        current = hashlib.pbkdf2_hmac('sha256', current, b'custompath_stretch', iterations)
    return current.hex()

def secure_choice(seq, salt_bytes, counter):
    h = hmac.new(salt_bytes, str(counter).encode(), hashlib.sha256).digest()
    return seq[int.from_bytes(h[:8], 'big') % len(seq)]