# ====================== custompath/generator.py ======================
import secrets
import hashlib
import hmac
from .config import MAX_INDEX
from .crypto import pick_from, make_noise

def make_number(salt_bytes, counter):
    h = hmac.new(salt_bytes, f"i{counter}".encode(), hashlib.sha3_512).digest()
    digits = (int.from_bytes(h[:1], 'big') % 10) + 1
    if digits == 1:
        return str(int.from_bytes(h[1:2], 'big') % 10), counter + 1
    max_val = min(10**digits - 1, MAX_INDEX)
    val = int.from_bytes(h[1:9], 'big') % (max_val + 1)
    return str(val), counter + 1

def make_path(final_salt: str, target_len: int) -> str:
    salt_bytes = hashlib.sha3_512(final_salt.encode('utf-8')).digest()
    levels = secrets.randbelow(80) + 220
    parts = ['m']
    counter = 0

    for i in range(levels):
        idx, counter = make_number(salt_bytes, counter)
        if i < 200:
            parts.append(idx + "'")
        else:
            if secrets.randbelow(100) < 75:
                segment = idx + "'"
            else:
                segment = idx
            noise, counter = make_noise(salt_bytes, counter)
            parts.append(segment + noise)

    parts.append("0")
    parts.append("0")
    path = '/'.join(parts)

    if len(path) > target_len:
        path = path[:target_len]
        if not path.endswith("/0"):
            path = path.rstrip("/") + "/0/0"
    return path