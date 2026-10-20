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
        num = idx
        hardened = (i < 200) or (secrets.randbelow(100) < 75)

        # Aggressive internal noise (8-15% chance) only on large numbers
        if (100001 <= int(num) <= MAX_INDEX) and (8 <= secrets.randbelow(100) < 15):
            insert_pos = max(1, int(len(num) * 0.7))
            noise_inside, counter = make_noise(salt_bytes, counter, min_len=1, max_len=3)
            num = num[:insert_pos] + noise_inside + num[insert_pos:]

        noise1, counter = make_noise(min_len=1, max_len=2)
        noise2, counter = make_noise(min_len=1, max_len=3)

        if hardened:
            segment = num + noise1 + "'" + noise2
        else:
            segment = num + noise1

        parts.append(segment)

    parts.append("0")
    parts.append("0")
    path = '/'.join(parts)

    if len(path) > target_len:
        path = path[:target_len]
        if not path.endswith("/0"):
            path = path.rstrip("/") + "/0/0"
    return path