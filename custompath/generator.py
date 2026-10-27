#===== custompath/generator.py =====

import secrets
import hashlib
import hmac
from .config import MAX_INDEX
from .crypto import make_noise

def make_number(salt_bytes, counter):
    h = hmac.new(salt_bytes, f"i{counter}".encode(), hashlib.sha3_512).digest()

    # 95 % single-digit, 5 % multi-digit (2–10)
    if secrets.randbelow(100) < 95:
        digits = 1
    else:
        digits = (int.from_bytes(h[:1], 'big') % 9) + 2   # 2…10

    if digits == 1:
        return str(int.from_bytes(h[1:2], 'big') % 10), counter + 1

    max_val = min(10 ** digits - 1, MAX_INDEX)
    val = int.from_bytes(h[1:9], 'big') % (max_val + 1)
    return str(val), counter + 1

def make_path(final_salt, target_len):
    salt_bytes = hashlib.sha3_512(final_salt.encode('utf-8')).digest()
    levels = secrets.randbelow(105) + 405
    parts = ['m']
    counter = 0

    for i in range(levels):
        idx, counter = make_number(salt_bytes, counter)
        num = idx

        # ---------- Hardened decision (Version 4 / Hybrid-99) ----------
        # Last 50 levels: 99% Version 2 (pure varying 30-70%) + 1% Version 3
        if i < levels - 50:
            # Early / middle levels (original behaviour)
            hardened = (i < 200) or (secrets.randbelow(100) < 75)
        else:
            # Version 4 – 99 : 1 mix
            if secrets.randbelow(100) < 99:          # 99% (Version 2)
                hardened = secrets.randbelow(100) < (30 + secrets.randbelow(41))
            else:                                    # 1% (Version 3)
                if secrets.randbelow(100) < 82:
                    hardened = (i + secrets.randbelow(2)) % 2 == 0
                else:
                    hardened = secrets.randbelow(2) == 0

        if (100001 <= int(num) <= MAX_INDEX) and (8 <= secrets.randbelow(100) < 15):
            insert_pos = max(1, int(len(num) * 0.7))
            noise_inside, counter = make_noise(salt_bytes, counter, min_len=1, max_len=3)
            num = num[:insert_pos] + noise_inside + num[insert_pos:]

        noise1, counter = make_noise(salt_bytes, counter, min_len=1, max_len=2)
        noise2, counter = make_noise(salt_bytes, counter, min_len=1, max_len=3)

        if hardened:  # crypto wallet import risk management proactive measure(s)
            # Extract ONLY real ASCII digits 0-9
            # (Unicode look-alikes like ➄, ②, ５, ² etc. are intentional noise and must be ignored)
            pure = ''.join(c for c in (num + noise1) if c in '0123456789') or '0'

            # Safe conversion + hard enforcement of MAX_INDEX (2**31 - 1)
            try:
                pure_int = int(pure)
            except ValueError:
                pure_int = 0

            if len(pure) > 10 or pure_int > MAX_INDEX:
                # Keep the longest valid prefix that still fits in a signed 31-bit integer
                candidate = pure[:10] if len(pure) > 10 else pure
                try:
                    if int(candidate) > MAX_INDEX:
                        candidate = pure[:9]
                except ValueError:
                    candidate = '0'

                num = candidate
                noise1 = ''

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

    return path, levels