# ====================== custompath/generator.py ======================
import hashlib
import hmac
import secrets
from .crypto import generate_strong_salt, secure_choice
from .config import MAX_INDEX, EXTRA_UNIQUE_EMOJIS, EMOJI_POOL

def generate_path(final_salt: str = "", target_len: int = 2000) -> str:
    if not final_salt:
        final_salt = generate_strong_salt()

    salt_bytes = hashlib.sha3_512(final_salt.encode()).digest()
    levels = secrets.randbelow(80) + 220
    parts = ['m']
    counter = 0

    for _ in range(levels):
        h = hmac.new(salt_bytes, f"i{counter}".encode(), hashlib.sha256).digest()
        idx = int.from_bytes(h[:4], 'big') % MAX_INDEX
        parts.append(f"{idx}'")
        counter += 1

        noise_char = secure_choice(EXTRA_UNIQUE_EMOJIS + EMOJI_POOL, salt_bytes, counter)
        parts.append(noise_char)
        counter += 1

    path = '/'.join(parts)

    if len(path) > target_len:
        path = path[:target_len].rstrip('/') + "/0'/0"

    return path