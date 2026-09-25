# ====================== custompath/sanitizer.py ======================
def sanitize_input(text: str) -> str:
    dangerous = [
        '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
        '\u2066', '\u2067', '\u2068', '\u2069', '\u200e', '\u200f'
    ]
    for char in dangerous:
        text = text.replace(char, '')
    return text.strip()