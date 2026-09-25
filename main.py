# ====================== main.py ======================
from custompath.ui import get_user_choices
from custompath.generator import generate_path
import subprocess

def main():
    print("=" * 60)
    print("🔑 Custom Obfuscated Path Generator")
    print("=" * 60)

    final_salt, target_len = get_user_choices()
    result = generate_path(final_salt, target_len)

    print("\n" + result)
    print(f"\nLength: {len(result)} characters")

    try:
        subprocess.run(['termux-clipboard-set', result], check=True)
        print("✅ Copied to clipboard!")
    except Exception:
        print("⚠️ Please copy manually.")

if __name__ == "__main__":
    main()