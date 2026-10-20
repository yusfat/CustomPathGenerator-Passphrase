#===== main.py =====

#!/usr/bin/env python3
# main.py

from custompath.crypto import make_system_salt, make_random_salt
from custompath.generator import make_path
import hashlib
import sys

def copy_to_clipboard(text):
    import subprocess
    for cmd in (["termux-clipboard-set"],
                ["xclip", "-selection", "clipboard"],
                ["pbcopy"]):
        try:
            subprocess.run(cmd, input=text.encode("utf-8"), check=True, capture_output=True)
            return True
        except Exception:
            continue
    return False

def print_header():
    print("=" * 70)
    print("  CustomPathGenerator-Passphrase")
    print("  High-entropy custom path & passphrase generator")
    print("  200+ levels deep · Non-standard · Advanced users only")
    print("=" * 70)
    print()
    print("WARNING: For advanced users only. Use at your own risk.")
    print("Always test recovery with a small amount first.")
    print()
    print("Tested wallets:")
    print("  AirGap Vault & TokenPocket  → path + passphrase")
    print("  BlueWallet & Electrum       → passphrase only")
    print()

def get_target_length():
    while True:
        try:
            value = int(input("Path length (2000-2150): ").strip())
            if 2000 <= value <= 2150:
                return value
            print("Must be between 2000 and 2150.")
        except ValueError:
            print("Enter a number.")

def get_advanced_salt():
    print("\nAdvanced mode")
    print("1. Pure random")
    print("2. One personal salt")
    print("3. Salt chaining")
    choice = input("Choice (1/2/3): ").strip()

    if choice == "3":
        print("\nSalt chaining (5-7 layers recommended)")
        final_salt = ""
        layers = 0
        while layers < 7:
            print(f"\nLayer {layers + 1}")
            gen = input("Generate random salt for this layer? (y/n): ").strip().lower()
            if gen == "y":
                current = make_random_salt()
                print("Random salt applied (not shown).")
            else:
                current = input("Paste salt (at least 50 chars): ").strip()
                if len(current) < 50:
                    print("Too short, skipping.")
                    continue

            if layers == 0:
                final_salt = current
            else:
                final_salt = hashlib.sha3_512((final_salt + current).encode()).hexdigest() + current

            layers += 1
            if input("Add another layer? (y/n): ").strip().lower() != "y":
                break

        print(f"\nDone. {layers} layers used.")
        return final_salt

    if choice == "2":
        personal = input("Personal salt (at least 50 chars): ").strip()
        if len(personal) < 50:
            print("Too short, using pure random instead.")
            return ""
        return personal

    return ""

def main():
    print_header()

    while True:
        mode = input("Beginner or Advanced? (b/a): ").strip().lower()
        target_len = get_target_length()

        _, system_salt_hex = make_system_salt()

        if mode == "a":
            final_salt = get_advanced_salt()
        else:
            print("\nBeginner mode – pure random")
            final_salt = ""

        combined = final_salt + system_salt_hex if final_salt else system_salt_hex

        print("\nGenerating path...")
        result = make_path(combined, target_len)

        print("\n" + "=" * 70)
        print("DERIVATION PATH")
        print("=" * 70)
        print(result)
        print("=" * 70)
        print(f"Length: {len(result)} characters")

        if copy_to_clipboard(result):
            print("Path copied to clipboard.")
        else:
            print("Could not copy automatically – please copy it yourself.")

        print("\nHow to use:")
        print("  A) Same string for both path and passphrase")
        print("  B) Make a separate passphrase (better)")
        print("  C) Make another path and use that as passphrase")
        print("\nIf you lose the path or passphrase the funds are gone forever.")

        if input("\nMake a separate passphrase too? (y/n): ").strip().lower() == "y":
            passphrase = make_random_salt(min_len=80, max_len=200)
            print("\n" + "=" * 70)
            print("SEPARATE PASSPHRASE")
            print("=" * 70)
            print(passphrase)
            print("=" * 70)
            if copy_to_clipboard(passphrase):
                print("Passphrase copied to clipboard.")
            else:
                print("Could not copy automatically – please copy it yourself.")

        print("\nChecklist:")
        print("  - Save only the final path and passphrase")
        print("  - Test recovery with a tiny amount first")
        print("  - Never keep intermediate salts")
        print()

        if input("Generate another one? (y/n): ").strip().lower() != "y":
            print("\nStay safe.")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nStopped. Stay safe.")
        sys.exit(0)