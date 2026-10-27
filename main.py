#===== main.py =====

#!/usr/bin/env python3

from custompath.crypto import make_system_salt, make_random_salt, make_password, load_secret_noise
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
    print("  High-entropy path & password generator")
    print("  Advanced users only")
    print("=" * 70)
    print()
    print("WARNING: Use at your own risk. Always test recovery with a small amount.")
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

def generate_path():
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
    result, levels = make_path(combined, target_len)
    print("\n" + "=" * 70)
    print("DERIVATION PATH")
    print("=" * 70)
    print(result)
    print("=" * 70)
    print(f"Length: {len(result)} characters")
    print(f"Levels: {levels} (excluding the final /0/0)")

    if copy_to_clipboard(result):
        print("Path copied to clipboard.")
    else:
        print("Could not copy automatically – please copy it yourself.")

def generate_password():
    print("\nSelect service / limit:")
    print("1. SafePal          (max 128 chars, full noise allowed)")
    print("2. Gmail            (max 100 chars, letters/digits/standard specials only)")
    print("3. Coursera         (max 71 chars)")
    print("4. GitHub / General (emojis & noise ok, longer)")
    print("5. Custom length")
    choice = input("Choice (1-5): ").strip()

    if choice == "1":          # SafePal
        max_len = 128
        print("\nSafePal options:")
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
    elif choice == "2":        # Gmail
        max_len = 100
        print("\nGmail rules: no emoji, no invisible characters.")
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=False, allow_invisible=False, allow_space=allow_space, standard_only=True)
    elif choice == "3":        # Coursera
        max_len = 71
        print("\nCoursera options:")
        use_full = input("Use full noise (emoji + invisible)? (y/n): ").strip().lower() == "y"
        if use_full:
            allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
            result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
        else:
            allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
            result = make_password(max_len, allow_emoji=False, allow_invisible=False, allow_space=allow_space, standard_only=True)
    elif choice == "4":        # GitHub / general
        max_len = 200
        print("\nGitHub / general (full noise allowed)")
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=True, allow_invisible=True, allow_space=allow_space)
    else:                      # Custom
        while True:
            try:
                max_len = int(input("Maximum length: ").strip())
                if max_len >= 16:
                    break
                print("Minimum 16 characters recommended.")
            except ValueError:
                print("Enter a number.")
        allow_emoji = input("Allow emojis & scripts? (y/n): ").strip().lower() == "y"
        allow_invisible = input("Allow invisible characters? (y/n): ").strip().lower() == "y"
        allow_space = input("Allow spaces? (y/n): ").strip().lower() == "y"
        result = make_password(max_len, allow_emoji=allow_emoji, allow_invisible=allow_invisible, allow_space=allow_space)

    print("\n" + "=" * 70)
    print("GENERATED PASSWORD / PASSPHRASE")
    print("=" * 70)
    print(result)
    print("=" * 70)
    print(f"Length: {len(result)} characters")

    if copy_to_clipboard(result):
        print("Copied to clipboard.")
    else:
        print("Could not copy automatically – please copy it yourself.")

def main():
    print_header()

    # ---- Optional password-protected extra noise pool (additive) ----
    encrypted_noise = input("Path to encrypted secret noise file (Enter to skip / default secret_noise.age): ").strip() or "secret_noise.age"
    loaded = load_secret_noise(encrypted_noise)
    if loaded:
        print(f"✅ Secret noise pool loaded ({len(loaded)} unique characters). Will be used more frequently.")
    else:
        print("ℹ️  No secret noise pool loaded (file missing, wrong password, or skipped). Using original pools only.")

    while True:
        print("What do you want to generate?")
        print("1. Long custom derivation path (for advanced wallets)")
        print("2. Password / passphrase for SafePal, Gmail, Coursera, GitHub, etc.")
        choice = input("Choice (1/2): ").strip()

        if choice == "1":
            generate_path()
        else:
            generate_password()

        print("\nChecklist:")
        print("  - Save the final result in a password manager")
        print("  - Never store it together with your seed phrase")
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