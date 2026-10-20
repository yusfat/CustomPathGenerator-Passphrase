# ====================== main.py ======================
from custompath.crypto import make_system_salt, make_random_salt
from custompath.generator import make_path
import subprocess
import hashlib

def copy_text(text: str) -> bool:
    try:
        subprocess.run(['termux-clipboard-set', text], check=True)
        return True
    except Exception:
        return False


def main():
    print("🌼At least - 200 Levels Deep Non-Standard For Advanced User💥🌼")
    print("[A 2-IN-1 ADVANCED USER CUSTOM DERIVATION PATH/PASSPHRASE GENERATOR]")

    print("[WARNING] For advanced users only. Standard paths recommended for beginners.")
    print("WARNING: This tool is for ADVANCED CRYPTO USERS ONLY.")
    print("BEGINNERS SHOULD USE EXISTING STANDARD DERIVATION PATHS.")
    print("🛑 STOP NOW IF YOU DON'T UNDERSTAND WHAT YOU'RE DOING.")
    print("YOU'RE USING THIS AT YOUR OWN RISK DUE TO LOST OF FUND/CRYPTO.")

    print("[SECURITY] Test recovery with only $1 before funding and ensure")
    print("full recoverability by storing in strong password manager.")

    print("⭕Always test with a small amount ($1) first and make sure")
    print("you can fully recover the wallet before using real funds.")

    print("[SUPPORT1] Wallets: AirGap Vault (www.airgapvault.io) &")
    print("TokenPocket (As BOTH CUSTOM PATH + PASSPHRASE support - Tested)")
    print("[SUPPORT2] Wallets: Bluewallet, Electrum (ONLY as passphrase support - Also Tested)")

    print("Other services such as Amazon, Coursera etc. that accept emojis in password shall be updated for users to generate secure, unpredictable passwords, later")

    print("[STORAGE] Store final output only in Bitwarden/KeePass or any secure & reputable password manager but not together with seedphrase. Do not expose intermediate salts.\n")

    
    print("Only save the FINAL output in Bitwarden / KeePass / etc.")
    print("Never share or memorize intermediate salts.")
    print("🔑🌼== Let's Begin To Ensure Reduction in Stolen Crypto==💥🌼")

    
    while True:
        print("\n" + "="*10)
        mode = input("Are you a Beginner or Advanced user? (b/a): ").strip().lower()

        while True:
            try:
                target_len = int(input("Enter desired path length (minimum 2000; maximum of 2150 due to bitwarden storage): "))
                if 2000 <= target_len <= 2150:
                    break
                print("Must be at least 2000 characters.")
            except ValueError:
                print("Please enter a number.")

        final_salt = ""
        system_salt_bytes, system_salt_hex = make_system_salt()

        if mode == 'a':
            print("\n--- ADVANCED MODE ---")
            print("1. Pure random (no personal salt)")
            print("2. Single personal salt (deterministic)")
            print("3. Salt chaining / key stretching - non-deterministic on purpose & doesn't require storing internal salts (strongest)")
            choice = input("Choose option (1/2/3): ").strip()

            if choice == '3':
                layers = 0
                current = ""
                print("\nSalt chaining activated (recommended 5–7 layers)")
                while layers < 7:
                    print(f"\n--- Layer {layers+1} ---")
                    gen = input("Generate a strong random salt for this layer? (y/n): ").strip().lower()
                    if gen == 'y':
                        current = make_random_salt()
                        print("Strong random salt generated and applied internally (not shown).")
                    else:
                        current = input("Paste your salt for this layer (≥50 chars): ").strip()
                        if len(current) < 50:
                            print("Salt too short! Minimum 50 characters.")
                            continue
                    if layers == 0:
                        final_salt = current
                    else:
                        final_salt = hashlib.sha3_512((final_salt + current).encode()).hexdigest() + current
                    layers += 1
                    more = input("Add another layer? (y/n): ").strip().lower()
                    if more != 'y':
                        break
                print(f"\nFinal chained salt created with {layers} layers.")
            elif choice == '2':
                final_salt = input("Enter your personal secret salt (≥50 chars): ").strip()
                if len(final_salt) < 50:
                    print("Salt too short. Using pure random instead.")
                    final_salt = ""
            else:
                final_salt = ""
        else:
            print("\n--- BEGINNER MODE ---")
            print("Using pure random (safest simple option)")
            final_salt = ""

        combined = final_salt + system_salt_hex if final_salt else system_salt_hex

        print("\nGenerating a secure 🔐 derivation path/passphrase...")
        result = make_path(combined, target_len)

        print("\n" + "="*2)
        print("DERIVATION PATH:")
        print(result)
        print("="*2)
        print(f"Length: {len(result)} characters")

        if copy_text(result):
            print("✅ Final path copied to clipboard!")
        else:
            print("⚠️  Please copy the path manually.")

        print("\n" + "-"*5)
        print("SECURITY: HOW TO USE THIS OUTPUT")
        print("-"*5)
        print("Option A: Use this SAME output as BOTH derivation path AND passphrase")
        print("Option B: For BETTER security, generate a SEPARATE passphrase")
        print("Option C:For MAXIMUM security, generate a ANOTHER derivation path AND use it as passphrase")
        print("WARNING: If you lose either the path OR passphrase, funds are LOST FOREVER.")
        print("- END")

        pp_choice = input("\nGenerate a separate passphrase too? (y/n): ").strip().lower()
        if pp_choice == 'y':
            passphrase = make_random_salt(min_len=80, max_len=200)
            print("\n" + "="*3)
            print("SEPARATE PASSPHRASE:")
            print(passphrase)
            print("="*2)
            if copy_text(passphrase):
                print("✅ Passphrase copied to clipboard!")
            else:
                print("⚠️  Please copy the passphrase manually. NOTE: YOU CAN USE IT AS PASSPHRASE (13th or 25th word on top your mnemonic seedphrase) IF U WISH; IT'S BEEN TESTED TO WORK. YOU CAN TEST IT TOO.")

        print("\nIMPORTANT FINAL CHECKLIST:")
        print("• Save ONLY the FINAL path and passphrase in Bitwarden / KeePass / 1Password")
        print("• Test recovery with $1 first on AirGap Vault / TokenPocket")
        print("• Never share intermediate salts")

        again = input("\nGenerate another path? (y/n): ").strip().lower()
        if again != 'y':
            print("Stay safe.")
            break

if __name__ == "__main__":
    main()