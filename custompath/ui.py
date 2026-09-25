# ====================== custompath/ui.py ======================
from .sanitizer import sanitize_input
from .crypto import multi_layer_salt

def get_user_choices():
    print("\n1. Pure Random (Beginner)")
    print("2. Personal Salt")
    print("3. Multi-layer Salt Chaining (Recommended)")

    choice = input("\nChoose option (1/2/3): ").strip()
    final_salt = ""

    if choice == "2":
        final_salt = sanitize_input(input("Enter your personal salt: "))
    elif choice == "3":
        base = sanitize_input(input("Enter base salt: "))
        layers = int(input("Number of layers (8-11 recommended): ") or 8)
        final_salt = multi_layer_salt(base, layers=layers)

    target_len = int(input("Target length (default 2000): ") or 2000)
    return final_salt, target_len