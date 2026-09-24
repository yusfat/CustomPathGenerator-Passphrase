#!/usr/bin/env python3
import secrets, string, subprocess, hashlib, hmac, time

print("🔑🌼1st - 200 Level💥🌼")
print("Worked ADVANCED 200 LEVEL CUSTOM DERIVATION PATH GENERATOR")
print("🔑🌼1st - 200 Level💥🌼")
print("WARNING: This tool is for ADVANCED crypto users only.")
print("Beginners should use standard derivation paths.")
print("Always test with a small amount ($1) first and make sure")
print("you can fully recover the wallet before using real funds.")
print("TESTED: Recommended wallets that support very long custom paths + passphrase BUT use this tool with caution:")
print("AirGap Vault  |  TokenPocket")
print("Only save the FINAL output in Bitwarden / KeePass (tested) etc.")
print("Never share or memorize intermediate salts.")
print("🔑🌼1st - 200 Level💥🌼")

MAX_INDEX = 2147483647

# Character pools to be used later for adding noise to the custom path index - obfuscation

EXTRA_UNIQUE_EMOJIS = (
    '🧿🪩🪽🫀🫁🫦🫅🐍💻🛜🇸🇨🇷🇪🇷🇴🇷🇸🇷🇺🇷🇼🇸🇦🇸🇧🇸🇻🇸🇾🇺🇳🇿🇦🇾🇪🇽🇰🇼🇸🇼🇫🇻🇳🇭🇹🇺🇸🇺🇾🇹🇼🇹🇹🇹🇨🇹🇨🎺🎷🧶🎙️🎛️🐦⬛🦜🐦🦧🦍🐒🦨🦡🦔🐓🦦🐳🪼🐙🦑🦀🦞🦐🐡🐠🐚🐌🐞🐝🪰🐛🦋🐾🍊🍑🍉🌶️🍅🍎🍒🍓🥕🥭🫛🥒🫐🫘🌰🇹🇲🥞🥩🍗🫔🍕🥗🍡🍤🍣🦞🍬🔪🛟🇹🇳🇹🇴🇺🇬🇸🇲🇸🇪'
    '🫧🫷🫸🪽🦫🦦🦥🦣🦬𓀀𓀁𓀂𓀃𓀄𓀅𓀆𓀇𓀈𓀉𓀊𓀋𓀌𓀍𓀎𓀏'
    '🜁🜂🜃🜄🜅🜆🜇🜈🜉🜊🜋🜌🜍🜎🜏🜐🜑🜒🜓🜔🜕🜖🜗🜘🜙🜚🜛🜜🜝🜞'
)

INVISIBLES = [
    '\u200b', '\u200c', '\u200d', '\u2060', '\u2061', '\u2062', '\u2063',
    '\u2064', '\ufeff', '\u180e', '\u00ad', '\u034f', '\u061c',
    '\u115f', '\u1160', '\u17b4', '\u17b5', '\u3164',
    '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
]

SPACES = [' ', '  ', '   ', '\t', '\u00a0', '\u2000', '\u2001', '\u2002',
          '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008',
          '\u2009', '\u200a', '\u202f', '\u205f']

EMOJI_POOL = (
    '🎉🚀🌈🍕🌟🐶🐱🏠📚💻🎊🍔🐻🎤sneeze🌪熊猫电影棕榈海滩鸡车跳舞向日葵猪礼物手机自行车青蛙'
    '🌺公园戏剧薯条握手雏菊马玫瑰龙电影电视西装玉米奖杯靶子施工流星鲸鱼南瓜拉面疯狂门火山鲸鱼圣诞巧克力安静香烟银河鱼'
    '圣诞老人棒棒糖流口水禁烟地球海豚烟花汤说谎旗帜时钟龙控制台竹子风铃墨镜蛛网多云青蛙摩天轮毕业游戏手柄下雨仓鼠过山车勋章兴奋厕所太阳兔子'
    '竹子淋浴狼钓鱼怀疑鼻子电影院安静风拥抱胡子盆栽派对亲吻病毒热老虎老虎玫瑰融化攀爬僵尸鸟火水雪电月亮星'
)

SCRIPTS = (
    'عربيአማርኛქართულიΕλληνικάગુજરાતીעבריתहिंदी日本語ಕನ್ನಡҚазақша'
    'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя'
    'αβγδεζηθικλμνξοπρστυφχψωΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ'
    'ℵθΩψΔкѲζσxw۝۞¶§†‡•€¥£¢°™®©√π∫∆∇≠≤≥±×÷≈∞'
    'あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん'
    'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン'
    '一二三四五六七八九十百千万亿ワヤ二ヴヶ'
    'אבגדהוזחטיכלמנסעפצקרשת'
)


BANNED = {'/', '\\', '"', "'"}
SAFE_PUNCT = ''.join(c for c in string.punctuation if c not in BANNED)
ASCII_NOISE = string.ascii_letters + string.digits + SAFE_PUNCT

def generate_strong_salt(min_len=60, max_len=180):
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    chars = ASCII_NOISE + EMOJI_POOL + EXTRA_UNIQUE_EMOJIS + ''.join(SCRIPTS) + ''.join(INVISIBLES)
    return ''.join(secrets.choice(chars) for _ in range(length))

def secure_choice(seq, salt_bytes, counter):
    h = hmac.new(salt_bytes, str(counter).encode(), hashlib.sha256).digest()
    return seq[int.from_bytes(h[:8], 'big') % len(seq)]

def random_noise_heavy(salt_bytes, counter, min_len=12, max_len=55):
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    parts = []
    for _ in range(length):
        r = int.from_bytes(hmac.new(salt_bytes, f"n{counter}".encode(), hashlib.sha256).digest()[:1], 'big') % 100
        counter += 1
        if r < 15:
            parts.append(secure_choice(INVISIBLES, salt_bytes, counter))
        elif r < 28:
            parts.append(secure_choice(SPACES, salt_bytes, counter))
        elif r < 43:
            parts.append(secure_choice(EMOJI_POOL, salt_bytes, counter))
        elif r < 58:
            parts.append(secure_choice(EXTRA_UNIQUE_EMOJIS, salt_bytes, counter))
        elif r < 78:
            parts.append(secure_choice(SCRIPTS, salt_bytes, counter))
        else:
            parts.append(secure_choice(ASCII_NOISE, salt_bytes, counter))
        counter += 1
    return ''.join(parts), counter

def random_index(salt_bytes, counter):
    h = hmac.new(salt_bytes, f"i{counter}".encode(), hashlib.sha256).digest()
    digits = (int.from_bytes(h[:1], 'big') % 10) + 1
    if digits == 1:
        return str(int.from_bytes(h[1:2], 'big') % 10), counter + 1
    max_val = min(10**digits - 1, MAX_INDEX)
    val = int.from_bytes(h[1:9], 'big') % (max_val + 1)
    return str(val), counter + 1

def generate_path(final_salt: str, target_len: int):
    salt_bytes = hashlib.sha256(final_salt.encode('utf-8')).digest()
    levels = secrets.randbelow(80) + 220
    parts = ['m']
    counter = 0

    for i in range(levels):
        idx, counter = random_index(salt_bytes, counter)
        if i < 200:
            parts.append(idx + "'")
        else:
            if secrets.randbelow(100) < 75:
                segment = idx + "'"
            else:
                segment = idx
            noise, counter = random_noise_heavy(salt_bytes, counter)
            parts.append(segment + noise)

    parts.append("0")
    parts.append("0")
    path = '/'.join(parts)

    if len(path) > target_len:
        path = path[:target_len]
        if not path.endswith("/0"):
            path = path.rstrip("/") + "/0/0"
    return path

while True:
    print("\n" + "="*50)
    mode = input("Are you a Beginner or Advanced user? (b/a): ").strip().lower()

    while True:
        try:
            target_len = int(input("Enter desired path length (minimum 2000): "))
            if target_len >= 2000:
                break
            print("Must be at least 2000 characters.")
        except:
            print("Please enter a number.")

    final_salt = ""

    if mode == 'a':
        print("\n--- ADVANCED MODE ---")
        print("1. Pure random (no salt)")
        print("2. Single personal salt (deterministic)")
        print("3. Salt chaining / key stretching (strongest)")
        choice = input("Choose option (1/2/3): ").strip()

        if choice == '3':
            layers = 0
            current = ""
            print("\nSalt chaining activated (recommended 8–11 layers)")
            while layers < 11:
                print(f"\n--- Layer {layers+1} ---")
                gen = input("Generate a strong random salt for this layer? (y/n): ").strip().lower()
                if gen == 'y':
                    current = generate_strong_salt()
                    print("Generated salt (save only if you want):")
                    print(current[:80] + "...")
                else:
                    current = input("Paste your salt for this layer (≥50 chars): ").strip()
                    if len(current) < 50:
                        print("Salt too short! Minimum 50 characters.")
                        continue
                if layers == 0:
                    final_salt = current
                else:
                    final_salt = hashlib.sha256((final_salt + current).encode()).hexdigest() + current
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

    print("\nGenerating secure derivation path...")
    result = generate_path(final_salt if final_salt else secrets.token_hex(32), target_len)

    print("\n" + "="*60)
    print(result)
    print("="*60)
    print(f"Length: {len(result)} characters")

    try:
        subprocess.run(['termux-clipboard-set', result], check=True)
        print("✅ Final path copied to clipboard!")
    except:
        print("⚠️  Please copy the path manually.")

    print("\nIMPORTANT:")
    print("• Save ONLY this final path in your password manager")
    print("• Test recovery with $1 first")
    print("• Never share intermediate salts")

    again = input("\nGenerate another path? (y/n): ").strip().lower()
    if again != 'y':
        print("Stay safe.")
        break
