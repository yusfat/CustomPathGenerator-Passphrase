#!/usr/bin/env python3
import secrets
import string
import hashlib
import hmac
import subprocess

MAX_INDEX = 2147483647

# Character pools to be used later for adding noise to the custom path index - obfuscation

EXTRA_UNIQUE_EMOJIS = (
    '🧿🪩🪽🫀🫁🫦🫅🐍💻🛜🇸🇨🇷🇪🇷🇴🇷🇸🇷🇺🇷🇼🇸🇦🇸🇧🇸🇻🇸🇾🇺🇳🇿🇦🇾🇪🇽🇰🇼🇸🇼🇫🇻🇳🇭🇹🇺🇸🇺🇾🇹🇼🇹🇹🇹🇨🇹🇨🎺🎷🧶🎙️🎛️🐦⬛🦜🐦🦧🦍🐒🦨🦡🦔🐓🦦🐳🪼🐙🦑🦀🦞🦐🐡🐠🐚🐌🐞🐝🪰🐛🦋🐾🍊🍑🍉🌶️🍅🍎🍒🍓🥕🥭🫛🥒🫐🫘🌰🇹🇲🥞🥩🍗🫔🍕🥗🍡🍤🍣🦞🍬🔪🛟🇹🇳🇹🇴🇺🇬🇸🇲🇸🇪'
    '🫧🫷🫸🪽🦫🦦🦥🦣🦬𓀀𓀁𓀂𓀃𓀄𓀅𓀆𓀇𓀈𓀉𓀊𓀋𓀌𓀍𓀎𓀏'
    '🜁🜂🜃🜄🜅🜆🜇🜈🜉🜊🜋🜌🜍🜎🜏🜐🜑🜒🜓🜔🜕🜖🜗🜘🜙🜚🜛🜜🜝🜞'
)

print("constants and character pools loaded")
