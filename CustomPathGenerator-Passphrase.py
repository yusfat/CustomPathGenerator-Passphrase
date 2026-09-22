#!/usr/bin/env python3
import secrets
import string
import hashlib
import hmac

# hard limit for derivation index
MAX_INDEX = 2147483647

# big pools of characters used for noise later
EXTRA_UNIQUE_EMOJIS = (
    '🧿🪩🪽🫀🫁🫦🫅🐍💻🛜🇸🇨🇷🇪🇷🇴🇷🇸🇷🇺🇷🇼🇸🇦🇸🇧🇸🇰🇸🇻🇸🇾🇺🇳🇿🇦🇾🇪🇺🇬🇺🇦🇹🇲🇹🇨🏴󠁧󠁢󠁳󠁣󠁴󠁿🏴󠁧󠁢󠁷󠁬󠁳󠁿🇽🇰🇼🇸🇼🇫🇻🇳🇭🇹🇺🇸🇺🇾🇹🇼🇹🇹🇹🇨🇹🇨🎺🎷플루мары🧶드럼롱🎙️🎛️슬라이더🐦‍⬛🦜🐦🦧🦍🐒🦨🦡🦔🐓🦦🐳🪼🐙🦑🦀🦞🦐🐡🐠🐚🐌🐞🐝🪰蟑螂蚊子病毒蠕虫🐛🦋蚂蚁蟋蟀🐾🍊🍑🍉🌶️🍅🍎🍒🍓🥕🥭🫛🥒🫐🫘🌰🇹🇲🥞🥩🍗🫔🍕🥗🍡🍤🍣🦞🍬🔪🛟🇹🇳🇹🇴🇺🇬🇸🇲🇸🇪'
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

print("emojis and noise characters loaded successfully"
