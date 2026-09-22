#!/usr/bin/env python3
import secrets
import string
import hashlib
import hmac

# hard limit for derivation index
MAX_INDEX = 2147483647

# big pools of characters used for noise later
EXTRA_UNIQUE_EMOJIS = (
    '🧿🪩🪽🫀🫁🫦🫅🐍💻🛜🇸🇨🇷🇪🇷🇴🇷🇸🇷🇺🇷🇼🇸🇦🇸🇧🇸🇰🇸🇻🇸🇾🇺🇳🇿🇦🇾🇪🇺🇬🧿🪩🪽🫀🫁🫦🫅🐍💻🛜🇸🇨🇷🇪🇷🇴🇷🇸🇷🇺🇷🇼🇸🇦🇸🇧🇸🇰🇸🇻🇸🇾🇺🇳🇿🇦🇾🇪🇺🇬🇺🇦🇹🇲🇹🇨🏴󠁧󠁢󠁳󠁣󠁴󠁿🏴󠁧󠁢󠁷󠁬󠁳󠁿🇽🇰🇼🇸🇼🇫🇻🇳🇻🇺🇺🇸🇺🇾🇹🇼🇹🇹🇹🇨🇹🇨🎺🎷플루мары🧶드럼롱🎙️🎛️슬라이더🐦‍⬛🦜🐦🦧🦍🐒🦨🦡🦔🐓🦦🐳🪼🐙🦑🦀🦞🦐🐡🐠🐚🐌🐞🐝🪰🇺🇦🇹🇲🇹🇨🏴󠁧󠁢󠁳󠁣󠁴󠁿🏴󠁧󠁢󠁷󠁬󠁳󠁿🇽🇰🇼🇸🇼🇫🇻🇳🇻🇺🇺🇸🇺🇾🇹🇼🇹🇹🇹🇨🇹🇨🎺🎷'
)

print(emojis loaded successfully)
