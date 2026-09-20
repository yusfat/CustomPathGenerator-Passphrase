#!/usr/bin/env python3
import secrets
import string
import hashlib
import hmac

# == 
# KISS IPO SUMMARY (what i intend to acheive 
# ======
# Input:
# - noise introduction in a way that already tested crypto wallets would no return "invalid " index e.g token pocket & airgapvault.io ( here's it:     I manually created and tested with emojis, non ASCII characters and noises in October 2024 but with a very small sample such as m/243😭'/50🔑9'/72🚢'/2032710863🐯📁📱👇🙏🧐&#$7√'/75⛵90'/365xyz0' which was tested and confirmed to create the same crypto wallet as m/243'/50'/72'/2032710863'/75'/365'
# ---------------
#
# This custom derivation path with emojis and noises and characters/alphabets:
#
# m/243😭'/50🔑9'/72🚢'/2032710863🐯📁📱👇🙏🧐&#$7√'/75⛵90'/365xyz0'
#
# vs
#
# a tested cleaned version:
#
# m/243'/50'/72'/2032710863'/75'/365'
#      ) - both landed me in the same wallet address (  0x5673170D4cBd2Ca8b186900EE731d38E84E7e5C8 ) after tweaking the alphabets, characters, and digits that later let to the discovery behind this project 
#   - User mode (Beginner / Advanced)
#   - Desired part length (minimum 2000 characters)
#   - Optional personal salt or multi-layer salt chaining (Advanced mode only)
#
# Process:
# users are meant to be asked their crypto experience before generating path that suits their need due to risk of custom path & fund lost if forgotten 
#   - Build a deep, non-standard BIP32-style derivation path (m/...) - as above
#   - Use cryptographically secure randomness (or deterministic HMAC-SHA256 when salted)
#   - Inject heavy character noise (emojis, invisible Unicode, multi-script chars, spaces)
#   - Support pure-random (Beginner) and salted / multi-layer key-stretching (Advanced)
#   - Keep every step modular and limited to Sequence → Selection → Repetition
#
# Pseudocode (simple lagic):
#   1. Ask mode (b/a) and desired part length (>=2000)
#   2. If Advanced → optionally collect salt or do multi-layer salt chaining
#   3. Create final_salt (or pure random if none)
#   4. Generate path:
#        start with "m"
#        loop many levels (220+)
#            generate index (hardened or not)
#            if later levels → add heavy noise (emoji/invisible/script/space)
#        add final "0'/0"
#        trim if longer than target length
#   5. Print the final part and try to copy to clipboard
#   6. Show warnings
#
# Expected Output:
#   - One ultra-long custom derivation path (≥ 2000 characters)
#   - Auto-copied to clipboard when possible
#   - Clear warnings: advanced users only • test with small amount first • save only the final path
#
# This is the entire program reduced to the simplest reliabl lagic.
# =====
