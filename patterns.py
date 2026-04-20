import re

KEYBOARD_WALKS = [
    "qwerty", "qwert", "asdf", "asdfg", "zxcv", "zxcvb",
    "12345", "123456", "1234567", "654321"
]

LEET_MAP = {
    '4': 'a', '@': 'a',
    '3': 'e',
    '1': 'i', '!': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't',
}

def detect_keyboard_walk(password):
    pwd_lower = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in pwd_lower:
            return True, walk
    return False, None

def detect_date_pattern(password):
    patterns = [
        r'\d{4}[/-]\d{1,2}[/-]\d{1,2}',
        r'\d{1,2}[/-]\d{1,2}[/-]\d{4}',
        r'\d{8}',
        r'(19|20)\d{2}',
    ]
    for p in patterns:
        if re.search(p, password):
            return True
    return False

def detect_leet(password):
    normalized = ""
    for ch in password.lower():
        normalized += LEET_MAP.get(ch, ch)
    common_words = ["password", "admin", "letmein", "welcome", "login"]
    for word in common_words:
        if word in normalized:
            return True, normalized
    return False, normalized

def detect_all_patterns(password):
    kw_found, kw_match = detect_keyboard_walk(password)
    date_found = detect_date_pattern(password)
    leet_found, leet_normalized = detect_leet(password)
    return {
        "keyboard_walk": {"detected": kw_found, "match": kw_match},
        "date_pattern": {"detected": date_found},
        "leet_speak": {"detected": leet_found, "normalized": leet_normalized},
    }