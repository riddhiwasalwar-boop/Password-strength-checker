"""
Password Strength Checker & Security Analyser
---------------------------------------------
Analyses a password and reports its strength, weaknesses, estimated
crack time and suggestions. Uses only the Python standard library.

Checks performed
  * length and character variety (lowercase, uppercase, digits, symbols)
  * entropy estimate (bits) with penalties for weak patterns
  * common-password check (including leetspeak such as p@ssw0rd)
  * repeated characters, sequences (abc, 123), keyboard walks (qwerty)
  * years / date-like patterns
  * optional online breach check (Have I Been Pwned, k-anonymity:
    only the first 5 characters of the SHA-1 hash leave your computer)

Usage
  python password_checker.py                 interactive check (hidden input)
  python password_checker.py --online        also check known data breaches
  python password_checker.py --generate 16   generate a strong password
  python password_checker.py --show          show the password while typing

The password is never saved, logged or written to disk.
"""

import argparse
import getpass
import hashlib
import math
import re
import secrets
import string
import sys
import urllib.request

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "password1", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "iloveyou", "login",
    "master", "sunshine", "princess", "football", "baseball", "shadow",
    "superman", "batman", "trustno1", "000000", "qwerty123", "1q2w3e4r",
    "passw0rd", "admin123", "root", "toor", "test", "guest", "hello",
    "freedom", "whatever", "qazwsx", "zaq12wsx", "starwars", "michael",
    "jordan", "hunter", "ranger", "buster", "soccer", "hockey", "killer",
    "secret", "changeme", "default", "india123", "krishna", "ganesh",
    "pass", "pass123", "welcome1", "access", "flower", "cricket",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "0": "o",
                      "$": "s", "5": "s", "7": "t", "!": "i", "+": "t"})
CRACK_RATE = 1e10  # guesses/second: offline attack on a fast hash with GPUs
SYMBOLS = string.punctuation


def analyse_charset(pw):
    has = {
        "lowercase": any(c.islower() for c in pw),
        "uppercase": any(c.isupper() for c in pw),
        "digits": any(c.isdigit() for c in pw),
        "symbols": any(c in SYMBOLS or (not c.isalnum() and not c.isspace())
                       for c in pw),
    }
    pool = 0
    pool += 26 if has["lowercase"] else 0
    pool += 26 if has["uppercase"] else 0
    pool += 10 if has["digits"] else 0
    pool += 33 if has["symbols"] else 0
    return has, max(pool, 1)


def find_sequences(pw):
    """Runs of 3+ characters going up or down by one (abc, 321)."""
    s, found, i = pw.lower(), [], 0
    while i < len(s) - 2:
        d = ord(s[i + 1]) - ord(s[i])
        if d in (1, -1) and s[i].isalnum():
            j = i + 1
            while j < len(s) and ord(s[j]) - ord(s[j - 1]) == d and s[j].isalnum():
                j += 1
            if j - i >= 3:
                found.append(s[i:j])
                i = j
                continue
        i += 1
    return found


def find_keyboard_walks(pw):
    s, found = pw.lower(), []
    for row in KEYBOARD_ROWS:
        for r in (row, row[::-1]):
            for n in range(len(r) - 3):
                chunk = r[n:n + 4]
                if chunk in s and chunk not in found:
                    found.append(chunk)
    return found


def find_repeats(pw):
    return [m.group(0) for m in re.finditer(r"(.)\1{2,}", pw)]


def is_common(pw):
    low = pw.lower()
    base = re.sub(r"[\d\W_]+$", "", low)  # drop trailing digits/symbols
    candidates = {low, low.translate(LEET), base, base.translate(LEET)}
    return any(c in COMMON_PASSWORDS for c in candidates)


def contains_common_word(pw):
    plain = pw.lower().translate(LEET)
    return [w for w in COMMON_PASSWORDS
            if len(w) >= 4 and not w.isdigit() and w in plain][:3]


def format_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("year", 31557600), ("day", 86400), ("hour", 3600),
             ("minute", 60), ("second", 1)]
    if seconds >= 31557600 * 1e9:
        return "billions of years or more"
    for name, size in units:
        if seconds >= size:
            n = seconds / size
            if n >= 1e6 and name == "year":
                return f"{n:,.2e} years"
            return f"{n:,.0f} {name}{'s' if round(n) != 1 else ''}"
    return "instantly"


def breach_count(pw):
    """Have I Been Pwned range API (k-anonymity). Returns count or None."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "password-strength-checker-student-project"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read().decode("utf-8")
    except Exception:
        return None
    for line in body.splitlines():
        h, _, count = line.partition(":")
        if h.strip() == suffix:
            return int(count)
    return 0


def analyse(pw):
    has, pool = analyse_charset(pw)
    entropy = len(pw) * math.log2(pool)
    issues, good = [], []

    if len(pw) >= 12:
        good.append(f"Good length ({len(pw)} characters)")
    elif len(pw) < 8:
        issues.append(f"Too short ({len(pw)} characters), use at least 12")
    else:
        issues.append(f"Fairly short ({len(pw)} characters), use at least 12")

    kinds = sum(has.values())
    if kinds == 4:
        good.append("Uses lowercase, uppercase, digits and symbols")
    else:
        missing = [k for k, v in has.items() if not v]
        issues.append("Missing character types: " + ", ".join(missing))

    penalty = 0
    if is_common(pw):
        issues.append("This is a very common password (or a simple variation)")
        entropy = min(entropy, 10)
    else:
        words = contains_common_word(pw)
        if words:
            issues.append("Contains a common word: " + ", ".join(words))
            penalty += 8
    rep = find_repeats(pw)
    if rep:
        issues.append("Repeated characters: " + ", ".join(rep))
        penalty += 4 * len(rep)
    seq = find_sequences(pw)
    if seq:
        issues.append("Sequences found: " + ", ".join(seq))
        penalty += 4 * len(seq)
    walk = find_keyboard_walks(pw)
    if walk:
        issues.append("Keyboard patterns found: " + ", ".join(walk))
        penalty += 6 * len(walk)
    if re.search(r"(19|20)\d{2}", pw):
        issues.append("Contains a year, which is easy to guess")
        penalty += 3
    if len(set(pw)) <= len(pw) / 2:
        issues.append("Many repeated characters, low variety")
        penalty += 4

    entropy = max(entropy - penalty, 0)
    if len(pw) < 8:
        entropy = min(entropy, 30)  # very short passwords are never rated well
    score = int(min(entropy / 80, 1) * 100)
    if entropy < 28:
        level = "VERY WEAK"
    elif entropy < 36:
        level = "WEAK"
    elif entropy < 60:
        level = "MODERATE"
    elif entropy < 80:
        level = "STRONG"
    else:
        level = "VERY STRONG"

    seconds = (2 ** entropy) / CRACK_RATE / 2  # average case: half the space
    suggestions = []
    if len(pw) < 12:
        suggestions.append("Make it at least 12-16 characters long")
    if kinds < 4:
        suggestions.append("Mix uppercase, lowercase, numbers and symbols")
    if issues and any("common" in i.lower() for i in issues):
        suggestions.append("Avoid dictionary words, names and simple substitutions like @ for a")
    if rep or seq or walk:
        suggestions.append("Avoid repeats, sequences (abc, 123) and keyboard patterns")
    suggestions.append("Consider a passphrase of 4+ random words, or use a password manager")
    suggestions.append("Never reuse the same password on multiple sites")

    return {"length": len(pw), "pool": pool, "entropy": entropy, "score": score,
            "level": level, "crack_time": format_time(seconds),
            "good": good, "issues": issues, "suggestions": suggestions, "has": has}


def generate_password(length=16):
    length = max(length, 8)
    sets = [string.ascii_lowercase, string.ascii_uppercase,
            string.digits, "!@#$%^&*()-_=+?"]
    chars = [secrets.choice(s) for s in sets]
    allc = "".join(sets)
    chars += [secrets.choice(allc) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def print_report(r, breaches="skip"):
    bar_len = 30
    filled = int(r["score"] / 100 * bar_len)
    print("\n" + "=" * 52)
    print("  PASSWORD SECURITY REPORT")
    print("=" * 52)
    print(f"  Strength : {r['level']}")
    print(f"  Score    : {r['score']}/100  [{'#' * filled}{'-' * (bar_len - filled)}]")
    print(f"  Entropy  : {r['entropy']:.1f} bits (character pool: {r['pool']})")
    print(f"  Length   : {r['length']}")
    print(f"  Crack time (offline, 10 billion guesses/sec): {r['crack_time']}")
    if breaches != "skip":
        if breaches is None:
            print("  Breach check: could not connect (check internet)")
        elif breaches == 0:
            print("  Breach check: NOT found in known data breaches")
        else:
            print(f"  Breach check: FOUND in {breaches:,} known breaches! Do not use it.")
    if r["good"]:
        print("\n  What is good:")
        for g in r["good"]:
            print("   + " + g)
    if r["issues"]:
        print("\n  Problems found:")
        for i in r["issues"]:
            print("   - " + i)
    print("\n  Suggestions:")
    for s in r["suggestions"]:
        print("   * " + s)
    print("=" * 52 + "\n")


def main():
    p = argparse.ArgumentParser(description="Password strength checker")
    p.add_argument("--online", action="store_true",
                   help="check Have I Been Pwned (sends only a partial hash)")
    p.add_argument("--generate", nargs="?", const=16, type=int, metavar="LEN",
                   help="generate a strong random password (default 16)")
    p.add_argument("--show", action="store_true", help="show password while typing")
    args = p.parse_args()

    if args.generate is not None:
        pw = generate_password(args.generate)
        print("Generated password:", pw)
        print_report(analyse(pw))
        return

    reader = input if args.show else getpass.getpass
    while True:
        pw = reader("Enter a password to check (blank to quit): ")
        if not pw:
            break
        result = analyse(pw)
        b = breach_count(pw) if args.online else "skip"
        print_report(result, b)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)
