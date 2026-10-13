# Password Strength Checker & Security Analyser

A command-line tool that analyses how strong a password is, explains what is wrong with it, estimates how long it would take to crack, and suggests improvements. Built in pure Python (no external libraries) with a Windows `.bat` launcher.

## Features

- Strength rating: Very Weak, Weak, Moderate, Strong, Very Strong, with a score out of 100
- Entropy estimate in bits based on length and character variety
- Estimated crack time for an offline attack (10 billion guesses per second)
- Detects common passwords, including leetspeak variants (`p@ssw0rd`)
- Detects repeated characters, sequences (`abc`, `123`), keyboard patterns (`qwerty`) and years
- Optional online breach check using the Have I Been Pwned API
- Secure random password generator
- Hidden password input, and nothing is saved or logged

## Project Structure

```
password-strength-checker/
├── password_checker.py        # Main program
├── run_password_checker.bat   # Windows menu launcher
└── README.md                  # Documentation
```

## Requirements

- Python 3.8 or higher
- No extra packages. Internet is needed only for the optional breach check.

## Usage

### Option 1: Windows launcher

Double-click `run_password_checker.bat` and choose:

1. Check a password
2. Check a password plus online breach check
3. Generate a strong password
4. Exit

### Option 2: Command line

```
python password_checker.py                 # check passwords (hidden input)
python password_checker.py --online        # also check known data breaches
python password_checker.py --show          # show the password while typing
python password_checker.py --generate 20   # generate a 20-character password
```

## Sample Output

```
====================================================
  PASSWORD SECURITY REPORT
====================================================
  Strength : VERY WEAK
  Score    : 8/100  [##----------------------------]
  Entropy  : 7.0 bits
  Crack time (offline, 10 billion guesses/sec): instantly

  Problems found:
   - This is a very common password (or a simple variation)
   - Contains a year, which is easy to guess

  Suggestions:
   * Make it at least 12-16 characters long
   * Avoid dictionary words, names and simple substitutions
====================================================
```

## How It Works

1. **Character pool:** lowercase (26), uppercase (26), digits (10) and symbols (33) are counted for the types present.
2. **Entropy:** `length x log2(pool size)` gives the base strength in bits.
3. **Penalties:** bits are subtracted for common words, repeats, sequences, keyboard walks and years. A common password is capped at 10 bits, and passwords under 8 characters are capped at 30 bits.
4. **Rating:**

| Entropy (bits) | Rating |
|----------------|--------|
| below 28 | Very Weak |
| 28 to 35 | Weak |
| 36 to 59 | Moderate |
| 60 to 79 | Strong |
| 80 and above | Very Strong |

5. **Crack time:** `2^entropy / 10 billion / 2` seconds (average case).
6. **Breach check (optional):** the SHA-1 hash of the password is computed locally and only its first 5 characters are sent to the API (k-anonymity). The full password or hash never leaves your computer.

## Test Cases

| Password | Expected Result |
|----------|-----------------|
| `password` | Very Weak (common password) |
| `P@ssw0rd123` | Very Weak (leetspeak common password) |
| `qwerty123` | Very Weak (keyboard pattern) |
| `Rk7!vQ` | Weak (too short) |
| `Divya2004` | Moderate (name and year) |
| `xK9#mQ2$vL7!pR4z` | Very Strong |
| Empty input | Program exits |

## Limitations

- The common-password list is small (about 60 entries). A real tool would use a list of millions.
- Entropy is an estimate and not a guarantee. Real attackers use dictionaries and patterns.
- Strength is judged on the password only, so it cannot know if you reuse it elsewhere.

## Future Improvements

- Larger wordlist (such as rockyou) loaded from a file
- GUI with Tkinter or a web version with Flask
- Real-time strength meter while typing
- Check passwords against personal info (name, birth year)
- Export the report as PDF

## Technologies Used

Python 3 (`math`, `re`, `secrets`, `hashlib`, `urllib`, `getpass`, `argparse`) and Windows Batch scripting.

## Author

Divya Chaware
B.Tech, Information Technology
Priyadarshini College of Engineering
