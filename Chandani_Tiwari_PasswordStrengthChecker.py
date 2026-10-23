"""
Password Strength Checker
IBM SkillsBuild Cyber Security BootCamp 2026 - Student Project

A command-line tool that gives an educational estimate of password strength.
It does not save, transmit, or log the password entered by the user.
"""

import getpass
import re
import math
import string

# Small educational blocklist. This is not a complete leaked-password database.
COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "12345678",
    "qwerty", "qwerty123", "admin", "letmein", "welcome", "iloveyou",
    "abc123", "111111", "000000", "india123"
}

def has_sequential_pattern(value: str) -> bool:
    """Detect simple ascending/descending runs such as abc, 123, or cba."""
    value = value.lower()
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]
    for sequence in sequences:
        for i in range(len(sequence) - 2):
            part = sequence[i:i + 3]
            if part in value or part[::-1] in value:
                return True
    return False

def estimate_entropy_bits(password: str) -> float:
    """
    Return a rough character-pool entropy estimate.
    This is an educational estimate, not a crack-time guarantee.
    """
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)
    if any(c.isspace() for c in password):
        pool_size += 1
    if not password or pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)

def assess_password(password: str) -> dict:
    """Assess a password and return a score, rating, feedback, and estimate."""
    feedback = []
    score = 0

    length = len(password)
    if length >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters; 12 or more is a better target.")

    if length >= 12:
        score += 1
    else:
        feedback.append("Consider making the password 12 characters or longer.")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add a number.")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Consider adding a symbol (for example, ! or #).")

    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 1)
        feedback.append("This password is on a small common-password blocklist. Choose a unique one.")
    if password and len(set(password)) == 1:
        score = min(score, 1)
        feedback.append("Avoid repeating the same character.")
    if has_sequential_pattern(password):
        score = max(0, score - 1)
        feedback.append("Avoid predictable sequences such as abc or 123.")

    if length < 8:
        rating = "Very Weak"
    elif score <= 2:
        rating = "Weak"
    elif score <= 4:
        rating = "Moderate"
    elif score == 5:
        rating = "Strong"
    else:
        rating = "Very Strong"

    if not feedback:
        feedback.append("Good result. Keep it unique and never reuse it across accounts.")

    return {
        "score": score,
        "maximum_score": 6,
        "rating": rating,
        "length": length,
        "estimated_entropy_bits": round(estimate_entropy_bits(password), 1),
        "feedback": feedback,
    }

def main() -> None:
    print("=" * 48)
    print("         PASSWORD STRENGTH CHECKER")
    print("=" * 48)
    print("Educational checker — your input is not saved.")
    print("Tip: use a long, unique passphrase.")
    print()

    try:
        password = getpass.getpass("Enter a test password (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        print("\nExiting safely.")
        return

    if not password:
        print("No password entered. Please run the program again.")
        return

    result = assess_password(password)
    print("\n--- Assessment ---")
    print(f"Rating: {result['rating']}")
    print(f"Rule score: {result['score']}/{result['maximum_score']}")
    print(f"Length: {result['length']} characters")
    print(f"Rough character-pool entropy estimate: {result['estimated_entropy_bits']} bits")
    print("\nSuggestions:")
    for item in result["feedback"]:
        print(f"- {item}")

    print("\nImportant: this is a simple educational estimate, not a guarantee")
    print("of security or a prediction of how long cracking would take.")

if __name__ == "__main__":
    main()
