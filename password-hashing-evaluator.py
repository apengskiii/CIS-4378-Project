"""
Password Hashing Evaluator
CIS 4378 - Spring 2026
Authors: Amir Ibrahim, Arman Briones, Kyle Stressman, Prem Patel

Tests Argon2id, bcrypt, and PBKDF2 by timing how long each hash takes
and estimating how long a brute force attack might take.
"""

import time
import math
import string
import bcrypt
from argon2 import PasswordHasher
from hashlib import pbkdf2_hmac

# password sets split by strength
passwords = {
    "weak": [
        "admin",
        "qwerty",
        "123456789",
        "letmein",
        "password",
    ],
    "medium": [
        "Break123",
        "Philly123",
        "Spring2026",
        "Welcome123",
        "Football123",
    ],
    "strong": [
        "X7#kP!2mQ9",
        "9$mK!vQ2pL",
        "Hy7@wX3!nZ",
        "#Bg5!rT9qW",
        "Tr0ub4dor&3",
    ],
}

# estimate how strong the password is
def estimate_entropy(password):
    # figure out what kind of characters are used
    charset = 0
    if any(c in string.ascii_lowercase for c in password):
        charset += 26
    if any(c in string.ascii_uppercase for c in password):
        charset += 26
    if any(c in string.digits for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += 32

    if charset == 0:
        return 0

    # basic entropy formula
    return int(len(password) * math.log2(charset))


# estimate brute force time based on hash speed and entropy
def estimate_crack_time(hash_time_seconds, entropy_bits):
    # total possible guesses
    keyspace = 2 ** entropy_bits

    # assume attacker is limited by hash speed
    return keyspace * hash_time_seconds


# turn seconds into something readable
def format_time(seconds):
    YEAR = 3.154e7
    years = seconds / YEAR

    if years > 1e12:
        return f"{years / 1e12:,.2f} trillion years"
    elif years > 1e9:
        return f"{years / 1e9:,.2f} billion years"
    elif years > 1e6:
        return f"{years / 1e6:,.2f} million years"
    elif years > 1:
        return f"{years:,.2f} years"
    elif seconds > 3600:
        return f"{seconds / 3600:,.2f} hours"
    elif seconds > 60:
        return f"{seconds / 60:,.2f} minutes"
    else:
        return f"{seconds:,.2f} seconds"


# bcrypt hashing
def hash_bcrypt(password):
    # measure how long it takes
    start = time.time()
    bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    return time.time() - start


# PBKDF2 hashing
def hash_pbkdf2(password):
    # fixed salt just for testing
    salt = b"cis4378_salt"

    start = time.time()
    pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return time.time() - start


# Argon2 hashing
def hash_argon2(password):
    # using common parameters
    ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)

    start = time.time()
    ph.hash(password)
    return time.time() - start


def evaluate():
    print("=" * 70)
    print("  Password Hashing Evaluator — CIS 4378")
    print("=" * 70)

    for tier, pwd_list in passwords.items():
        print(f"\n{'─' * 70}")
        print(f"  Tier: {tier.upper()}")
        print(f"{'─' * 70}")
        print(f"  {'Password':<15} {'Algorithm':<12} {'Hash Time':>10}  {'Estimated Crack Time'}")
        print(f"  {'─'*14} {'─'*11} {'─'*10}  {'─'*30}")

        for pwd in pwd_list:
            entropy = estimate_entropy(pwd)

            argon2_time  = hash_argon2(pwd)
            bcrypt_time  = hash_bcrypt(pwd)
            pbkdf2_time  = hash_pbkdf2(pwd)

            argon2_crack  = format_time(estimate_crack_time(argon2_time, entropy))
            bcrypt_crack  = format_time(estimate_crack_time(bcrypt_time, entropy))
            pbkdf2_crack  = format_time(estimate_crack_time(pbkdf2_time, entropy))

            print(f"  {pwd:<15} {'Argon2id':<12} {argon2_time:>9.3f}s  {argon2_crack}")
            print(f"  {'':<15} {'bcrypt':<12} {bcrypt_time:>9.3f}s  {bcrypt_crack}")
            print(f"  {'':<15} {'PBKDF2':<12} {pbkdf2_time:>9.3f}s  {pbkdf2_crack}")
            print()

    print("=" * 70)
    print("  Evaluation complete.")
    print("=" * 70)


if __name__ == "__main__":
    evaluate()
