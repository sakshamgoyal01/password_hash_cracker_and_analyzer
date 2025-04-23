# hash_cracker.py

import hashlib
import bcrypt
import itertools
import string

# === Wordlist-based Crackers ===

def crack_md5(hash_to_crack, wordlist_path):
    with open(wordlist_path, 'r', encoding='latin-1') as file:
        for word in file:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
                return word
    return None

def crack_sha1(hash_to_crack, wordlist_path):
    with open(wordlist_path, 'r', encoding='latin-1') as file:
        for word in file:
            word = word.strip()
            if hashlib.sha1(word.encode()).hexdigest() == hash_to_crack:
                return word
    return None

def crack_ntlm(hash_to_crack, wordlist_path):
    with open(wordlist_path, 'r', encoding='latin-1') as file:
        for word in file:
            word = word.strip()
            hashed = hashlib.new('md4', word.encode('utf-16le')).hexdigest()
            if hashed.lower() == hash_to_crack.lower():
                return word
    return None

def crack_sha512(hash_to_crack, wordlist_path):
    with open(wordlist_path, 'r', encoding='latin-1') as file:
        for word in file:
            word = word.strip()
            if hashlib.sha512(word.encode()).hexdigest() == hash_to_crack:
                return word
    return None

def crack_sha256(hash_to_crack, wordlist_path):
    with open(wordlist_path, 'r', encoding='latin-1') as file:
        for word in file:
            word = word.strip()
            if hashlib.sha256(word.encode()).hexdigest() == hash_to_crack:
                return word
    return None

def crack_bcrypt(hash_to_crack, wordlist_path):
    try:
        with open(wordlist_path, 'r', encoding='latin-1') as file:
            for word in file:
                word = word.strip()
                try:
                    # Check password using bcrypt's checkpw
                    if bcrypt.checkpw(word.encode(), hash_to_crack.encode()):
                        return word
                except Exception as e:
                    # Handle invalid bcrypt formats gracefully
                    continue
    except Exception as e:
        print(f"Error reading wordlist: {e}")
    return None

# === Brute-force Fallback (up to 4 characters) ===

def brute_force_crack(hash_to_crack, hash_type, max_length=10):
    # Add special characters to the charset
    charset = string.ascii_letters + string.digits + "@#$%^!&*()_+=-\"':;<,>.?/|\\"

    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            password = ''.join(attempt)
            if hash_type == "MD5":
                if hashlib.md5(password.encode()).hexdigest() == hash_to_crack:
                    return password
            elif hash_type == "SHA-1":
                if hashlib.sha1(password.encode()).hexdigest() == hash_to_crack:
                    return password
            elif hash_type == "SHA-256":
                if hashlib.sha256(password.encode()).hexdigest() == hash_to_crack:
                    return password
            elif hash_type == "SHA-512":
                if hashlib.sha512(password.encode()).hexdigest() == hash_to_crack:
                    return password
            elif hash_type == "NTLM":
                ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
                if ntlm_hash.lower() == hash_to_crack.lower():
                    return password
            elif hash_type == "bcrypt":
                if bcrypt.checkpw(password.encode(), hash_to_crack.encode()):
                    return password
    return None