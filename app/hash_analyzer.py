# hash_analyzer.py

def identify_hash_type(hash_str):
    if hash_str.startswith("$2b$") or hash_str.startswith("$2a$"):
        return "bcrypt"
    elif len(hash_str) == 32:
        return "MD5"
    elif len(hash_str) == 40:
        return "SHA-1"
    elif len(hash_str) == 64:
        return "SHA-256"
    elif len(hash_str) == 128:
        return "SHA-512"
    elif len(hash_str) == 32 and all(c in "0123456789abcdef" for c in hash_str.lower()):
         return "NTLM"
    else:
        return "Unknown"
