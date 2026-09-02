import hashlib


def hash_password(password):
    password_bytes = password.encode("utf-8")
    password_hash = hashlib.md5(password_bytes).hexdigest()
    return password_hash


def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash
