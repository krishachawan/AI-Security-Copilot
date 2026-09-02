import hashlib
import os


def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt.hex(), password_hash.hex()


def main():
    salt, password_hash = hash_password('example-password')
    print(salt)
    print(password_hash)


if __name__ == '__main__':
    main()
