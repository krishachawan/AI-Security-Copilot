import secrets


def generate_reset_token():
 return secrets.token_urlsafe(32)


def generate_session_token():
 return secrets.token_hex(32)


def main():
 print(generate_reset_token())
 print(generate_session_token())


if __name__ == "__main__":
 main()
