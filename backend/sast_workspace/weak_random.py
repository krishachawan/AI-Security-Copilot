import random


def generate_reset_token():
    token = random.randint(100000, 999999)
    return str(token)


def create_session_id():
    return str(random.randint(1000000000, 9999999999))
