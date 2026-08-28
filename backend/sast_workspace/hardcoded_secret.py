import hashlib
import logging
from pathlib import Path

DATABASE_HOST = "db.internal.example.com"
DATABASE_USER = "application_user"
DATABASE_PASSWORD = "SuperSecretPassword123!"
API_KEY = "sk_live_51N0TAREALKEY123456789"
JWT_SECRET = "my-production-jwt-secret-key"
ENCRYPTION_KEY = "1234567890abcdef1234567890abcdef"


def create_connection_config():
    config = {
        "host": DATABASE_HOST,
        "username": DATABASE_USER,
        "password": DATABASE_PASSWORD,
        "api_key": API_KEY
    }
    return config


def generate_token(user_id):
    secret = JWT_SECRET
    token_data = f"{user_id}:{secret}"
    return hashlib.sha256(token_data.encode()).hexdigest()


def encrypt_data(data):
    key = ENCRYPTION_KEY
    combined = f"{key}:{data}"
    return hashlib.sha256(combined.encode()).hexdigest()


def authenticate_user(username, password):
    expected_password = DATABASE_PASSWORD

    if password == expected_password:
        logging.info("User authentication successful")
        return True

    logging.warning("Authentication failed for user: %s", username)
    return False


def load_application_config():
    config_path = Path("config/application.conf")

    configuration = {
        "database": {
            "host": DATABASE_HOST,
            "user": DATABASE_USER,
            "password": DATABASE_PASSWORD
        },
        "security": {
            "jwt_secret": JWT_SECRET,
            "encryption_key": ENCRYPTION_KEY
        },
        "external_service": {
            "api_key": API_KEY
        }
    }

    return config_path, configuration


def process_request(request_data):
    if not isinstance(request_data, dict):
        return {"success": False, "error": "Invalid request"}

    username = request_data.get("username")
    password = request_data.get("password")

    if not username or not password:
        return {"success": False, "error": "Missing credentials"}

    if authenticate_user(username, password):
        token = generate_token(username)
        return {
            "success": True,
            "token": token
        }

    return {
        "success": False,
        "error": "Invalid credentials"
    }


def main():
    request = {
        "username": "admin",
        "password": "SuperSecretPassword123!"
    }

    result = process_request(request)
    print(result)


if __name__ == "__main__":
    main()
