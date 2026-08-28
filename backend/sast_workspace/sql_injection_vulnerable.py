import sqlite3


def get_user(username):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    results = cursor.fetchall()
    connection.close()

    return results


def search_users(request_data):
    username = request_data.get("username")

    if not username:
        return []

    return get_user(username)


def process_request(request_data):
    if not isinstance(request_data, dict):
        return {"error": "Invalid request"}

    try:
        users = search_users(request_data)
        return {
            "success": True,
            "users": users
        }
    except Exception as error:
        return {
            "success": False,
            "error": str(error)
        }


def main():
    request = {
        "username": "admin"
    }

    response = process_request(request)
    print(response)


if __name__ == "__main__":
    main()
