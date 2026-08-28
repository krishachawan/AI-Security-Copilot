import sqlite3


def find_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = 'SELECT * FROM users WHERE username = ' + username
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()
    return rows


def handle_request(request):
    username = request.get('username')
    if username:
        return find_user(username)
    return []


def main():
    request = {'username': 'admin'}
    result = handle_request(request)
    print(result)


if __name__ == '__main__':
    main()
