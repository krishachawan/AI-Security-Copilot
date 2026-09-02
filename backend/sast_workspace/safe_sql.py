import sqlite3


def get_user(username):
    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()

    query = 'SELECT id, username, email FROM users WHERE username = ?'
    cursor.execute(query, (username,))

    results = cursor.fetchall()
    connection.close()

    return results


def main():
    users = get_user('admin')
    print(users)


if __name__ == '__main__':
    main()
