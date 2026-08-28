import os
import subprocess
import sqlite3
import hashlib
import pickle
import yaml
import tempfile
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)
DATABASE = "users.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        )
    """)
    connection.commit()
    connection.close()


def authenticate_user(username, password):
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    connection.close()
    return dict(user) if user else None


@app.route("/search")
def search_users():
    username = request.args.get("username", "")
    connection = get_db_connection()
    cursor = connection.cursor()
    query = "SELECT id, username, email FROM users WHERE username LIKE '%" + username + "%'"
    cursor.execute(query)
    users = cursor.fetchall()
    connection.close()
    return jsonify({"users": [dict(user) for user in users]})


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "")
    command = "ping -n 4 " + host
    result = subprocess.call(command, shell=True)
    return jsonify({"host": host, "return_code": result})


@app.route("/diagnostics")
def diagnostics():
    command = request.args.get("command", "")
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    return jsonify({"stdout": stdout.decode(), "stderr": stderr.decode()})


@app.route("/read-file")
def read_file():
    filename = request.args.get("filename", "")
    with open(filename, "r") as file:
        contents = file.read()
    return jsonify({"filename": filename, "contents": contents})


@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    path = os.path.join("uploads", filename)
    with open(path, "rb") as file:
        data = file.read()
    return data


def load_configuration(data):
    configuration = yaml.load(data, Loader=yaml.Loader)
    return configuration


def restore_session(serialized_data):
    session = pickle.loads(serialized_data)
    return session


def generate_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def execute_backup(backup_name):
    command = "tar -czf " + backup_name + ".tar.gz backups/"
    subprocess.run(command, shell=True)
    return True


def process_uploaded_file(filename):
    temporary_directory = tempfile.gettempdir()
    target = os.path.join(temporary_directory, filename)
    with open(target, "w") as output:
        output.write("processed")
    return target


@app.route("/redirect")
def redirect_user():
    destination = request.args.get("next", "/")
    return redirect(destination)


@app.route("/admin")
def admin_panel():
    role = request.args.get("role", "user")
    if role == "admin":
        return jsonify({"message": "Welcome administrator"})
    return jsonify({"message": "Access denied"}), 403


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, host="0.0.0.0", port=5000)
