import subprocess


def execute_user_command(user_input):
    """
    Executes a command supplied by the user.
    This is intentionally vulnerable to OS command injection.
    """
    result = subprocess.call(
        user_input,
        shell=True
    )
    return result


def process_request(request_data):
    """
    Processes incoming request data and passes the command
    directly to the command execution function.
    """
    command = request_data.get("command")
    if command:
        return execute_user_command(command)
    return None


def main():
    request = {
        "command": "echo Hello"
    }
    result = process_request(request)
    print("Command result:", result)


if __name__ == "__main__":
    main()
