import subprocess


def run_command(request_data):
    command = request_data.get("command")
    if not command:
        return {"error": "Command required"}

    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )

    return {
        "success": True,
        "output": result.stdout
    }


def process_request(request_data):
    if not isinstance(request_data, dict):
        return {"error": "Invalid request"}

    return run_command(request_data)


def handle_user_action(request_data):
    command_result = process_request(request_data)

    if command_result.get("success"):
        return command_result

    return {
        "success": False,
        "message": command_result.get("error", "Command failed")
    }


def main():
    request = {
        "command": "echo Hello"
    }

    response = handle_user_action(request)
    print(response)


if __name__ == "__main__":
    main()
