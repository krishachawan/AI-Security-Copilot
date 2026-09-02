import subprocess

ALLOWED_COMMANDS = {
 "status": ["python", "--version"],
 "help": ["python", "--help"]
}


def execute_command(request_data):
 command_name = request_data.get("command")

 if command_name not in ALLOWED_COMMANDS:
 return {"success": False, "error": "Command not allowed"}

 result = subprocess.run(
 ALLOWED_COMMANDS[command_name],
 shell=False,
 capture_output=True,
 text=True,
 check=True
 )

 return {
 "success": True,
 "output": result.stdout
 }


if __name__ == "__main__":
 print(execute_command({"command": "status"}))
