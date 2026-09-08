import subprocess
import shlex

def run_command(request_data):
    command = request_data.get("command")
    if not command:
        return ""
    args = shlex.split(command)
    result = subprocess.run(
        args,
        shell=False,
        capture_output=True,
        text=True
    )
    return result.stdout