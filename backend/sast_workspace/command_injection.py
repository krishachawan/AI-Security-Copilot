import subprocess

def run_command(request_data):
    command = request_data.get("command")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
