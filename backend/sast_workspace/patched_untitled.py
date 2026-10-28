import re
import subprocess

def ping_host(host):
    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
        raise ValueError("Invalid hostname or IP address")
    return subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True
    )