import subprocess

def ping_host(host):
    command = "ping -c 1 " + host
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )