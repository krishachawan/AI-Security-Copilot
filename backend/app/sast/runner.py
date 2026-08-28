import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass
class CommandResult:
    return_code: int
    stdout: str
    stderr: str


def run_command(
    command: Sequence[str],
    timeout: int
) -> CommandResult:

    try:
        result = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False
        )

        return CommandResult(
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr
        )

    except subprocess.TimeoutExpired:
        return CommandResult(
            return_code=-1,
            stdout="",
            stderr="Scanner timed out."
        )

    except FileNotFoundError as exc:
        return CommandResult(
            return_code=-2,
            stdout="",
            stderr=f"Scanner not found: {exc}"
        )

    except Exception as exc:
        return CommandResult(
            return_code=-3,
            stdout="",
            stderr=str(exc)
        )