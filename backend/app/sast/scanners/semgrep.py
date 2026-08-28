from pathlib import Path
import json
import os
import shutil
import subprocess

from app.sast.models import SASTFinding


def scan_with_semgrep(
    file_path: Path,
    timeout: int = 60
) -> tuple[list[SASTFinding], str | None]:

    findings: list[SASTFinding] = []

    # =========================================================
    # Locate Semgrep
    # =========================================================
    #
    # IMPORTANT:
    # Do NOT use:
    #
    #     python -m semgrep
    #
    # Windows + Python 3.13 can cause Semgrep's Python
    # subprocess to hang while initializing platform/WMI.
    #
    # Instead, use the actual semgrep executable available
    # through the active virtual environment.
    #
    # =========================================================

    semgrep_executable = shutil.which("semgrep")

    if not semgrep_executable:

        return (
            findings,
            "Semgrep executable not found in PATH. "
            "Make sure the virtual environment is activated "
            "and Semgrep is installed."
        )

    # =========================================================
    # Build Semgrep command
    # =========================================================

    command = [
        semgrep_executable,
        "scan",
        "--config",
        "p/python",
        "--json",
        "--no-git-ignore",
        str(file_path)
    ]

    # =========================================================
    # Prepare environment
    # =========================================================
    #
    # Remove Python environment variables that can interfere
    # with a Python-based executable launched from another
    # Python process.
    #
    # This is particularly important on Windows/Python 3.13.
    #
    # =========================================================

    environment = os.environ.copy()

    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)

    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUNBUFFERED"] = "1"

    # Prevent Semgrep from trying to send metrics/network
    # information during an API request.
    environment["SEMGREP_SEND_METRICS"] = "off"

    # =========================================================
    # Windows subprocess settings
    # =========================================================

    startupinfo = None
    creationflags = 0

    if os.name == "nt":

        startupinfo = subprocess.STARTUPINFO()

        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        startupinfo.wShowWindow = 0

        creationflags = subprocess.CREATE_NO_WINDOW

    # =========================================================
    # Execute Semgrep
    # =========================================================

    try:

        process = subprocess.run(
            command,

            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,

            stdin=subprocess.DEVNULL,

            timeout=timeout,

            text=True,
            encoding="utf-8",
            errors="replace",

            shell=False,

            cwd=str(file_path.parent),

            env=environment,

            startupinfo=startupinfo,

            creationflags=creationflags
        )

    except subprocess.TimeoutExpired:

        return (
            findings,
            f"Semgrep timed out after {timeout} seconds."
        )

    except FileNotFoundError:

        return (
            findings,
            f"Semgrep executable could not be started: "
            f"{semgrep_executable}"
        )

    except OSError as exc:

        return (
            findings,
            f"Failed to execute Semgrep: {exc}"
        )

    except Exception as exc:

        return (
            findings,
            f"Semgrep execution failed: {exc}"
        )

    # =========================================================
    # Read output
    # =========================================================

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    # =========================================================
    # No JSON output
    # =========================================================

    if not stdout.strip():

        if process.returncode != 0:

            error_message = stderr.strip()

            if not error_message:

                error_message = (
                    f"Semgrep exited with code "
                    f"{process.returncode}."
                )

            return findings, error_message

        return findings, None

    # =========================================================
    # Parse JSON
    # =========================================================

    try:

        result = json.loads(stdout)

    except json.JSONDecodeError as exc:

        # Sometimes a CLI warning may appear before/around the
        # JSON output. Return useful diagnostic information.

        return (
            findings,
            "Semgrep returned invalid JSON: "
            f"{exc}. "
            f"stderr: {stderr.strip()}"
        )

    # =========================================================
    # Handle Semgrep-reported errors
    # =========================================================
    #
    # Semgrep can return valid JSON while also reporting errors.
    #
    # =========================================================

    semgrep_errors = result.get("errors", [])

    semgrep_error_message = None

    if semgrep_errors:

        error_messages = []

        for error in semgrep_errors:

            if isinstance(error, dict):

                message = (
                    error.get("message")
                    or error.get("error")
                    or str(error)
                )

            else:

                message = str(error)

            error_messages.append(message)

        if error_messages:

            semgrep_error_message = (
                " | ".join(error_messages)
            )

    # =========================================================
    # Handle non-zero exit code
    # =========================================================

    if process.returncode != 0:

        if stderr.strip():

            semgrep_error_message = stderr.strip()

        elif not semgrep_error_message:

            semgrep_error_message = (
                f"Semgrep exited with code "
                f"{process.returncode}."
            )

    # =========================================================
    # Convert Semgrep findings
    # =========================================================

    for item in result.get("results", []):

        extra = item.get("extra", {}) or {}

        metadata = extra.get(
            "metadata",
            {}
        ) or {}

        start = item.get(
            "start",
            {}
        ) or {}

        end = item.get(
            "end",
            {}
        ) or {}

        # -----------------------------------------------------
        # Severity
        # -----------------------------------------------------

        severity = (
            extra.get("severity")
            or metadata.get("severity")
            or "UNKNOWN"
        )

        severity = str(
            severity
        ).upper()

        # -----------------------------------------------------
        # Confidence
        # -----------------------------------------------------

        confidence = (
            metadata.get("confidence")
            or extra.get("confidence")
            or "MEDIUM"
        )

        confidence = str(
            confidence
        ).upper()

        # -----------------------------------------------------
        # CWE
        # -----------------------------------------------------

        cwe = metadata.get("cwe")

        if isinstance(cwe, list):

            cwe = ", ".join(
                str(value)
                for value in cwe
            )

        elif cwe is not None:

            cwe = str(cwe)

        # -----------------------------------------------------
        # OWASP
        # -----------------------------------------------------

        owasp = metadata.get("owasp")

        if isinstance(owasp, list):

            owasp = ", ".join(
                str(value)
                for value in owasp
            )

        elif owasp is not None:

            owasp = str(owasp)

        # -----------------------------------------------------
        # Reference
        # -----------------------------------------------------

        reference = None

        references = metadata.get(
            "references"
        )

        if (
            isinstance(references, list)
            and references
        ):

            reference = str(
                references[0]
            )

        elif metadata.get(
            "source-rule-url"
        ):

            reference = str(
                metadata["source-rule-url"]
            )

        elif metadata.get(
            "source"
        ):

            reference = str(
                metadata["source"]
            )

        # -----------------------------------------------------
        # Rule ID
        # -----------------------------------------------------

        rule_id = item.get(
            "check_id"
        )

        # -----------------------------------------------------
        # Rule name
        # -----------------------------------------------------

        rule_name = metadata.get(
            "name"
        )

        if not rule_name:

            rule_name = rule_id

        # -----------------------------------------------------
        # Source code
        # -----------------------------------------------------

        code = extra.get(
            "lines"
        )

        if code == "requires login":

            code = None

        # -----------------------------------------------------
        # Message
        # -----------------------------------------------------

        message = extra.get(
            "message",
            "Semgrep security finding."
        )

        # -----------------------------------------------------
        # Create SAST finding
        # -----------------------------------------------------

        findings.append(
            SASTFinding(
                tool="semgrep",

                rule_id=rule_id,

                rule_name=rule_name,

                severity=severity,

                confidence=confidence,

                cwe=cwe,

                owasp=owasp,

                file=str(
                    file_path
                ),

                line=start.get(
                    "line"
                ),

                end_line=end.get(
                    "line"
                ),

                column=start.get(
                    "col"
                ),

                end_column=end.get(
                    "col"
                ),

                message=message,

                code=code,

                reference=reference
            )
        )

    # =========================================================
    # Successful scan
    # =========================================================

    return findings, semgrep_error_message