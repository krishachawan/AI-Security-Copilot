import json
from pathlib import Path

from app.sast.models import SASTFinding
from app.sast.runner import run_command


def scan_with_bandit(
    file_path: Path,
    timeout: int = 60
):
    command = [
        "bandit",
        "-f",
        "json",
        "-q",
        str(file_path)
    ]

    result = run_command(
        command,
        timeout
    )

    if result.return_code == -2:
        return [], result.stderr

    if not result.stdout.strip():

        if result.return_code != 0:
            return [], result.stderr

        return [], None

    try:
        data = json.loads(
            result.stdout
        )

    except json.JSONDecodeError:
        return [], "Invalid JSON returned by Bandit."

    findings = []

    for item in data.get(
        "results",
        []
    ):

        cwe_data = item.get(
            "issue_cwe"
        )

        cwe = None

        if isinstance(
            cwe_data,
            dict
        ):
            cwe_id = cwe_data.get(
                "id"
            )

            if cwe_id:
                cwe = f"CWE-{cwe_id}"

        line_range = item.get(
            "line_range",
            []
        )

        end_line = None

        if line_range:
            end_line = line_range[-1]

        finding = SASTFinding(
            tool="bandit",

            rule_id=item.get(
                "test_id"
            ),

            rule_name=item.get(
                "test_name"
            ),

            severity=str(
                item.get(
                    "issue_severity",
                    "UNKNOWN"
                )
            ).upper(),

            confidence=str(
                item.get(
                    "issue_confidence",
                    "UNKNOWN"
                )
            ).upper(),

            cwe=cwe,

            file=item.get(
                "filename",
                str(file_path)
            ),

            line=item.get(
                "line_number"
            ),

            end_line=end_line,

            message=item.get(
                "issue_text",
                "Bandit finding"
            ),

            code=item.get(
                "code"
            ),

            reference=item.get(
                "more_info"
            )
        )

        findings.append(
            finding
        )

    return findings, None