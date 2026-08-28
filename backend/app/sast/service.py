from collections import Counter

from app.sast.models import (
    SASTFinding,
    SASTSummary,
    SASTScanResult
)

from app.sast.language import detect_language

from app.sast.scanners.semgrep import (
    scan_with_semgrep
)

from app.sast.scanners.bandit import (
    scan_with_bandit
)

from app.core.config import (
    SAST_WORKSPACE,
    SEMGREP_TIMEOUT,
    BANDIT_TIMEOUT
)


def build_summary(
    findings: list[SASTFinding]
) -> SASTSummary:

    counter = Counter()

    for finding in findings:
        counter[finding.severity.lower()] += 1

    return SASTSummary(
        critical=counter["critical"],
        high=counter["high"],
        medium=counter["medium"],
        low=counter["low"],
        info=counter["info"],
        unknown=counter["unknown"],
        total=len(findings)
    )


def scan_code(
    code: str,
    filename: str
) -> SASTScanResult:

    # -----------------------------------------
    # Validate source code
    # -----------------------------------------

    if not code.strip():
        raise ValueError(
            "Source code cannot be empty."
        )

    # -----------------------------------------
    # Detect programming language
    # -----------------------------------------

    language = detect_language(
        filename
    )

    if language != "python":
        raise ValueError(
            "Only Python source files are "
            "supported by the current "
            "PyCodeVul pipeline."
        )

    # -----------------------------------------
    # Create file inside configured workspace
    # -----------------------------------------

    file_path = (
        SAST_WORKSPACE / filename
    )

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path.write_text(
        code,
        encoding="utf-8"
    )

    findings: list[SASTFinding] = []
    scanner_errors: list[str] = []

    # -----------------------------------------
    # Run Semgrep
    # -----------------------------------------

    semgrep_findings, semgrep_error = (
        scan_with_semgrep(
            file_path,
            timeout=SEMGREP_TIMEOUT
        )
    )

    findings.extend(
        semgrep_findings
    )

    if semgrep_error:
        scanner_errors.append(
            f"Semgrep: {semgrep_error}"
        )

    # -----------------------------------------
    # Run Bandit
    # -----------------------------------------

    bandit_findings, bandit_error = (
        scan_with_bandit(
            file_path,
            timeout=BANDIT_TIMEOUT
        )
    )

    findings.extend(
        bandit_findings
    )

    if bandit_error:
        scanner_errors.append(
            f"Bandit: {bandit_error}"
        )

    # -----------------------------------------
    # Build final SAST result
    # -----------------------------------------

    return SASTScanResult(
        status=(
            "completed"
            if not scanner_errors
            else "completed_with_errors"
        ),

        language=language,

        file=filename,

        findings=findings,

        summary=build_summary(
            findings
        ),

        scanner_errors=scanner_errors
    )