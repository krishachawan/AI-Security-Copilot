# backend/app/sast/normalizer.py

from typing import Any

from app.sast.models import SASTFinding


def normalize_bandit_finding(
    finding: dict[str, Any]
) -> SASTFinding:
    """
    Convert a Bandit finding into the common SASTFinding format.
    """

    location = finding.get("location", {})

    return SASTFinding(
        tool="bandit",

        rule_id=finding.get("test_id"),
        rule_name=finding.get("test_name"),

        severity=str(
            finding.get("issue_severity", "UNKNOWN")
        ).upper(),

        confidence=str(
            finding.get("issue_confidence", "UNKNOWN")
        ).upper(),

        cwe=extract_bandit_cwe(finding),

        owasp=None,

        file=finding.get(
            "filename",
            ""
        ),

        line=location.get("line_number"),
        end_line=location.get("line_range", [None])[-1],

        column=location.get("col_offset"),
        end_column=location.get("end_col_offset"),

        message=finding.get(
            "issue_text",
            ""
        ),

        code=location.get("code"),

        reference=finding.get(
            "more_info"
        )
    )


def extract_bandit_cwe(
    finding: dict[str, Any]
) -> str | None:
    """
    Extract CWE ID from Bandit's CWE object.
    """

    cwe = finding.get("issue_cwe")

    if isinstance(cwe, dict):
        return cwe.get("id")

    return None


def normalize_semgrep_finding(
    finding: dict[str, Any]
) -> SASTFinding:
    """
    Convert a Semgrep finding into the common SASTFinding format.
    """

    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})

    start = finding.get("start", {})
    end = finding.get("end", {})

    return SASTFinding(
        tool="semgrep",

        rule_id=finding.get("check_id"),

        rule_name=(
            metadata.get("name")
            or metadata.get("short_description")
        ),

        severity=normalize_semgrep_severity(
            metadata.get("severity")
        ),

        confidence=normalize_semgrep_confidence(
            metadata
        ),

        cwe=extract_semgrep_cwe(metadata),

        owasp=extract_semgrep_owasp(metadata),

        file=finding.get(
            "path",
            ""
        ),

        line=start.get("line"),

        end_line=end.get("line"),

        column=start.get("col"),

        end_column=end.get("col"),

        message=extra.get(
            "message",
            ""
        ),

        code=extra.get(
            "lines"
        ),

        reference=extract_semgrep_reference(
            metadata
        )
    )


def normalize_semgrep_severity(
    severity: str | None
) -> str:
    """
    Normalize Semgrep severity values.
    """

    if not severity:
        return "UNKNOWN"

    severity = severity.upper()

    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW"
    }

    return mapping.get(
        severity,
        severity
    )


def normalize_semgrep_confidence(
    metadata: dict[str, Any]
) -> str:
    """
    Extract Semgrep confidence if available.
    """

    confidence = metadata.get(
        "confidence"
    )

    if not confidence:
        return "UNKNOWN"

    return str(confidence).upper()


def extract_semgrep_cwe(
    metadata: dict[str, Any]
) -> str | None:
    """
    Extract CWE from Semgrep metadata.
    """

    cwe = metadata.get("cwe")

    if isinstance(cwe, list):
        if len(cwe) > 0:
            return str(cwe[0])

        return None

    if cwe:
        return str(cwe)

    return None


def extract_semgrep_owasp(
    metadata: dict[str, Any]
) -> str | None:
    """
    Extract OWASP category from Semgrep metadata.
    """

    owasp = metadata.get("owasp")

    if isinstance(owasp, list):
        if len(owasp) > 0:
            return str(owasp[0])

        return None

    if owasp:
        return str(owasp)

    return None


def extract_semgrep_reference(
    metadata: dict[str, Any]
) -> str | None:
    """
    Extract a reference URL from Semgrep metadata.
    """

    references = metadata.get(
        "references"
    )

    if isinstance(references, list):
        if len(references) > 0:
            return str(references[0])

        return None

    if references:
        return str(references)

    return None