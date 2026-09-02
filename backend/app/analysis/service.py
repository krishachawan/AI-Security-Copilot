from app.classifier.codebert import CodeBERTClassifier
from app.core.config import MODEL_PATH
from app.sast.service import scan_code
from app.rag.service import retrieve_security_context
from app.llm.service import generate_security_analysis


# =========================================================
# LOAD CODEBERT ONCE
# =========================================================

codebert_classifier = CodeBERTClassifier(
    str(MODEL_PATH)
)


# =========================================================
# SAFE COMMAND EXECUTION DETECTION
# =========================================================

def has_safe_command_execution_pattern(code: str) -> bool:
    """
    Detect a conservative safe subprocess pattern.

    Considered safe when:
        1. subprocess execution is used
        2. shell=False is explicitly specified
        3. commands come from an allowlist

    This only recognizes the specific safe pattern.
    It does not prove that arbitrary code is safe.
    """

    uses_subprocess = (
        "subprocess.run(" in code
        or "subprocess.call(" in code
        or "subprocess.Popen(" in code
    )

    if not uses_subprocess:
        return False

    explicit_shell_false = (
        "shell=False" in code
    )

    has_allowlist = (
        "ALLOWED_COMMANDS" in code
        or "allowed_commands" in code
        or "ALLOWED_COMMAND" in code
    )

    return (
        uses_subprocess
        and explicit_shell_false
        and has_allowlist
    )


# =========================================================
# MAIN ANALYSIS FUNCTION
# =========================================================

def analyze_code(
    code: str,
    filename: str
) -> dict:

    if not code or not code.strip():
        raise ValueError(
            "Source code cannot be empty."
        )

    # =====================================================
    # 1. CODEBERT PREDICTION
    # =====================================================

    codebert_result = codebert_classifier.predict(code)

    # =====================================================
    # 2. SAST SCANNING
    # =====================================================

    sast_result = scan_code(
        code=code,
        filename=filename
    )

    sast_findings = [
        finding.model_dump()
        for finding in sast_result.findings
    ]

    # =====================================================
    # 3. SAST SEVERITY SIGNALS
    # =====================================================

    has_critical_sast = (
        sast_result.summary.critical > 0
    )

    has_high_sast = (
        sast_result.summary.high > 0
    )

    has_medium_sast = (
        sast_result.summary.medium > 0
    )

    has_low_sast = (
        sast_result.summary.low > 0
    )

    has_high_or_critical_sast = (
        has_critical_sast
        or has_high_sast
    )

    has_medium_or_above_sast = (
        has_critical_sast
        or has_high_sast
        or has_medium_sast
    )
        # Overall severity = highest severity reported by SAST
    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    sast_severities = [
        str(finding.get("severity", "INFO")).upper()
        for finding in sast_findings
        if finding.get("severity") is not None
    ]

    if sast_severities:
        severity = max(
            sast_severities,
            key=lambda value: severity_order.get(value, 0)
        )
    else:
        severity = "N/A"

    # =====================================================
    # 4. CODEBERT SIGNALS
    # =====================================================

    vulnerable = codebert_result.get(
        "vulnerable",
        False
    )

    confidence = codebert_result.get(
        "confidence",
        0.0
    )

    high_confidence = (
        confidence >= 0.90
    )

    # =====================================================
    # 5. SAFE PATTERN ANALYSIS
    # =====================================================

    safe_command_pattern = (
        has_safe_command_execution_pattern(code)
    )

    # =====================================================
    # 6. COMBINED SECURITY DECISION
    # =====================================================
    #
    # Priority:
    #
    # 1. Explicit safe command pattern
    #    + no MEDIUM/HIGH/CRITICAL SAST
    #
    # 2. CodeBERT + meaningful SAST agreement
    #
    # 3. Independent HIGH/CRITICAL SAST
    #
    # 4. High-confidence CodeBERT alone
    #    -> potential vulnerability
    #
    # 5. Lower-confidence CodeBERT
    #    -> potential vulnerability
    #
    # 6. MEDIUM SAST
    #    -> potential vulnerability
    #
    # 7. LOW-only SAST
    #    -> no vulnerability detected
    #
    # 8. Nothing detected
    #    -> no vulnerability detected
    # =====================================================

    # -----------------------------------------------------
    # CASE 1:
    # Explicitly safe command execution
    #
    # Example:
    #
    # ALLOWED_COMMANDS = {...}
    #
    # subprocess.run(
    #     ALLOWED_COMMANDS[command],
    #     shell=False
    # )
    #
    # LOW-only SAST warnings such as B404/B603
    # do not override this safe pattern.
    # -----------------------------------------------------

    if (
        safe_command_pattern
        and not has_medium_or_above_sast
    ):

        verdict = (
            "no_vulnerability_detected"
        )

    # -----------------------------------------------------
    # CASE 2:
    # CodeBERT strongly predicts vulnerability AND
    # SAST provides MEDIUM/HIGH/CRITICAL evidence.
    #
    # This represents agreement between ML and
    # static-analysis evidence.
    # -----------------------------------------------------

    elif (
        vulnerable
        and high_confidence
        and has_medium_or_above_sast
    ):

        verdict = (
            "high_confidence_vulnerability"
        )

    # -----------------------------------------------------
    # CASE 3:
    # SAST independently detects HIGH/CRITICAL.
    #
    # CodeBERT does not need to agree.
    # -----------------------------------------------------

    elif has_high_or_critical_sast:

        verdict = (
            "sast_detected_vulnerability"
        )

    # -----------------------------------------------------
    # CASE 4:
    # CodeBERT strongly predicts vulnerability but
    # SAST does not provide meaningful confirmation.
    #
    # Do not call it confirmed.
    # -----------------------------------------------------

    elif vulnerable and high_confidence:

        verdict = (
            "potential_vulnerability"
        )

    # -----------------------------------------------------
    # CASE 5:
    # CodeBERT predicts vulnerability with lower
    # confidence.
    # -----------------------------------------------------

    elif vulnerable:

        verdict = (
            "potential_vulnerability"
        )

    # -----------------------------------------------------
    # CASE 6:
    # MEDIUM SAST finding.
    # -----------------------------------------------------

    elif has_medium_sast:

        verdict = (
            "potential_vulnerability"
        )

    # -----------------------------------------------------
    # CASE 7:
    # LOW-only SAST findings.
    #
    # Examples:
    # B404
    # B603
    # -----------------------------------------------------

    elif has_low_sast:

        verdict = (
            "no_vulnerability_detected"
        )

    # -----------------------------------------------------
    # CASE 8:
    # Nothing detected.
    # -----------------------------------------------------

    else:

        verdict = (
            "no_vulnerability_detected"
        )

    # =====================================================
    # 7. RAG DECISION
    # =====================================================
    #
    # IMPORTANT:
    #
    # RAG now follows the FINAL AGGREGATED VERDICT.
    #
    # This prevents contradictory results such as:
    #
    # verdict = no_vulnerability_detected
    #
    # while RAG says:
    #
    # CWE-78 Command Injection
    #
    # RAG runs only when the aggregation layer considers
    # the code potentially vulnerable.
    # =====================================================

    should_run_rag = (
        verdict != "no_vulnerability_detected"
    )

    if should_run_rag:

        rag_result = retrieve_security_context(
            code=code,
            codebert=codebert_result,
            findings=sast_findings
        )

    else:

        rag_result = {
            "query": None,
            "retrieved_cwes": [],
            "context": None
        }

    # =====================================================
    # 8. LLM EXPLANATION + REMEDIATION
    # =====================================================
    # Gemini is downstream of detection and RAG. It does not
    # modify the aggregation verdict. It explains the evidence
    # and generates remediation grounded in the retrieved CWE
    # context.

    if should_run_rag and rag_result.get("context"):

        try:
            llm_result = generate_security_analysis(
                code=code,
                verdict=verdict,
                codebert=codebert_result,
                sast_findings=sast_findings,
                rag_context=rag_result["context"],
            )

            llm_result["status"] = "completed"

        except Exception as exc:

            # LLM failure must not invalidate the detector's result.
            llm_result = {
                "status": "failed",
                "error": str(exc),
            }

    else:

        llm_result = {
            "status": "not_run",
            "reason": "No vulnerability verdict requiring LLM analysis."
        }

    # =====================================================
    # 9. FINAL RESPONSE
    # =====================================================

    return {
        "filename": filename,

        "language": sast_result.language,

        "verdict": verdict,
        "severity": severity,

        "codebert": codebert_result,

        "sast": sast_result.model_dump(),

        "rag": rag_result,

        "llm": llm_result
    }
