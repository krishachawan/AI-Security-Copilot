from app.classifier.codebert import CodeBERTClassifier
from app.core.config import MODEL_PATH
from app.sast.service import scan_code
from app.rag.service import retrieve_security_context


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

    This is NOT intended to prove arbitrary code is safe.
    It only handles the specific safe command-execution
    pattern used by the application.
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
    # 1. CodeBERT PREDICTION
    # =====================================================

    codebert_result = (
        codebert_classifier.predict(code)
    )

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

    has_any_sast = (
        len(sast_findings) > 0
    )

    # =====================================================
    # 4. CODEBERT SIGNALS
    # =====================================================

    vulnerable = (
        codebert_result.get(
            "vulnerable",
            False
        )
    )

    confidence = (
        codebert_result.get(
            "confidence",
            0.0
        )
    )

    high_confidence = (
        confidence >= 0.90
    )

    # =====================================================
    # 5. SAFE-PATTERN ANALYSIS
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
    # 1. Clearly safe command pattern + no meaningful
    #    SAST evidence
    #
    # 2. CodeBERT + MEDIUM/HIGH/CRITICAL SAST agreement
    #
    # 3. Independent HIGH/CRITICAL SAST
    #
    # 4. CodeBERT high-confidence prediction alone
    #    -> only potential vulnerability
    #
    # 5. CodeBERT lower-confidence prediction
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
    # This prevents CodeBERT from turning this specific
    # safe pattern into a vulnerability.
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
    # Strong agreement between CodeBERT and SAST
    #
    # Example:
    #
    # CodeBERT = vulnerable, confidence > 0.90
    # SAST = MEDIUM/HIGH/CRITICAL
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
    # SAST independently detected HIGH/CRITICAL
    #
    # CodeBERT does not need to agree.
    # -----------------------------------------------------

    elif has_high_or_critical_sast:

        verdict = (
            "sast_detected_vulnerability"
        )

    # -----------------------------------------------------
    # CASE 4:
    # CodeBERT strongly predicts vulnerability but SAST
    # provides no meaningful confirmation.
    #
    # Do NOT call this confirmed.
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
    # MEDIUM SAST finding
    #
    # Example:
    #
    # CodeBERT = non-vulnerable
    # SAST = MEDIUM CWE-89
    #
    # This is still meaningful evidence.
    # -----------------------------------------------------

    elif has_medium_sast:

        verdict = (
            "potential_vulnerability"
        )

    # -----------------------------------------------------
    # CASE 7:
    # LOW-only SAST findings
    #
    # Examples:
    #
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
    # RAG runs when there is meaningful vulnerability
    # evidence:
    #
    # - CodeBERT predicts vulnerability
    # OR
    # - SAST has MEDIUM/HIGH/CRITICAL findings
    #
    # LOW-only SAST findings do not trigger RAG.
    # =====================================================

    should_run_rag = (
        vulnerable
        or has_medium_or_above_sast
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
    # 8. FINAL RESPONSE
    # =====================================================

    return {
        "filename": filename,

        "language": sast_result.language,

        "verdict": verdict,

        "codebert": codebert_result,

        "sast": sast_result.model_dump(),

        "rag": rag_result
    }