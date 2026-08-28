from pathlib import Path
import sys
from functools import lru_cache

from sentence_transformers import SentenceTransformer


# ============================================================
# RAG PATH
# ============================================================

BACKEND_ROOT = Path(__file__).resolve().parents[2]

RAG_ROOT = (
    BACKEND_ROOT.parent
    / "RAG"
    / "Capstone_RAG_audited"
)

RAG_SRC = RAG_ROOT / "src"


if str(RAG_SRC) not in sys.path:
    sys.path.insert(0, str(RAG_SRC))


# ============================================================
# IMPORT EXISTING RAG
# ============================================================

from retrieve_cwe import (
    load_database,
    retrieve,
    EMBEDDING_MODEL,
)

from context_builder import build_context


# ============================================================
# LOAD RAG ONCE
# ============================================================

@lru_cache(maxsize=1)
def load_rag():

    print("\n" + "=" * 60)
    print("Loading CWE RAG...")
    print("=" * 60)

    index, metadata = load_database()

    print("\nLoading BGE embedding model...")

    model = SentenceTransformer(
        EMBEDDING_MODEL
    )

    print("CWE RAG loaded successfully.")

    return index, metadata, model


# ============================================================
# BUILD SECURITY QUERY
# ============================================================

def build_security_query(
    code: str,
    codebert: dict,
    findings: list
) -> str:

    parts = []

    # --------------------------------------------------------
    # CodeBERT prediction
    # --------------------------------------------------------

    vulnerable = codebert.get(
        "vulnerable",
        False
    )

    probability = codebert.get(
        "vulnerable_probability",
        0.0
    )

    parts.append(
        f"CodeBERT prediction: "
        f"{'vulnerable' if vulnerable else 'non-vulnerable'}"
    )

    parts.append(
        f"vulnerability probability: "
        f"{probability:.4f}"
    )

    # --------------------------------------------------------
    # SAST findings
    # --------------------------------------------------------

    for finding in findings:

        tool = finding.get(
            "tool",
            "unknown"
        )

        severity = finding.get(
            "severity",
            "UNKNOWN"
        )

        cwe = finding.get(
            "cwe"
        )

        rule_id = finding.get(
            "rule_id"
        )

        message = finding.get(
            "message",
            ""
        )

        parts.append(
            f"{tool} finding: "
            f"severity={severity}, "
            f"rule={rule_id}, "
            f"CWE={cwe}, "
            f"message={message}"
        )

    # --------------------------------------------------------
    # Source code
    # --------------------------------------------------------

    parts.append(
        "Source code:\n"
        + code
    )

    return "\n".join(parts)


# ============================================================
# RUN RAG
# ============================================================

def retrieve_security_context(
    code: str,
    codebert: dict,
    findings: list
) -> dict:

    # --------------------------------------------------------
    # Load cached RAG
    # --------------------------------------------------------

    index, metadata, model = load_rag()

    # --------------------------------------------------------
    # Build query
    # --------------------------------------------------------

    query = build_security_query(
        code=code,
        codebert=codebert,
        findings=findings
    )

    # --------------------------------------------------------
    # Retrieve CWE knowledge
    # --------------------------------------------------------

    results = retrieve(
        query,
        index,
        metadata,
        model
    )

    # --------------------------------------------------------
    # Build LLM context
    # --------------------------------------------------------

    context = build_context(
        results
    )

    # --------------------------------------------------------
    # Deduplicate CWE results
    #
    # The RAG database can contain multiple chunks/sections
    # belonging to the same CWE.
    #
    # Example:
    #
    # CWE-78 - Description
    # CWE-78 - Detection Methods
    # CWE-78 - Demonstrative Examples
    #
    # We only expose the strongest result for each CWE.
    # --------------------------------------------------------

    cwe_map = {}

    for candidate in results:

        result = candidate["result"]
        metadata_item = result["metadata"]

        cwe_id = metadata_item["cwe_id"]

        semantic_score = candidate.get(
            "semantic_score",
            0.0
        )

        final_score = candidate.get(
            "final_score",
            0.0
        )

        # ----------------------------------------------------
        # Keep the strongest result for this CWE
        # ----------------------------------------------------

        current = cwe_map.get(cwe_id)

        if (
            current is None
            or final_score > current["final_score"]
        ):

            cwe_map[cwe_id] = {
                "cwe_id": cwe_id,
                "cwe_name": metadata_item["cwe_name"],
                "section": metadata_item["section"],
                "semantic_score": semantic_score,
                "final_score": final_score
            }

    # --------------------------------------------------------
    # Sort CWEs by final retrieval score
    # --------------------------------------------------------

    retrieved_cwes = sorted(
        cwe_map.values(),
        key=lambda item: item["final_score"],
        reverse=True
    )

    # --------------------------------------------------------
    # Return structured result
    # --------------------------------------------------------

    return {
        "query": query,
        "retrieved_cwes": retrieved_cwes,
        "context": context
    }