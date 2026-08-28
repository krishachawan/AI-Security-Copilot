import json
import re
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer


# ============================================================
# Configuration
# ============================================================

from pathlib import Path

RAG_ROOT = Path(__file__).resolve().parents[1]

INDEX_PATH = (
    RAG_ROOT
    / "data"
    / "vector_db"
    / "cwe.index"
)

METADATA_PATH = (
    RAG_ROOT
    / "data"
    / "vector_db"
    / "cwe_metadata.json"
)

EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

# Number of semantic candidates retrieved from FAISS.
CANDIDATE_K = 50

# Number of results finally returned to the LLM.
FINAL_K = 5

# BGE retrieval instruction.
QUERY_INSTRUCTION = (
    "Represent this sentence for searching relevant passages: "
)


# ============================================================
# Section priorities
# ============================================================

SECTION_PRIORITIES = {

    # General explanation of a vulnerability
    "explanation": {
        "Description": 1.00,
        "Common Consequences": 0.80,
        "Potential Mitigations": 0.55,
        "Demonstrative Examples": 0.45,
        "Detection Methods": 0.40,
        "Observed Examples": 0.25,
        "Modes of Introduction": 0.20,
        "Background": 0.20,
    },

    # How to fix / prevent a vulnerability
    "remediation": {
        "Potential Mitigations": 1.00,
        "Detection Methods": 0.75,
        "Description": 0.55,
        "Demonstrative Examples": 0.45,
        "Common Consequences": 0.35,
        "Observed Examples": 0.25,
        "Modes of Introduction": 0.20,
        "Background": 0.15,
    },

    # How to identify a vulnerability
    "detection": {
        "Detection Methods": 1.00,
        "Description": 0.85,
        "Demonstrative Examples": 0.60,
        "Common Consequences": 0.45,
        "Potential Mitigations": 0.40,
        "Observed Examples": 0.30,
        "Modes of Introduction": 0.20,
        "Background": 0.15,
    },

    # User specifically asks for examples
    "examples": {
        "Demonstrative Examples": 1.00,
        "Observed Examples": 0.90,
        "Description": 0.55,
        "Common Consequences": 0.45,
        "Potential Mitigations": 0.35,
        "Detection Methods": 0.30,
        "Modes of Introduction": 0.20,
        "Background": 0.15,
    },
}


# ============================================================
# Primary section for each intent
# ============================================================

PRIMARY_SECTIONS = {
    "remediation": "Potential Mitigations",
    "detection": "Detection Methods",
    "examples": "Demonstrative Examples",
    "explanation": "Description",
}


# ============================================================
# Load vector database
# ============================================================

def load_database():

    print("Loading FAISS index...")

    index = faiss.read_index(
        str(INDEX_PATH)
    )

    print(
        f"Vectors in index: {index.ntotal}"
    )

    print("\nLoading metadata...")

    with METADATA_PATH.open(
        "r",
        encoding="utf-8"
    ) as file:
        metadata = json.load(file)

    print(
        f"Metadata records: {len(metadata)}"
    )

    # Safety check
    if index.ntotal != len(metadata):
        raise RuntimeError(
            "FAISS index and metadata count do not match."
        )

    return index, metadata


# ============================================================
# Extract CWE ID from query
# ============================================================

def extract_cwe_id(query):

    match = re.search(
        r"\bCWE[-\s]?(\d+)\b",
        query,
        re.IGNORECASE
    )

    if not match:
        return None

    return f"CWE-{match.group(1)}"


# ============================================================
# Detect user intent
# ============================================================

def detect_intent(query):

    query_lower = query.lower()

    # --------------------------------------------------------
    # Remediation
    # --------------------------------------------------------

    remediation_words = [
        "fix",
        "prevent",
        "remediate",
        "remediation",
        "secure",
        "patch",
        "mitigate",
        "mitigation",
        "avoid",
        "protect against",
        "how should i fix",
        "how do i fix",
        "how can i fix",
        "how can i prevent",
        "how should i prevent",
        "how to fix",
        "how to prevent",
    ]

    # --------------------------------------------------------
    # Detection
    # --------------------------------------------------------

    detection_words = [
        "detect",
        "detection",
        "identify",
        "identification",
        "find",
        "recognize",
        "scanner",
        "scanning",
        "static analysis",
        "how can i detect",
        "how to detect",
    ]

    # --------------------------------------------------------
    # Examples
    # --------------------------------------------------------

    example_words = [
        "example",
        "examples",
        "sample",
        "samples",
        "code example",
        "code examples",
        "vulnerable code",
        "show me",
        "demonstrate",
    ]

    # Check remediation first because queries such as
    # "show me how to fix..." contain both concepts.
    if any(
        word in query_lower
        for word in remediation_words
    ):
        return "remediation"

    if any(
        word in query_lower
        for word in detection_words
    ):
        return "detection"

    if any(
        word in query_lower
        for word in example_words
    ):
        return "examples"

    return "explanation"


# ============================================================
# Score a candidate
# ============================================================

def score_candidate(
    candidate,
    target_cwe,
    intent
):

    result = candidate["result"]
    metadata = result["metadata"]

    semantic_score = candidate["semantic_score"]

    candidate_cwe = metadata["cwe_id"]
    section = metadata["section"]

    score = semantic_score

    # --------------------------------------------------------
    # Determine whether this is the exact requested CWE
    # --------------------------------------------------------

    exact_cwe = (
        target_cwe is not None
        and candidate_cwe.upper() == target_cwe.upper()
    )

    # --------------------------------------------------------
    # Exact CWE
    # --------------------------------------------------------

    if exact_cwe:

        # Strong preference for the requested CWE.
        score += 1.00

        # ----------------------------------------------------
        # Primary section
        # ----------------------------------------------------

        primary_section = PRIMARY_SECTIONS.get(
            intent
        )

        if section == primary_section:

            # Strongest preference.
            score += 1.00

        else:

            # Other sections of the correct CWE are still
            # useful, but less important.
            section_priority = (
                SECTION_PRIORITIES
                .get(intent, {})
                .get(section, 0.0)
            )

            score += section_priority * 0.30

    # --------------------------------------------------------
    # Related / different CWE
    # --------------------------------------------------------

    else:

        section_priority = (
            SECTION_PRIORITIES
            .get(intent, {})
            .get(section, 0.0)
        )

        # Related CWEs are allowed to appear, but should not
        # easily outrank the requested CWE.
        score += section_priority * 0.10

    return score


# ============================================================
# Select diverse results
# ============================================================

def select_diverse_results(
    candidates,
    final_k,
    target_cwe=None
):

    selected = []

    cwe_counts = {}
    # Keyed by (cwe_id, section) rather than just `section`.
    #
    # BUG FIXED: the original cap was keyed by section name alone, e.g.
    # section_counts["Description"]. For a natural-language query with
    # no explicit CWE ID, that means once 2 Description chunks from
    # ANY two CWEs made it into the result, a 3rd, potentially more
    # relevant CWE's Description chunk was silently dropped in favor
    # of a lower-priority section from an already-included CWE. This
    # only matters for no-CWE-ID queries, since target_cwe queries
    # already funnel almost all slots to one CWE -- but it's a real
    # bug for the "semantic retrieval without an explicit CWE ID"
    # requirement, e.g. "what are common injection vulnerabilities".
    section_counts = {}

    # --------------------------------------------------------
    # First pass:
    #
    # For an exact CWE query, prioritize candidates belonging
    # to that CWE.
    # --------------------------------------------------------

    if target_cwe:

        exact_cwe_candidates = [
            candidate
            for candidate in candidates
            if (
                candidate["result"]["metadata"]["cwe_id"]
                .upper()
                == target_cwe.upper()
            )
        ]

        other_candidates = [
            candidate
            for candidate in candidates
            if (
                candidate["result"]["metadata"]["cwe_id"]
                .upper()
                != target_cwe.upper()
            )
        ]

        ordered_candidates = (
            exact_cwe_candidates
            + other_candidates
        )

    else:

        ordered_candidates = candidates

    # --------------------------------------------------------
    # Select diverse candidates
    # --------------------------------------------------------

    for candidate in ordered_candidates:

        result = candidate["result"]
        metadata = result["metadata"]

        cwe_id = metadata["cwe_id"]
        section = metadata["section"]

        # ----------------------------------------------------
        # Don't allow more than two chunks from the same
        # section.
        # ----------------------------------------------------

        section_key = (cwe_id, section)

        if section_counts.get(section_key, 0) >= 2:
            continue

        # ----------------------------------------------------
        # For exact CWE queries, strongly prefer the requested
        # CWE. We allow a maximum of one unrelated CWE result
        # into the final context.
        # ----------------------------------------------------

        if target_cwe:

            is_exact = (
                cwe_id.upper()
                == target_cwe.upper()
            )

            unrelated_count = sum(
                count
                for other_cwe, count
                in cwe_counts.items()
                if other_cwe.upper()
                != target_cwe.upper()
            )

            if not is_exact and unrelated_count >= 1:
                continue

        # ----------------------------------------------------
        # General CWE diversity limit
        # ----------------------------------------------------

        if cwe_counts.get(cwe_id, 0) >= 4:
            continue

        # ----------------------------------------------------
        # Add candidate
        # ----------------------------------------------------

        selected.append(candidate)

        cwe_counts[cwe_id] = (
            cwe_counts.get(cwe_id, 0) + 1
        )

        section_counts[section_key] = (
            section_counts.get(section_key, 0) + 1
        )

        if len(selected) >= final_k:
            break

    return selected


# ============================================================
# Retrieve relevant CWE knowledge
# ============================================================

def retrieve(
    query,
    index,
    metadata,
    model
):

    # --------------------------------------------------------
    # Analyze query
    # --------------------------------------------------------

    target_cwe = extract_cwe_id(query)
    intent = detect_intent(query)

    print(
        f"\nDetected CWE: {target_cwe}"
    )

    print(
        f"Detected intent: {intent}"
    )

    # --------------------------------------------------------
    # Create BGE query
    # --------------------------------------------------------

    instructed_query = (
        QUERY_INSTRUCTION + query
    )

    query_embedding = model.encode(
        [instructed_query],
        normalize_embeddings=True,
        convert_to_numpy=True
    ).astype("float32")

    # --------------------------------------------------------
    # Stage 1: Semantic retrieval
    # --------------------------------------------------------

    semantic_scores, indices = index.search(
        query_embedding,
        CANDIDATE_K
    )

    candidates = {}

    for semantic_score, index_id in zip(
        semantic_scores[0],
        indices[0]
    ):

        if index_id < 0:
            continue

        result = metadata[index_id]

        candidates[index_id] = {
            "index_id": int(index_id),
            "semantic_score": float(
                semantic_score
            ),
            "result": result,
            "source": "semantic",
        }

    # --------------------------------------------------------
    # Stage 2: Exact CWE retrieval
    #
    # If the query contains CWE-XX, retrieve ALL chunks
    # belonging to that CWE directly from metadata.
    #
    # This prevents FAISS from accidentally excluding the
    # most useful section.
    # --------------------------------------------------------

    if target_cwe:

        for index_id, result in enumerate(
            metadata
        ):

            candidate_cwe = (
                result["metadata"]["cwe_id"]
            )

            if (
                candidate_cwe.upper()
                == target_cwe.upper()
            ):

                # Preserve semantic score if FAISS already
                # found this document.
                if index_id not in candidates:

                    candidates[index_id] = {
                        "index_id": index_id,
                        "semantic_score": 0.0,
                        "result": result,
                        "source": "exact_cwe",
                    }

    # --------------------------------------------------------
    # Stage 3: Score all candidates
    # --------------------------------------------------------

    for candidate in candidates.values():

        candidate["final_score"] = score_candidate(
            candidate,
            target_cwe,
            intent
        )

    # --------------------------------------------------------
    # Stage 4: Sort
    # --------------------------------------------------------

    sorted_candidates = sorted(
        candidates.values(),
        key=lambda item: item["final_score"],
        reverse=True
    )

    # --------------------------------------------------------
    # Stage 5: Diversity / relevance selection
    # --------------------------------------------------------

    selected = select_diverse_results(
        sorted_candidates,
        FINAL_K,
        target_cwe
    )

    return selected


# ============================================================
# Display results
# ============================================================

def display_results(
    query,
    results
):

    print(
        "\n" + "=" * 80
    )

    print(
        "OPTIMIZED RETRIEVAL"
    )

    print(
        "=" * 80
    )

    print(
        "\nQuery:"
    )

    print(query)

    for rank, candidate in enumerate(
        results,
        start=1
    ):

        result = candidate["result"]
        metadata = result["metadata"]

        print(
            f"\n{'-' * 80}"
        )

        print(
            f"Rank: {rank}"
        )

        print(
            f"Semantic Score: "
            f"{candidate['semantic_score']:.4f}"
        )

        print(
            f"Final Score: "
            f"{candidate['final_score']:.4f}"
        )

        print(
            f"Retrieval Source: "
            f"{candidate['source']}"
        )

        print(
            f"ID: {result['id']}"
        )

        print(
            f"CWE: "
            f"{metadata['cwe_id']}"
        )

        print(
            f"Name: "
            f"{metadata['cwe_name']}"
        )

        print(
            f"Section: "
            f"{metadata['section']}"
        )

        print(
            "\nContent:"
        )

        print(
            result["text"][:1500]
        )


# ============================================================
# Main
# ============================================================

def main():

    # --------------------------------------------------------
    # Load FAISS + metadata
    # --------------------------------------------------------

    index, metadata = load_database()

    # --------------------------------------------------------
    # Load embedding model
    # --------------------------------------------------------

    print(
        "\nLoading embedding model..."
    )

    model = SentenceTransformer(
        EMBEDDING_MODEL
    )

    print(
        "Embedding model loaded."
    )

    # --------------------------------------------------------
    # User query
    # --------------------------------------------------------

    query = input(
        "\nEnter your security question: "
    ).strip()

    if not query:

        print(
            "No query provided."
        )

        return

    # --------------------------------------------------------
    # Retrieve
    # --------------------------------------------------------

    results = retrieve(
        query,
        index,
        metadata,
        model
    )

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    display_results(
        query,
        results
    )


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()