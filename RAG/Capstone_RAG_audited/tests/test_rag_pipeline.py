import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from retrieve_cwe import load_database, retrieve, EMBEDDING_MODEL
from context_builder import build_context
from sentence_transformers import SentenceTransformer


def main():

    query = "How do I fix CWE-78 command injection in Python?"

    print("=" * 80)
    print("RAG PIPELINE TEST")
    print("=" * 80)

    # Load database
    index, metadata = load_database()

    # Load embedding model
    print("\nLoading embedding model...")
    model = SentenceTransformer(EMBEDDING_MODEL)
    print("Embedding model loaded.")

    # Retrieve
    print("\nRetrieving...")
    results = retrieve(
        query,
        index,
        metadata,
        model
    )

    print(f"\nRetrieved {len(results)} results.")

    # Build context
    print("\nBuilding LLM context...")
    context = build_context(results)

    print("\n" + "=" * 80)
    print("FINAL LLM CONTEXT")
    print("=" * 80)
    print(context)

    # Basic validation
    assert context, "Context is empty."

    assert "CWE-78" in context, \
        "CWE-78 missing from context."

    assert "OS Command Injection" in context, \
        "CWE name missing from context."

    assert "REMEDIATION:" in context, \
        "Remediation section missing from context."

    print("\n" + "=" * 80)
    print("TEST PASSED")
    print("=" * 80)


if __name__ == "__main__":
    main()