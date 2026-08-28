"""
Evaluation harness for the CWE RAG pipeline.

This did not exist anywhere in the original project -- check_chunks.py
is a manual eyeball-the-output debug script, not a metric-producing
evaluator. Requirement 16 (evaluation methodology) was entirely
unaddressed, and without it every scoring weight in retrieve_cwe.py's
SECTION_PRIORITIES is an unverified guess, which is a real problem for
"academically defensible."

Metrics, all standard IR metrics appropriate for a Capstone report:

- Hit Rate@K: fraction of queries where at least one gold chunk
  appears in the top K results.
- Recall@K: for queries with multiple gold chunks (e.g. "give me
  everything about CWE-89"), fraction of gold chunks found in top K.
- MRR (Mean Reciprocal Rank): 1 / rank of the first gold chunk,
  averaged across queries. Rewards ranking the right answer FIRST,
  not just anywhere in the top K -- directly measures the "CWE-78
  Potential Mitigations should be Rank 1" requirement.
- Latency: wall-clock time per query (embedding + FAISS search +
  scoring + diversity filtering), reported as mean/median/p95.

Gold labels are defined at the (cwe_id, section) level rather than
exact chunk id, because chunk ids can shift as chunking strategy
changes (e.g. demonstrative examples are now split into
CWE-78-demonstrative_example-1, -2, ... instead of one
CWE-78-demonstrative_examples chunk) -- (cwe_id, section) is the
stable unit that actually matters for "did the LLM get the right
information," and it survives that kind of internal refactor.

Usage:
    python src/evaluate.py
"""

import json
import statistics
import time
from pathlib import Path

from retrieve_cwe import load_database, retrieve
from sentence_transformers import SentenceTransformer


EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
RESULTS_PATH = Path("data/eval_results.json")

# K values to report Hit Rate / Recall at.
K_VALUES = [1, 3, 5]


# ============================================================
# Curated test set
#
# Each case: query, and gold = list of (cwe_id, section) pairs that
# should appear in results. Covers: CWE-ID + intent combinations
# (explanation/remediation/detection/examples), and natural-language
# queries with no explicit CWE ID.
# ============================================================

TEST_CASES = [
    # --- Explicit CWE ID, explanation intent -> Description ---
    {
        "query": "What is CWE-22 path traversal?",
        "gold": [("CWE-22", "Description")],
    },
    {
        "query": "Explain CWE-79 cross-site scripting",
        "gold": [("CWE-79", "Description")],
    },

    # --- Explicit CWE ID, remediation intent -> Potential Mitigations ---
    {
        "query": "How do I fix CWE-78 command injection in Python?",
        "gold": [("CWE-78", "Potential Mitigations")],
    },
    {
        "query": "How can I prevent CWE-89 SQL injection?",
        "gold": [("CWE-89", "Potential Mitigations")],
    },
    {
        "query": "What mitigations exist for CWE-352 CSRF?",
        "gold": [("CWE-352", "Potential Mitigations")],
    },

    # --- Explicit CWE ID, detection intent -> Detection Methods ---
    {
        "query": "How can CWE-78 be detected?",
        "gold": [("CWE-78", "Detection Methods")],
    },
    {
        "query": "How do static analysis tools detect CWE-502 deserialization issues?",
        "gold": [("CWE-502", "Detection Methods")],
    },

    # --- Explicit CWE ID, examples intent -> Demonstrative Examples ---
    {
        "query": "Show me examples of CWE-89 SQL injection",
        "gold": [("CWE-89", "Demonstrative Examples")],
    },
    {
        "query": "Give me a vulnerable code example for CWE-798 hardcoded credentials",
        "gold": [("CWE-798", "Demonstrative Examples")],
    },

    # --- Explicit CWE ID, impact / consequence intent ---
    {
        "query": "What is the impact of CWE-79 cross-site scripting?",
        "gold": [("CWE-79", "Common Consequences")],
    },

    # --- Natural language, no explicit CWE ID ---
    {
        "query": "What weakness allows an attacker to run arbitrary OS commands?",
        "gold": [("CWE-78", "Description")],
    },
    {
        "query": "What vulnerability lets a user read files outside a restricted directory?",
        "gold": [("CWE-22", "Description")],
    },
    {
        "query": "What is SQL injection?",
        "gold": [("CWE-89", "Description")],
    },
    {
        "query": "How do hardcoded passwords in source code become a security risk?",
        "gold": [("CWE-798", "Description")],
    },
]


# ============================================================
# Metric computation
# ============================================================

def result_key(candidate):
    md = candidate["result"]["metadata"]
    return (md["cwe_id"], md["section"])


def hit_rate_at_k(ranked_keys, gold, k):
    top_k = set(ranked_keys[:k])
    return 1.0 if top_k & set(gold) else 0.0


def recall_at_k(ranked_keys, gold, k):
    if not gold:
        return None
    top_k = set(ranked_keys[:k])
    found = top_k & set(gold)
    return len(found) / len(gold)


def reciprocal_rank(ranked_keys, gold):
    gold_set = set(gold)
    for rank, key in enumerate(ranked_keys, start=1):
        if key in gold_set:
            return 1.0 / rank
    return 0.0


# ============================================================
# Runner
# ============================================================

def run_evaluation():
    print("Loading FAISS index + metadata...")
    index, metadata = load_database()

    print("Loading embedding model...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    per_query_results = []
    latencies = []

    for case in TEST_CASES:
        query = case["query"]
        gold = case["gold"]

        start = time.perf_counter()
        results = retrieve(query, index, metadata, model)
        elapsed = time.perf_counter() - start
        latencies.append(elapsed)

        ranked_keys = [result_key(c) for c in results]

        record = {
            "query": query,
            "gold": gold,
            "retrieved": ranked_keys,
            "latency_sec": round(elapsed, 4),
            "mrr": reciprocal_rank(ranked_keys, gold),
        }

        for k in K_VALUES:
            record[f"hit_rate@{k}"] = hit_rate_at_k(ranked_keys, gold, k)
            record[f"recall@{k}"] = recall_at_k(ranked_keys, gold, k)

        per_query_results.append(record)

    return per_query_results, latencies


def summarize(per_query_results, latencies):
    summary = {"num_queries": len(per_query_results)}

    summary["mrr"] = round(
        statistics.mean(r["mrr"] for r in per_query_results), 4
    )

    for k in K_VALUES:
        summary[f"hit_rate@{k}"] = round(
            statistics.mean(r[f"hit_rate@{k}"] for r in per_query_results), 4
        )
        recalls = [
            r[f"recall@{k}"] for r in per_query_results
            if r[f"recall@{k}"] is not None
        ]
        summary[f"recall@{k}"] = round(statistics.mean(recalls), 4) if recalls else None

    summary["latency_mean_ms"] = round(statistics.mean(latencies) * 1000, 2)
    summary["latency_median_ms"] = round(statistics.median(latencies) * 1000, 2)
    if len(latencies) >= 2:
        sorted_lat = sorted(latencies)
        p95_idx = min(int(len(sorted_lat) * 0.95), len(sorted_lat) - 1)
        summary["latency_p95_ms"] = round(sorted_lat[p95_idx] * 1000, 2)

    return summary


def main():
    per_query_results, latencies = run_evaluation()
    summary = summarize(per_query_results, latencies)

    print("\n" + "=" * 70)
    print("EVALUATION SUMMARY")
    print("=" * 70)
    for key, value in summary.items():
        print(f"{key:20s}: {value}")

    print("\nPer-query failures (MRR < 1.0, i.e. gold not ranked #1):")
    for r in per_query_results:
        if r["mrr"] < 1.0:
            print(f"  - '{r['query']}'")
            print(f"      gold={r['gold']}  top3={r['retrieved'][:3]}  mrr={r['mrr']:.3f}")

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_PATH.open("w", encoding="utf-8") as f:
        json.dump(
            {"summary": summary, "per_query": per_query_results},
            f, indent=2, ensure_ascii=False
        )
    print(f"\nFull results saved to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
