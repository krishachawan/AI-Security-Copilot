# CWE RAG Pipeline (audited + fixed)

## What changed vs. the original project

See the full audit in the chat response. Summary of code changes:

| File | Status | Change |
|---|---|---|
| `src/parse_cwe.py` | Rewritten | Preserves structure of complex XML fields (Common_Consequences, Potential_Mitigations, Detection_Methods, Demonstrative_Examples, Observed_Examples, Modes_Of_Introduction, Applicable_Platforms) instead of flattening to text. Fixes `Applicable_Platforms` being silently empty for every CWE. |
| `src/chunk_cwe.py` | Rewritten | Renders structured fields into clean labelled text. Splits Demonstrative_Examples into one chunk per example (language-tagged). Enforces a 350-word chunk ceiling. Skips `Deprecated` CWEs. |
| `src/build_vector_db.py` | Unchanged | Already correct (BGE-recommended: no instruction prefix on passages, only on queries; `IndexFlatIP` + normalized embeddings for cosine similarity). |
| `src/retrieve_cwe.py` | One bug fix | Diversity cap in `select_diverse_results` was keyed by section name alone, which could silently drop a highly relevant CWE's chunk in multi-CWE natural-language queries. Now keyed by `(cwe_id, section)`. |
| `src/context_builder.py` | New | Deterministic structured LLM context builder (CWE/NAME/DESCRIPTION/IMPACT/DETECTION/REMEDIATION/EXAMPLES/SOURCE), with a character budget and per-CWE grouping. |
| `src/evaluate.py` | New | Curated 13-query test set + Hit Rate@K, Recall@K, MRR, latency. Nothing like this existed before. |
| `src/check_chunks.py` | Unchanged | Fine as a manual debug script. |

## Pipeline

```
data/raw/cwec_v4.20.xml
  -> python src/parse_cwe.py          -> data/processed/cwe.json
  -> python src/chunk_cwe.py          -> data/processed/cwe_chunks.json
  -> python src/build_vector_db.py    -> data/vector_db/cwe.index, cwe_metadata.json
  -> python src/retrieve_cwe.py       (interactive query)
  -> python src/evaluate.py           -> data/eval_results.json
```

`data/processed/cwe.json` and `cwe_chunks.json` in this delivery were
already regenerated with the fixed parser/chunker and verified. You
need to rerun `build_vector_db.py` yourself (needs internet access to
download `BAAI/bge-small-en-v1.5` from Hugging Face the first time,
which wasn't reachable in the sandbox this was built in) and then
`evaluate.py` to get real Hit Rate / Recall / MRR / latency numbers
for your report.

## Notes

- `dataset/all_c_cpp_release2.0.csv` (Big-Vul) is unrelated to this
  RAG pipeline and was left out of this delivery; it belongs with
  your detector training work, not the CWE knowledge base.
