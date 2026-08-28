"""
Turns the ranked chunk list from retrieve_cwe.retrieve() into a single
structured, deterministic context block for the LLM.

Why this exists as its own module instead of living in retrieve_cwe.py:
retrieval (what's relevant) and context construction (how it's
presented to the LLM) are different responsibilities with different
failure modes -- retrieval bugs show up as wrong chunks, context
bugs show up as wasted tokens or a confused LLM. Keeping them separate
also means the eventual vulnerability detector can call
`build_context()` directly with its own retrieved chunks without
depending on retrieve_cwe's CLI/model-loading code.

Design:
- Groups selected chunks by CWE, then by section within each CWE, in
  a fixed section order (not retrieval-score order) so the LLM always
  sees CWE -> NAME -> DESCRIPTION -> IMPACT -> DETECTION -> REMEDIATION
  -> EXAMPLES -> SOURCE in the same shape regardless of query.
- Deduplicates: if diversity filtering ever lets two chunks from the
  same CWE+section through (e.g. a split "part 2 of 2"), they are
  concatenated once under one heading instead of repeated headers.
- Deterministic: no randomness, no wall-clock-dependent ordering --
  same input chunks always produce the same output string, which
  matters for reproducible evaluation and grading.
- Hard character budget (MAX_CONTEXT_CHARS) so a very verbose CWE
  (many mitigations + examples) can't blow out the LLM's context
  window; sections are trimmed in reverse-priority order, never mid-
  sentence for the highest-priority section.
"""

from textwrap import shorten


# Fixed presentation order -- independent of retrieval/intent ranking.
SECTION_ORDER = [
    "Description",
    "Common Consequences",
    "Detection Methods",
    "Potential Mitigations",
    "Demonstrative Examples",
    "Observed Examples",
    "Modes of Introduction",
    "Applicable Platforms",
    "Background",
]

SECTION_TO_LABEL = {
    "Description": "DESCRIPTION",
    "Common Consequences": "IMPACT",
    "Detection Methods": "DETECTION",
    "Potential Mitigations": "REMEDIATION",
    "Demonstrative Examples": "EXAMPLES",
    "Observed Examples": "REAL_WORLD_EXAMPLES",
    "Modes of Introduction": "INTRODUCED_DURING",
    "Applicable Platforms": "APPLIES_TO",
    "Background": "BACKGROUND",
}

MAX_CONTEXT_CHARS = 6000

# When trimming for budget, cut from the lowest-priority sections first.
TRIM_PRIORITY = list(reversed(SECTION_ORDER))


def _strip_header(chunk_text):
    """
    Chunks are stored with a
        "CWE ID: ...\nCWE Name: ...\nSection: ...\n\n"
    header (see chunk_cwe.make_header). Strip it here since the
    context builder adds its own structured header per CWE -- keeping
    both would duplicate the CWE ID/name on every single section.
    """
    marker = "\n\n"
    idx = chunk_text.find(marker)
    if idx == -1:
        return chunk_text.strip()
    return chunk_text[idx + len(marker):].strip()


def _group_by_cwe(results):
    """results -> {cwe_id: {"name": ..., "sections": {section: [texts]}}}"""
    grouped = {}

    for candidate in results:
        result = candidate["result"]
        metadata = result["metadata"]
        cwe_id = metadata["cwe_id"]
        section = metadata["section"]

        entry = grouped.setdefault(cwe_id, {
            "name": metadata["cwe_name"],
            "sections": {},
        })

        entry["sections"].setdefault(section, [])
        body = _strip_header(result["text"])

        # Deduplicate identical bodies (can happen if a chunk was
        # retrieved via both semantic search and exact-CWE lookup).
        if body not in entry["sections"][section]:
            entry["sections"][section].append(body)

    return grouped


def _render_cwe_block(cwe_id, entry, char_budget):
    lines = [f"CWE:\n{cwe_id}", "", f"NAME:\n{entry['name']}"]

    # Build each present section fully first, then trim if needed.
    section_blocks = []
    for section in SECTION_ORDER:
        bodies = entry["sections"].get(section)
        if not bodies:
            continue
        label = SECTION_TO_LABEL[section]
        text = "\n\n".join(bodies)
        section_blocks.append((section, f"{label}:\n{text}"))

    lines.append("")
    used = len("\n\n".join(lines))

    # Add sections in presentation order while we still have budget;
    # if we run out, drop lowest-priority sections first rather than
    # truncating mid-sentence.
    included = {s: b for s, b in section_blocks}
    total_len = used + sum(len(b) + 2 for b in included.values())

    if total_len > char_budget:
        for section in TRIM_PRIORITY:
            if section not in included:
                continue
            total_len -= len(included[section]) + 2
            del included[section]
            if total_len <= char_budget:
                break

    for section, _ in section_blocks:
        if section in included:
            lines.append(included[section])
            lines.append("")

    lines.append("SOURCE:\nMITRE CWE")

    return "\n".join(lines)


def build_context(results, max_chars=MAX_CONTEXT_CHARS):
    """
    Build the final LLM-facing context string from retrieve_cwe.retrieve()
    output. Splits the overall budget evenly across the distinct CWEs
    present so one verbose CWE can't starve the others.
    """
    if not results:
        return ""

    grouped = _group_by_cwe(results)
    per_cwe_budget = max(max_chars // len(grouped), 800)

    blocks = [
        _render_cwe_block(cwe_id, entry, per_cwe_budget)
        for cwe_id, entry in grouped.items()
    ]

    return "\n\n---\n\n".join(blocks)


if __name__ == "__main__":
    # Small smoke test using a stub, so this file can be sanity-checked
    # without loading the embedding model.
    stub_results = [
        {
            "result": {
                "id": "CWE-78-description",
                "text": (
                    "CWE ID: CWE-78\nCWE Name: OS Command Injection\n"
                    "Section: Description\n\n"
                    "The software constructs an OS command using "
                    "externally-influenced input."
                ),
                "metadata": {
                    "cwe_id": "CWE-78",
                    "cwe_name": "OS Command Injection",
                    "section": "Description",
                },
            }
        },
    ]
    print(build_context(stub_results))
