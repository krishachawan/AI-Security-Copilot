"""
CWE JSON -> retrieval chunks.

Changes vs. the original version, and why:

1. Deprecated CWEs (status == "Deprecated") are skipped. They are
   MITRE-withdrawn/merged entries -- surfacing them to a user asking
   "how do I fix CWE-XXX" as if they were current guidance is actively
   wrong for a defensible RAG system. (25 of 969 entries affected.)

2. Every "complex" section is now rendered from structured data
   (see parse_cwe.py) into clean, labelled text instead of a run-on
   blob. Common_Consequences becomes explicit "Scope -> Impact" lines;
   Potential_Mitigations becomes one bullet per mitigation with its
   Phase/Strategy; Detection_Methods becomes one bullet per method.

3. Demonstrative_Examples are split into ONE CHUNK PER EXAMPLE instead
   of one chunk for the whole (often multi-language, multi-paragraph)
   section. This fixes two real problems found in the original output:
     - CWE-78's demonstrative_examples chunk merged a PHP example and
       a C example into one undifferentiated 800+ word blob with no
       language labels.
     - The largest chunks in the corpus (up to 1755 words, i.e. well
       over BGE's 512-token limit) were almost all multi-example
       Demonstrative_Examples sections that got silently truncated
       during embedding. Per-example chunks are dramatically smaller
       and each one embeds without truncation.
   Each example chunk also carries a `languages` metadata field
   (e.g. ["PHP"]) pulled straight from the XML's Language attribute --
   this is what lets a downstream step boost/filter for Python later
   without needing a separate classifier.

4. Applicable_Platforms is now a real, if small, chunk when a CWE
   explicitly names specific languages/technologies (previously dead
   code that produced zero chunks for every single CWE).

5. A hard word-count ceiling (MAX_CHUNK_WORDS) splits any remaining
   oversized section (e.g. a CWE with 15+ mitigations) into multiple
   numbered sub-chunks so nothing silently exceeds the embedding
   model's context window.
"""

import json
from pathlib import Path


INPUT_PATH = Path("data/processed/cwe.json")
OUTPUT_PATH = Path("data/processed/cwe_chunks.json")

# BGE-small-en-v1.5 has a 512 token max sequence length. ~350 words is
# a conservative ceiling that stays under that limit even for dense
# technical text (roughly 1.3-1.5 tokens/word for this vocabulary).
MAX_CHUNK_WORDS = 350

SECTION_NAMES = {
    "description": "Description",
    "background": "Background",
    "common_consequences": "Common Consequences",
    "detection_methods": "Detection Methods",
    "potential_mitigations": "Potential Mitigations",
    "demonstrative_examples": "Demonstrative Examples",
    "observed_examples": "Observed Examples",
    "modes_of_introduction": "Modes of Introduction",
    "applicable_platforms": "Applicable Platforms",
}


# ============================================================
# Renderers: structured field -> clean text
# ============================================================

def render_common_consequences(consequences):
    lines = []
    for c in consequences:
        scope = ", ".join(c["scope"]) if c["scope"] else "Unspecified scope"
        impact = ", ".join(c["impact"]) if c["impact"] else "Unspecified impact"
        line = f"- Scope: {scope} | Impact: {impact}"
        if c["note"]:
            line += f"\n  Note: {c['note']}"
        lines.append(line)
    return "\n".join(lines)


def render_modes_of_introduction(modes):
    lines = []
    for m in modes:
        line = f"- Phase: {m['phase'] or 'Unspecified'}"
        if m["note"]:
            line += f" -- {m['note']}"
        lines.append(line)
    return "\n".join(lines)


def render_detection_methods(methods):
    blocks = []
    for m in methods:
        block = f"Method: {m['method']}"
        if m["description"]:
            block += f"\n{m['description']}"
        if m["effectiveness"]:
            block += f"\nEffectiveness: {m['effectiveness']}"
        if m["effectiveness_notes"]:
            block += f"\nEffectiveness Notes: {m['effectiveness_notes']}"
        blocks.append(block)
    return "\n\n".join(blocks)


def render_potential_mitigations(mitigations):
    blocks = []
    for m in mitigations:
        header_bits = []
        if m["phase"]:
            header_bits.append("Phase: " + ", ".join(m["phase"]))
        if m["strategy"]:
            header_bits.append(f"Strategy: {m['strategy']}")
        header = " | ".join(header_bits)
        block = f"{header}\n{m['description']}" if header else m["description"]
        blocks.append(block)
    return "\n\n".join(blocks)


def render_observed_examples(examples):
    lines = []
    for e in examples:
        line = f"- {e['reference']}: {e['description']}"
        if e["link"]:
            line += f" ({e['link']})"
        lines.append(line)
    return "\n".join(lines)


def render_example_segments(segments):
    """Render one Demonstrative_Example's ordered segments."""
    parts = []
    for seg in segments:
        if seg["kind"] == "text":
            parts.append(seg["content"])
        else:
            label_bits = [b for b in (seg.get("language"), seg.get("nature")) if b]
            label = f"[{' / '.join(label_bits)} code]" if label_bits else "[code]"
            parts.append(f"{label}\n{seg['content']}")
    return "\n\n".join(parts)


def render_applicable_platforms(platforms):
    lines = []
    for p in platforms:
        bits = [p["type"], p["name"]]
        if p["prevalence"]:
            bits.append(f"(Prevalence: {p['prevalence']})")
        lines.append("- " + " ".join(b for b in bits if b))
    return "\n".join(lines)


# ============================================================
# Chunk size control
# ============================================================

def split_by_words(text, max_words):
    """Split text into <= max_words pieces on whitespace, never mid-word."""
    words = text.split()
    if len(words) <= max_words:
        return [text]

    pieces = []
    for i in range(0, len(words), max_words):
        pieces.append(" ".join(words[i:i + max_words]))
    return pieces


def make_header(cwe_id, name, section_label, part=None, total_parts=None):
    header = f"CWE ID: {cwe_id}\nCWE Name: {name}\nSection: {section_label}"
    if part is not None:
        header += f" (part {part} of {total_parts})"
    return header + "\n\n"


def base_metadata(cwe, section_label):
    return {
        "source": "MITRE_CWE",
        "cwe_id": cwe["cwe_id"],
        "cwe_name": cwe["name"],
        "section": section_label,
        "abstraction": cwe.get("abstraction"),
        "status": cwe.get("status"),
    }


def emit_chunks(chunks, chunk_id_base, cwe, section_label, body_text, extra_metadata=None):
    """Word-bound a rendered section and append one or more chunk dicts."""
    if not body_text or not body_text.strip():
        return

    pieces = split_by_words(body_text.strip(), MAX_CHUNK_WORDS)
    total = len(pieces)

    for idx, piece in enumerate(pieces, start=1):
        header = make_header(
            cwe["cwe_id"], cwe["name"], section_label,
            part=idx if total > 1 else None,
            total_parts=total if total > 1 else None,
        )
        metadata = base_metadata(cwe, section_label)
        if extra_metadata:
            metadata.update(extra_metadata)

        chunk_id = chunk_id_base if total == 1 else f"{chunk_id_base}-part{idx}"

        chunks.append({
            "id": chunk_id,
            "text": header + piece,
            "metadata": metadata,
        })


# ============================================================
# Main chunking logic
# ============================================================

def chunk_cwe(cwe, chunks):
    cwe_id = cwe["cwe_id"]

    # --- simple text sections ---
    if cwe.get("description"):
        emit_chunks(chunks, f"{cwe_id}-description", cwe,
                    SECTION_NAMES["description"], cwe["description"])

    if cwe.get("background_details"):
        emit_chunks(chunks, f"{cwe_id}-background", cwe,
                    SECTION_NAMES["background"], cwe["background_details"])

    # --- structured sections, rendered ---
    if cwe.get("common_consequences"):
        emit_chunks(chunks, f"{cwe_id}-common_consequences", cwe,
                    SECTION_NAMES["common_consequences"],
                    render_common_consequences(cwe["common_consequences"]))

    if cwe.get("modes_of_introduction"):
        emit_chunks(chunks, f"{cwe_id}-modes_of_introduction", cwe,
                    SECTION_NAMES["modes_of_introduction"],
                    render_modes_of_introduction(cwe["modes_of_introduction"]))

    if cwe.get("detection_methods"):
        emit_chunks(chunks, f"{cwe_id}-detection_methods", cwe,
                    SECTION_NAMES["detection_methods"],
                    render_detection_methods(cwe["detection_methods"]))

    if cwe.get("potential_mitigations"):
        emit_chunks(chunks, f"{cwe_id}-potential_mitigations", cwe,
                    SECTION_NAMES["potential_mitigations"],
                    render_potential_mitigations(cwe["potential_mitigations"]))

    if cwe.get("observed_examples"):
        emit_chunks(chunks, f"{cwe_id}-observed_examples", cwe,
                    SECTION_NAMES["observed_examples"],
                    render_observed_examples(cwe["observed_examples"]))

    if cwe.get("applicable_platforms"):
        emit_chunks(chunks, f"{cwe_id}-applicable_platforms", cwe,
                    SECTION_NAMES["applicable_platforms"],
                    render_applicable_platforms(cwe["applicable_platforms"]))

    # --- demonstrative examples: ONE CHUNK PER EXAMPLE ---
    for ex_idx, example in enumerate(cwe.get("demonstrative_examples", []), start=1):
        body = render_example_segments(example["segments"])
        languages = sorted({
            seg["language"] for seg in example["segments"]
            if seg.get("kind") == "code" and seg.get("language")
        })
        extra = {"languages": languages} if languages else {}
        emit_chunks(
            chunks,
            f"{cwe_id}-demonstrative_example-{ex_idx}",
            cwe,
            SECTION_NAMES["demonstrative_examples"],
            body,
            extra_metadata=extra,
        )


def main():
    print("Loading CWE JSON...")

    with INPUT_PATH.open("r", encoding="utf-8") as file:
        cwes = json.load(file)

    print(f"Loaded {len(cwes)} CWE entries.")

    skipped_deprecated = sum(1 for c in cwes if c.get("status") == "Deprecated")

    chunks = []
    for cwe in cwes:
        if cwe.get("status") == "Deprecated":
            continue
        chunk_cwe(cwe, chunks)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(chunks, file, indent=2, ensure_ascii=False)

    print(f"Skipped {skipped_deprecated} deprecated CWE entries.")
    print(f"Created {len(chunks)} chunks.")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
