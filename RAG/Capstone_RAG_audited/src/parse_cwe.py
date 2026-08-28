"""
CWE XML -> structured JSON parser.

Key change vs. the original version:
    The original implementation flattened every "complex" section
    (Common_Consequences, Potential_Mitigations, Detection_Methods,
    Demonstrative_Examples, Observed_Examples, Modes_Of_Introduction,
    Applicable_Platforms) with `" ".join(element.itertext())`.

    That approach throws away structure that lives in *attributes*
    (Scope, Impact, Phase, Strategy, Language, Nature, Prevalence, ...)
    and interleaves multiple sub-records (e.g. 3 different demonstrative
    examples in 3 different languages) into one undifferentiated blob of
    text with no separators. Two concrete, verified problems this caused:

    1. Applicable_Platforms was ALWAYS empty text, because that section
       only carries attributes (Language Name="Python" Prevalence="Often"),
       no text nodes. `element_text()` legitimately returns "" for every
       single CWE. Downstream, chunk_cwe.py's "applicable_platforms"
       section is therefore 100% dead code -- it produces zero chunks,
       ever. This also means the one place in the raw MITRE data that
       flags "this CWE explicitly applies to Python" was silently
       discarded.

    2. Common_Consequences, Demonstrative_Examples, etc. collapse into
       run-on text, e.g. for CWE-78:
       "Confidentiality Integrity Availability Non-Repudiation Execute
       Unauthorized Code or Commands DoS: Crash, Exit, or Restart ..."
       with no indication of which Scope maps to which Impact, and
       multiple Demonstrative_Example blocks (PHP, then C, then more)
       glued back-to-back with no separators or language labels.

    This version keeps the same output shape (a flat dict per CWE, so
    downstream code isn't broken) but stores complex fields as
    structured Python data (lists of dicts) instead of flattened
    strings. chunk_cwe.py is responsible for rendering that structure
    into clean, readable text for embedding/LLM consumption.
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


XML_PATH = Path("data/raw/cwec_v4.20.xml")
OUTPUT_PATH = Path("data/processed/cwe.json")

NAMESPACE = {
    "cwe": "http://cwe.mitre.org/cwe-7"
}


# ============================================================
# Text helpers
# ============================================================

def clean_text(text):
    """Clean whitespace while preserving readable text."""
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text)
    return text.strip()


def element_text(element):
    """Extract all text contained inside an XML element (flattened)."""
    if element is None:
        return ""

    return clean_text(" ".join(element.itertext()))


def find_text(parent, tag):
    """Convenience: text of a single direct child, or ''."""
    if parent is None:
        return ""
    el = parent.find(f"cwe:{tag}", NAMESPACE)
    return element_text(el)


def find_all_text(parent, tag):
    """Convenience: text of every matching child, as a list."""
    if parent is None:
        return []
    return [
        element_text(el)
        for el in parent.findall(f"cwe:{tag}", NAMESPACE)
        if element_text(el)
    ]


# ============================================================
# Structured field parsers
# ============================================================

def parse_applicable_platforms(element):
    """
    Applicable_Platforms carries NO text nodes -- everything is stored
    as attributes on <Language>/<Technology>/<Operating_System>
    elements, e.g. <Language Name="Python" Prevalence="Often"/>.
    """
    if element is None:
        return []

    platforms = []
    for tag in ("Language", "Technology", "Operating_System", "Architecture"):
        for child in element.findall(f"cwe:{tag}", NAMESPACE):
            entry = {
                "type": tag,
                "name": child.get("Name") or child.get("Class"),
                "prevalence": child.get("Prevalence"),
            }
            if entry["name"]:
                platforms.append(entry)

    return platforms


def parse_common_consequences(element):
    """Each Consequence has 1+ Scope, 1+ Impact, and an optional Note."""
    if element is None:
        return []

    consequences = []
    for cons in element.findall("cwe:Consequence", NAMESPACE):
        entry = {
            "scope": find_all_text(cons, "Scope"),
            "impact": find_all_text(cons, "Impact"),
            "note": find_text(cons, "Note"),
        }
        if entry["scope"] or entry["impact"] or entry["note"]:
            consequences.append(entry)

    return consequences


def parse_modes_of_introduction(element):
    if element is None:
        return []

    modes = []
    for intro in element.findall("cwe:Introduction", NAMESPACE):
        entry = {
            "phase": find_text(intro, "Phase"),
            "note": find_text(intro, "Note"),
        }
        if entry["phase"] or entry["note"]:
            modes.append(entry)

    return modes


def parse_detection_methods(element):
    if element is None:
        return []

    methods = []
    for dm in element.findall("cwe:Detection_Method", NAMESPACE):
        entry = {
            "method": find_text(dm, "Method"),
            "description": find_text(dm, "Description"),
            "effectiveness": find_text(dm, "Effectiveness"),
            "effectiveness_notes": find_text(dm, "Effectiveness_Notes"),
        }
        if entry["method"] or entry["description"]:
            methods.append(entry)

    return methods


def parse_potential_mitigations(element):
    if element is None:
        return []

    mitigations = []
    for mit in element.findall("cwe:Mitigation", NAMESPACE):
        entry = {
            "phase": find_all_text(mit, "Phase"),
            "strategy": find_text(mit, "Strategy"),
            "description": find_text(mit, "Description"),
        }
        if entry["description"]:
            mitigations.append(entry)

    return mitigations


def parse_demonstrative_examples(element):
    """
    Each Demonstrative_Example is an ORDERED mix of Intro_Text,
    Example_Code (with Nature/Language attributes), and Body_Text.
    We preserve that order as a list of typed segments so the
    language of each code snippet is never lost, and so multiple
    examples never get glued together without separation.
    """
    if element is None:
        return []

    examples = []
    for demo in element.findall("cwe:Demonstrative_Example", NAMESPACE):
        segments = []
        for child in demo:
            local_tag = child.tag.split("}")[-1]

            if local_tag in ("Intro_Text", "Body_Text"):
                text = element_text(child)
                if text:
                    segments.append({"kind": "text", "content": text})

            elif local_tag == "Example_Code":
                code = element_text(child)
                if code:
                    segments.append({
                        "kind": "code",
                        "nature": child.get("Nature"),
                        "language": child.get("Language"),
                        "content": code,
                    })

        if segments:
            examples.append({"segments": segments})

    return examples


def parse_observed_examples(element):
    if element is None:
        return []

    examples = []
    for obs in element.findall("cwe:Observed_Example", NAMESPACE):
        entry = {
            "reference": find_text(obs, "Reference"),
            "description": find_text(obs, "Description"),
            "link": find_text(obs, "Link"),
        }
        if entry["reference"] or entry["description"]:
            examples.append(entry)

    return examples


def parse_related_weaknesses(element):
    """Extract related CWE IDs + relationship nature, deduplicated."""
    if element is None:
        return []

    seen = set()
    related = []
    for rel in element.findall("cwe:Related_Weakness", NAMESPACE):
        cwe_id = rel.get("CWE_ID")
        nature = rel.get("Nature")
        if not cwe_id:
            continue
        key = (nature, cwe_id)
        if key in seen:
            continue
        seen.add(key)
        related.append({"nature": nature, "cwe_id": f"CWE-{cwe_id}"})

    return related


# ============================================================
# Per-CWE parsing
# ============================================================

def parse_cwe(weakness):
    """Convert one CWE XML element into a Python dictionary."""

    cwe_id = weakness.get("ID")
    name = weakness.get("Name")

    data = {
        "cwe_id": f"CWE-{cwe_id}" if cwe_id else None,
        "name": name,
        "abstraction": weakness.get("Abstraction"),
        "structure": weakness.get("Structure"),
        "status": weakness.get("Status"),
    }

    # Simple text fields (genuinely flat prose -- itertext() is correct here)
    simple_fields = [
        "Description",
        "Background_Details",
        "Likelihood_Of_Exploit",
        "Mapping_Notes",
    ]

    for field in simple_fields:
        element = weakness.find(f"cwe:{field}", NAMESPACE)
        data[field.lower()] = element_text(element)

    # Structured fields -- parsed to preserve their real shape.
    data["applicable_platforms"] = parse_applicable_platforms(
        weakness.find("cwe:Applicable_Platforms", NAMESPACE)
    )
    data["common_consequences"] = parse_common_consequences(
        weakness.find("cwe:Common_Consequences", NAMESPACE)
    )
    data["modes_of_introduction"] = parse_modes_of_introduction(
        weakness.find("cwe:Modes_Of_Introduction", NAMESPACE)
    )
    data["detection_methods"] = parse_detection_methods(
        weakness.find("cwe:Detection_Methods", NAMESPACE)
    )
    data["potential_mitigations"] = parse_potential_mitigations(
        weakness.find("cwe:Potential_Mitigations", NAMESPACE)
    )
    data["demonstrative_examples"] = parse_demonstrative_examples(
        weakness.find("cwe:Demonstrative_Examples", NAMESPACE)
    )
    data["observed_examples"] = parse_observed_examples(
        weakness.find("cwe:Observed_Examples", NAMESPACE)
    )
    data["related_weaknesses"] = parse_related_weaknesses(
        weakness.find("cwe:Related_Weaknesses", NAMESPACE)
    )

    # Kept as flattened text: low RAG value, high structural noise.
    data["weakness_ordinalities"] = find_text(weakness, "Weakness_Ordinalities")
    data["references"] = find_text(weakness, "References")
    data["content_history"] = find_text(weakness, "Content_History")

    # Convenience flag used downstream (chunking, ranking, eval) to
    # identify CWEs the raw MITRE data explicitly ties to Python.
    data["is_python_relevant"] = any(
        p["name"] and "python" in p["name"].lower()
        for p in data["applicable_platforms"]
    )

    return data


# ============================================================
# Main
# ============================================================

def main():
    print("Loading CWE XML...")

    tree = ET.parse(XML_PATH)
    root = tree.getroot()

    weaknesses = root.find("cwe:Weaknesses", NAMESPACE)

    if weaknesses is None:
        raise RuntimeError("Could not find Weaknesses section.")

    print(f"Found {len(weaknesses)} CWE entries.")

    cwes = []

    for weakness in weaknesses:
        cwe = parse_cwe(weakness)
        cwes.append(cwe)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(
            cwes,
            file,
            indent=2,
            ensure_ascii=False
        )

    deprecated = sum(1 for c in cwes if c["status"] == "Deprecated")
    python_tagged = sum(1 for c in cwes if c["is_python_relevant"])

    print(f"Saved {len(cwes)} CWE entries.")
    print(f"  Deprecated entries included: {deprecated}")
    print(f"  Entries explicitly tagged Python-relevant: {python_tagged}")
    print(f"Output: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
