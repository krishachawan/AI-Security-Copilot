import json
from pathlib import Path

PATH = Path("data/processed/cwe_chunks.json")

with PATH.open("r", encoding="utf-8") as f:
    chunks = json.load(f)

print("Total chunks:", len(chunks))

print("\nFirst 5 chunks:\n")

for chunk in chunks[:5]:
    print("=" * 70)
    print("ID:", chunk["id"])
    print("CWE:", chunk["metadata"]["cwe_id"])
    print("Section:", chunk["metadata"]["section"])
    print("Text length:", len(chunk["text"]))
    print("Text:")
    print(chunk["text"][:500])