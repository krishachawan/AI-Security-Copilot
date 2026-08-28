import json
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


CHUNKS_PATH = Path("data/processed/cwe_chunks.json")
VECTOR_DB_PATH = Path("data/vector_db")

INDEX_PATH = VECTOR_DB_PATH / "cwe.index"
METADATA_PATH = VECTOR_DB_PATH / "cwe_metadata.json"

EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"


def main():

    print("Loading CWE chunks...")

    with CHUNKS_PATH.open("r", encoding="utf-8") as file:
        chunks = json.load(file)

    print(f"Loaded {len(chunks)} chunks.")

    # --------------------------------------------------
    # Load embedding model
    # --------------------------------------------------

    print("\nLoading embedding model...")

    model = SentenceTransformer(EMBEDDING_MODEL)

    print("Embedding model loaded.")

    # --------------------------------------------------
    # Prepare documents
    # --------------------------------------------------

    documents = [
        chunk["text"]
        for chunk in chunks
    ]

    print("\nGenerating embeddings...")

    embeddings = model.encode(
        documents,
        batch_size=32,
        show_progress_bar=True,
        normalize_embeddings=True,
        convert_to_numpy=True
    )

    # FAISS expects float32
    embeddings = embeddings.astype("float32")

    print("Embeddings shape:", embeddings.shape)

    # --------------------------------------------------
    # Create FAISS index
    # --------------------------------------------------

    dimension = embeddings.shape[1]

    print(f"\nCreating FAISS index...")
    print(f"Vector dimension: {dimension}")

    index = faiss.IndexFlatIP(dimension)

    index.add(embeddings)

    print(f"Vectors stored: {index.ntotal}")

    # --------------------------------------------------
    # Save index + metadata
    # --------------------------------------------------

    VECTOR_DB_PATH.mkdir(
        parents=True,
        exist_ok=True
    )

    faiss.write_index(
        index,
        str(INDEX_PATH)
    )

    # Keep the metadata in the exact same order
    metadata = []

    for chunk in chunks:
        metadata.append({
            "id": chunk["id"],
            "text": chunk["text"],
            "metadata": chunk["metadata"]
        })

    with METADATA_PATH.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=2,
            ensure_ascii=False
        )

    print("\n" + "=" * 60)
    print("VECTOR DATABASE CREATED")
    print("=" * 60)

    print(f"Vectors:  {index.ntotal}")
    print(f"Index:    {INDEX_PATH}")
    print(f"Metadata: {METADATA_PATH}")


if __name__ == "__main__":
    main()