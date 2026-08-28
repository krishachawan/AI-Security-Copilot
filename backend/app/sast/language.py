from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".py": "python",
}


def detect_language(filename: str) -> str:
    extension = Path(filename).suffix.lower()

    return SUPPORTED_EXTENSIONS.get(
        extension,
        "unknown"
    )