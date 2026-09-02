import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


BASE_DIR = Path(
    __file__
).resolve().parents[2]


MODEL_PATH = Path(
    os.getenv(
        "CODEBERT_MODEL_PATH",
        BASE_DIR / "models" / "codebert"
    )
)


SAST_WORKSPACE = Path(
    os.getenv(
        "SAST_WORKSPACE",
        BASE_DIR / "sast_workspace"
    )
)


SEMGREP_TIMEOUT = int(
    os.getenv(
        "SEMGREP_TIMEOUT",
        "120"
    )
)


BANDIT_TIMEOUT = int(
    os.getenv(
        "BANDIT_TIMEOUT",
        "60"
    )
)


MAX_CODE_SIZE = int(
    os.getenv(
        "MAX_CODE_SIZE",
        "500000"
    )
)


SAST_WORKSPACE.mkdir(
    parents=True,
    exist_ok=True
)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-2.5-flash"
)
