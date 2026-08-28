from fastapi import (
    APIRouter,
    HTTPException
)

from pydantic import BaseModel

from app.sast.service import (
    scan_code
)

from app.classifier.codebert import (
    CodeBERTClassifier
)

from app.core.config import (
    MODEL_PATH
)


router = APIRouter(
    prefix="/api/analysis",
    tags=["Analysis"]
)


classifier = CodeBERTClassifier(
    MODEL_PATH
)


class AnalysisRequest(BaseModel):

    filename: str

    code: str


@router.post("/scan")
def analyze_code(
    request: AnalysisRequest
):

    try:

        # ------------------------
        # 1. SAST
        # ------------------------

        sast_result = scan_code(
            code=request.code,
            filename=request.filename
        )

        # ------------------------
        # 2. CodeBERT
        # ------------------------

        classifier_result = (
            classifier.predict(
                request.code
            )
        )

        # ------------------------
        # 3. Combined result
        # ------------------------

        return {

            "file": request.filename,

            "language": (
                sast_result.language
            ),

            "sast": (
                sast_result.model_dump()
            ),

            "classifier": (
                classifier_result
            )

        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )