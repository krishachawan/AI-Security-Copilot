from fastapi import (
    APIRouter,
    HTTPException
)

from pydantic import BaseModel

from app.analysis.service import (
    analyze_code
)


router = APIRouter(
    prefix="/api",
    tags=["Analysis"]
)


class AnalyzeRequest(BaseModel):

    filename: str

    code: str


@router.post("/analyze")
def analyze(
    request: AnalyzeRequest
):

    try:

        result = analyze_code(
            code=request.code,
            filename=request.filename
        )

        return result

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {exc}"
        )