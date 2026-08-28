from fastapi import (
    APIRouter,
    HTTPException
)

from pydantic import BaseModel

from app.sast.service import (
    scan_code
)


router = APIRouter(
    prefix="/api/sast",
    tags=["SAST"]
)


class SASTRequest(BaseModel):

    filename: str

    code: str


@router.post("/scan")
def scan_sast(
    request: SASTRequest
):

    try:

        result = scan_code(
            code=request.code,
            filename=request.filename
        )

        return result.model_dump()

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"SAST scan failed: {exc}"
        )