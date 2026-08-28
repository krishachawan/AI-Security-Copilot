from fastapi import FastAPI

from app.api.routes.sast import (
    router as sast_router
)

from app.api.routes.analyze import (
    router as analyze_router
)


app = FastAPI(
    title="AI Security Copilot",
    version="1.0.0"
)


app.include_router(
    sast_router
)

app.include_router(
    analyze_router
)


@app.get("/")
def root():

    return {
        "message": "AI Security Copilot API"
    }