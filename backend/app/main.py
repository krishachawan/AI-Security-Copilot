from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.sast import router as sast_router
from app.api.routes.analyze import router as analyze_router


app = FastAPI(
    title="AI Security Copilot",
    version="1.0.0"
)


# Allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(sast_router)
app.include_router(analyze_router)


@app.get("/")
def root():
    return {
        "message": "AI Security Copilot API"
    }