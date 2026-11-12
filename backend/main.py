import os
import sys
from contextlib import asynccontextmanager

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router as api_router
from backend.assets.generator import create_all_sample_assets


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize sample documents folder on startup
    sample_dir = os.path.join(os.path.dirname(__file__), "assets", "samples")
    create_all_sample_assets(sample_dir)
    yield


app = FastAPI(
    title="PS13 Government Document PII Detector & Redactor API",
    description="Enterprise-grade Indian Government Document PII detection, redaction, and compliance audit API.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for Web/Streamlit integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "name": "PS13 Government Document PII Detector API",
        "status": "ONLINE",
        "docs": "/docs",
        "health": "/api/health",
        "compliance": "DPDP Act 2023 & Aadhaar Act 2016 Compliant"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
