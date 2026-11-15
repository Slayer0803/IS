"""
Main FastAPI Application Entrypoint.
Initializes the API server, database tables, CORS policy, and registers routing modules.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.config import CORS_ORIGINS, DEBUG, ENVIRONMENT, TEMP_SCREENSHOTS_DIR
from backend.database.database import init_db

# Configure structured logging
logging.basicConfig(
    level=logging.INFO if not DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishing-vlm")


# Initialize database tables
init_db()

app = FastAPI(
    title="Vision-Language Model (VLM) for Zero-Day Phishing Detection",
    description="Multimodal cybersecurity API combining visual screenshots, DOM analysis, and URL heuristics to detect zero-day phishing websites.",
    version="1.0.0"
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(router)


@app.get("/", tags=["General"])
async def root():
    """Root metadata endpoint."""
    return {
        "project": "Vision-Language Model (VLM) for Zero-Day Phishing Detection",
        "description": "Multimodal detection pipeline for zero-day phishing pages",
        "status": "online",
        "docs_url": "/docs",
        "health_check": "/health",
        "endpoints": {
            "analyze": "POST /api/analyze",
            "scans": "GET /api/scans",
            "stats": "GET /api/stats",
            "test_pages": "GET /api/test-pages"
        }
    }


if __name__ == "__main__":
    import uvicorn
    from backend.config import HOST, PORT
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=DEBUG)
