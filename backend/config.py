"""
Configuration management for the VLM Zero-Day Phishing Detection System.
Loads environment variables with robust fallback defaults.
"""
import os
from pathlib import Path
from typing import List

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"
TEMP_SCREENSHOTS_DIR = BASE_DIR / "temp_screenshots"

# Ensure runtime directories exist
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
TEMP_SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
(BACKEND_DIR / "data").mkdir(parents=True, exist_ok=True)

# Server settings
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8000"))
DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

# CORS Origins
_cors_env = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000")
CORS_ORIGINS: List[str] = [origin.strip() for origin in _cors_env.split(",") if origin.strip()]

# VLM Backend Configuration
# Supported options:
# - "heuristic": Fast local computer-vision & layout discrepancy analyzer (Zero-Day Brand Impersonation)
# - "mock": Instant mock responses for automated testing
# - "huggingface": Uses transformers Vision-Language Model (e.g. SmolVLM, Moondream2)
VLM_BACKEND: str = os.getenv("VLM_BACKEND", "heuristic").lower()
VLM_MODEL_ID: str = os.getenv("VLM_MODEL_ID", "HuggingFaceTB/SmolVLM-Instruct")
DEVICE: str = os.getenv("DEVICE", "cpu")

# Multimodal Fusion Weights (Documented initial experimental weights)
WEIGHT_URL: float = float(os.getenv("WEIGHT_URL", "0.20"))
WEIGHT_VISUAL: float = float(os.getenv("WEIGHT_VISUAL", "0.40"))
WEIGHT_TEXT: float = float(os.getenv("WEIGHT_TEXT", "0.25"))
WEIGHT_HTML: float = float(os.getenv("WEIGHT_HTML", "0.15"))

# Classification Thresholds
THRESHOLD_SAFE: float = float(os.getenv("THRESHOLD_SAFE", "0.30"))
THRESHOLD_SUSPICIOUS: float = float(os.getenv("THRESHOLD_SUSPICIOUS", "0.65"))

# Security, Concurrency, and Rate Limit Settings
SSRF_PROTECTION_ENABLED: bool = os.getenv("SSRF_PROTECTION_ENABLED", "True").lower() in ("true", "1", "yes")
PAGE_FETCH_TIMEOUT_SECONDS: int = int(os.getenv("PAGE_FETCH_TIMEOUT_SECONDS", "15"))
MAX_HTML_SIZE_BYTES: int = int(os.getenv("MAX_HTML_SIZE_BYTES", str(5 * 1024 * 1024))) # 5 MB
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
API_KEY: str = os.getenv("API_KEY", "")
MAX_CONCURRENT_BROWSERS: int = int(os.getenv("MAX_CONCURRENT_BROWSERS", "3"))
SCREENSHOT_TTL_SECONDS: int = int(os.getenv("SCREENSHOT_TTL_SECONDS", "3600")) # 1 hour

# ML Baseline Configuration
ENABLE_ML_BASELINE: bool = os.getenv("ENABLE_ML_BASELINE", "True").lower() in ("true", "1", "yes")

# Database Configuration
DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BACKEND_DIR / 'data' / 'phishing_scans.db'}")

