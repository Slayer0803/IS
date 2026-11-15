"""
Database models and Pydantic validation schemas for phishing scan history.
Includes strict validation for custom weights and test-page demonstration selectors.
"""
import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class ScanRequest(BaseModel):
    """Payload for initiating a new phishing analysis scan."""
    url: Optional[str] = Field(
        None,
        description="Target webpage URL to analyze (HTTP or HTTPS)",
        max_length=2048
    )
    test_page_id: Optional[str] = Field(
        None,
        description="Optional ID of controlled local test page for safe zero-day demonstration"
    )
    custom_weights: Optional[Dict[str, float]] = Field(
        None,
        description="Optional custom modality weights: url, visual, text, html (values 0.0 to 1.0, sum > 0)"
    )

    @field_validator("custom_weights")
    @classmethod
    def validate_custom_weights(cls, weights: Optional[Dict[str, float]]) -> Optional[Dict[str, float]]:
        if weights is None:
            return None

        allowed_modalities = {"url", "visual", "text", "html"}
        for key, val in weights.items():
            if key not in allowed_modalities:
                raise ValueError(f"Unknown modality '{key}'. Allowed modality keys: {allowed_modalities}")
            if not isinstance(val, (int, float)) or math.isnan(val) or math.isinf(val):
                raise ValueError(f"Weight for '{key}' must be a finite floating-point number.")
            if val < 0.0 or val > 1.0:
                raise ValueError(f"Weight for '{key}' must be between 0.0 and 1.0 (received {val}).")

        total_weight = sum(weights.values())
        if total_weight <= 0.0:
            raise ValueError("The sum of custom modality weights must be strictly greater than 0.")

        return weights

    @model_validator(mode="after")
    def validate_target_present(self) -> "ScanRequest":
        if not self.url and not self.test_page_id:
            raise ValueError("Either 'url' or 'test_page_id' must be provided for analysis.")
        if self.url:
            cleaned = self.url.strip()
            if len(cleaned) < 3:
                raise ValueError("Provided URL is too short to be valid.")
        return self


class ScanResponse(BaseModel):
    """Complete structured response from a phishing analysis scan."""
    id: Optional[int] = None
    url: str
    hostname: str
    classification: str
    risk_score: float
    confidence: float
    is_unreachable: Optional[bool] = False
    unreachable_reason: Optional[str] = None
    screenshot_preview: Optional[str] = None
    analysis: Dict[str, Any]
    sub_scores: Dict[str, float]
    categorized_indicators: Dict[str, List[str]]
    explanation: List[str]
    created_at: Optional[str] = None


class ScanSummary(BaseModel):
    """Lightweight summary item for recent scan feeds."""
    id: int
    url: str
    hostname: str
    timestamp: str
    classification: str
    risk_score: float
    confidence: float
    url_score: float
    visual_score: float
    text_score: float
    html_score: float
    explanation_summary: str


class DashboardStats(BaseModel):
    """Aggregated scan metrics for executive cybersecurity dashboard."""
    total_scans: int
    phishing_count: int
    safe_count: int
    suspicious_count: int
    average_risk_score: float
    detection_rate: float
