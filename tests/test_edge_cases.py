"""
Unit tests for edge cases: empty content, malformed HTML, and timeouts.
"""
import pytest
from backend.security.html_features import extract_html_features
from backend.security.url_features import extract_url_features
from backend.security.ssrf_guard import validate_url_security


def test_empty_html_handling():
    res = extract_html_features("", base_url="https://example.com")
    assert res["html_risk"] == 0.0
    assert res["features"]["title"] == ""
    assert res["features"]["num_forms"] == 0


def test_malformed_html_handling():
    malformed = "<html><head><title>Unclosed Header</title><body><div>Unclosed Div<form action='bad'><input type=password<div>Missing tags"
    res = extract_html_features(malformed, base_url="https://example.com")
    assert res["features"]["has_password_field"] is True
    assert res["features"]["num_forms"] >= 1


def test_excessively_long_url():
    long_url = "https://example.com/" + "a" * 3000
    is_safe, reason = validate_url_security(long_url)
    assert is_safe is False
    assert "exceeds maximum allowed length" in reason


def test_empty_url():
    is_safe, reason = validate_url_security("")
    assert is_safe is False
    assert "empty" in reason

