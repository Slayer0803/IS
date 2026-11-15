"""
Unit tests for URL feature extraction and lexical heuristics.
"""
import pytest
from backend.security.url_features import calculate_entropy, extract_url_features


def test_normal_legitimate_url():
    url = "https://www.google.com/search?q=cybersecurity"
    res = extract_url_features(url)
    assert res["url_risk"] < 0.30
    assert res["features"]["has_ip_address"] is False
    assert res["features"]["uses_https"] is True
    assert res["features"]["is_suspicious_tld"] is False
    assert res["features"]["has_at_symbol"] is False


def test_ip_address_url():
    url = "http://192.168.1.100/admin/login.php"
    res = extract_url_features(url)
    assert res["features"]["has_ip_address"] is True
    assert res["features"]["uses_https"] is False
    assert res["url_risk"] >= 0.35
    assert any("raw IP address" in ind for ind in res["indicators"])


def test_brand_in_subdomain_spoofing():
    url = "https://paypal.com.account-verify-update.xyz/login"
    res = extract_url_features(url)
    assert "paypal" in res["features"]["brand_in_subdomain"]
    assert res["features"]["is_suspicious_tld"] is True
    assert res["url_risk"] > 0.50
    assert any("Brand impersonation in subdomain" in ind for ind in res["indicators"])


def test_at_symbol_credential_masking():
    url = "https://legit-site.com@evil-phishing-host.top/login"
    res = extract_url_features(url)
    assert res["features"]["has_at_symbol"] is True
    assert res["features"]["is_suspicious_tld"] is True
    assert res["url_risk"] >= 0.40


def test_entropy_calculation():
    low_entropy = calculate_entropy("aaaaaaa")
    high_entropy = calculate_entropy("7x9bQ3#zL!p9")
    assert low_entropy == 0.0
    assert high_entropy > 3.0

