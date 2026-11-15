"""
Unit tests for SSRF protection and protocol scheme validation.
"""
from unittest.mock import patch
import socket
import pytest
from backend.security.ssrf_guard import is_private_or_restricted_ip, validate_url_security


def test_reject_dangerous_schemes():
    dangerous_urls = [
        "file:///etc/passwd",
        "file:///C:/Windows/System32/drivers/etc/hosts",
        "gopher://127.0.0.1:70/",
        "ftp://attacker.com/malware.exe",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(document.cookie)",
    ]
    for url in dangerous_urls:
        is_safe, reason = validate_url_security(url)
        assert is_safe is False, f"Expected {url} to be blocked"
        assert "Forbidden" in reason or "Unsupported" in reason


def test_reject_cloud_metadata():
    assert is_private_or_restricted_ip("169.254.169.254") is True
    assert is_private_or_restricted_ip("fd00:ec2::254") is True


def test_reject_private_ips():
    assert is_private_or_restricted_ip("127.0.0.1") is True
    assert is_private_or_restricted_ip("10.0.0.1") is True
    assert is_private_or_restricted_ip("192.168.1.1") is True
    assert is_private_or_restricted_ip("172.16.0.1") is True


def test_allow_legitimate_public_url():
    # Mock public DNS resolution to ensure deterministic behavior regardless of network connectivity
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.190.46", 443))]):
        is_safe, reason = validate_url_security("https://www.google.com")
        assert is_safe is True
        assert "valid" in reason.lower() or "safe" in reason.lower()


def test_reject_local_test_pages_no_localhost_exemption():
    """Phase 1.1: Localhost exemption removed entirely to prevent SSRF and local file reads."""
    is_safe, reason = validate_url_security("http://localhost:8000/test-pages/fake_login_page.html")
    assert is_safe is False
    assert "localhost" in reason.lower() or "blocked" in reason.lower()


def test_nat64_and_ipv4_mapped_validation():
    """
    NAT64 (RFC 6052 Well-Known Prefix 64:ff9b::/96) and IPv4-mapped addresses must allow
    legitimate public internet IPs resolved over DNS64 while strictly blocking private,
    loopback, or cloud metadata targets.
    """
    # Public IPv4 inside NAT64 (e.g. Akamai CDN 23.222.31.90) -> Safe / Allowed
    assert is_private_or_restricted_ip("64:ff9b::17de:1f5a") is False
    assert is_private_or_restricted_ip("::ffff:23.222.31.90") is False

    # Loopback (127.0.0.1) inside NAT64 / IPv4-mapped -> Blocked
    assert is_private_or_restricted_ip("64:ff9b::7f00:1") is True
    assert is_private_or_restricted_ip("::ffff:127.0.0.1") is True

    # Cloud metadata (169.254.169.254) inside NAT64 -> Blocked
    assert is_private_or_restricted_ip("64:ff9b::a9fe:a9fe") is True

    # Private network (10.0.0.1, 192.168.1.1) inside NAT64 -> Blocked
    assert is_private_or_restricted_ip("64:ff9b::0a00:1") is True
    assert is_private_or_restricted_ip("64:ff9b::c0a8:101") is True

