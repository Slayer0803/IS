"""
URL Lexical, Structural, and Threat Heuristic Feature Extractor.
Extracts rich security features from target URLs to detect zero-day phishing patterns,
including brand impersonation in subdomains, free-tier hosting abuse (pages.dev, vercel.app, etc.),
deceptive homographs, high entropy, and ephemeral scam TLDs.
"""
import math
import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlparse


# Suspicious TLDs commonly leveraged in cheap, ephemeral zero-day phishing campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "buzz", "rest", "fit",
    "surf", "monster", "icu", "cam", "bid", "stream", "live", "link", "club", "online",
    "support", "secure", "vip", "account", "login", "auth", "cfd", "sbs", "cyou",
    "beauty", "hair", "quest", "bond", "boats", "yachts", "skin", "ru", "cn", "cc", "ws"
}

# Free/PaaS hosting providers heavily abused by attackers to host zero-day phishing pages
FREE_HOSTING_DOMAINS = {
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "firebaseio.com",
    "vercel.app", "netlify.app", "appspot.com", "github.io", "gitlab.io", "webflow.io",
    "glitch.me", "repl.co", "render.com", "surge.sh", "ngrok-free.app", "ngrok.io",
    "loca.lt", "trycloudflare.com", "duckdns.org", "no-ip.com", "000webhostapp.com",
    "weebly.com", "wixsite.com", "blogspot.com", "azurewebsites.net"
}

# Suspicious keywords frequently embedded into phishing URLs/paths
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "account", "update", "banking", "authenticate", "confirm", "security",
    "suspended", "unlock", "recover", "password", "credential", "appleid",
    "microsoft", "office365", "paypal", "google", "wellsfargo", "chase",
    "citi", "bankofamerica", "netflix", "support-desk", "billing", "invoice",
    "wallet", "airdrop", "claim", "seed", "phrase", "prize", "winner", "gift",
    "support", "alert", "notice", "parcel", "delivery", "tracking", "shipment",
    "tax", "refund", "auth", "portal", "helpdesk", "resolve", "connect",
    "phishing", "social-engineering", "scam", "fraud", "fake", "stealer",
    "trojan", "drainer", "malware", "safebrowsing"
]

# Major targeted brand tokens for subdomain/path spoofing detection
COMMON_BRAND_TOKENS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "wellsfargo", "chase", "citibank", "bankofamerica", "binance",
    "coinbase", "metamask", "trustwallet", "whatsapp", "telegram", "yahoo",
    "outlook", "office", "docusign", "adobe", "usps", "dhl", "fedex", "ups",
    "steam", "spotify", "linkedin", "amex", "capitalone"
]

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
HEX_OR_ENCODED_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string to detect randomized/DGA strings."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features(url: str, redirect_count: int = 0) -> Dict[str, Any]:
    """
    Extracts comprehensive lexical and structural security features from a URL.
    Returns:
        Dict containing raw feature metrics, risk score [0.0 - 1.0], and explainable indicators.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    url_length = len(url)
    domain_length = len(hostname)

    # Domain breakdown
    domain_parts = hostname.split(".")
    tld = domain_parts[-1].lower() if domain_parts else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_subdomains = max(0, len(domain_parts) - 2) if len(domain_parts) > 1 else 0

    # Special characters check
    special_chars = set("!$&'()*+,;=~_%[]:@")
    num_special_chars = sum(1 for c in url if c in special_chars)

    # IP address check
    has_ip_address = bool(IPV4_PATTERN.match(hostname))

    # Scheme
    uses_https = parsed.scheme.lower() == "https"

    # Suspicious symbols
    has_at_symbol = "@" in url
    has_url_encoding = bool(HEX_OR_ENCODED_PATTERN.search(url))

    # Path & Query complexity
    path_depth = len([p for p in path.split("/") if p])
    query_params = parse_qs(query)
    query_param_count = len(query_params)

    # Apex domain & subdomains definition
    apex_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
    subdomain_part = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

    # Suspicious keywords in URL (exclude legitimate apex domain name)
    url_lower = url.lower()
    found_keywords = [
        kw for kw in SUSPICIOUS_KEYWORDS
        if kw in url_lower and kw not in apex_domain
    ]
    suspicious_keywords_count = len(found_keywords)

    # Free PaaS Hosting abuse check (e.g. brand-security.pages.dev)
    is_free_hosting_abuse = any(hostname.endswith("." + fhd) or hostname == fhd for fhd in FREE_HOSTING_DOMAINS)

    # Brand spoofing in subdomain/path
    brand_in_subdomain = []

    for brand in sorted(COMMON_BRAND_TOKENS, key=len, reverse=True):
        brand_pat = re.compile(rf"(^|[-._]){re.escape(brand)}($|[-._])", re.IGNORECASE)
        # Check if brand appears in subdomain or free-hosting prefix while apex domain is not the official brand
        target_str = hostname if is_free_hosting_abuse else subdomain_part
        if brand_pat.search(target_str) and not brand_pat.search(apex_domain):
            brand_in_subdomain.append(brand)

    # Shannon Entropy of domain and full URL
    domain_entropy = calculate_entropy(hostname)
    url_entropy = calculate_entropy(url)

    # Risk Calculation (Heuristic scoring for URL modality)
    risk_points = 0.0
    indicators: List[str] = []

    if has_ip_address:
        risk_points += 0.50
        indicators.append("URL uses raw IP address instead of legitimate domain name")

    if not uses_https:
        risk_points += 0.20
        indicators.append("Connection is not secured with HTTPS")

    if is_suspicious_tld:
        risk_points += 0.35
        indicators.append(f"Suspicious high-risk TLD (.{tld}) commonly used in ephemeral scam campaigns")

    if has_at_symbol:
        risk_points += 0.40
        indicators.append("Presence of '@' character in URL (credentials masking technique)")

    if brand_in_subdomain:
        risk_points += 0.50
        indicators.append(
            f"Brand impersonation in subdomain/host: '{brand_in_subdomain[0]}' hosted on external infrastructure '{apex_domain}'"
        )

    if is_free_hosting_abuse and (suspicious_keywords_count > 0 or brand_in_subdomain):
        risk_points += 0.35
        indicators.append("Abuse of free/PaaS cloud hosting (pages.dev/vercel/firebase) with security keywords")

    if num_subdomains >= 3:
        risk_points += 0.20
        indicators.append(f"Excessive subdomain depth ({num_subdomains} subdomains)")

    if num_hyphens >= 3:
        risk_points += 0.18
        indicators.append(f"Unusually high number of hyphens ({num_hyphens}) in domain/URL")

    if num_dots >= 4:
        risk_points += 0.15
        indicators.append(f"Excessive number of dots ({num_dots}) in URL")

    if url_length > 85:
        risk_points += 0.15
        indicators.append(f"Excessively long URL ({url_length} characters)")

    if domain_entropy > 4.2:
        risk_points += 0.25
        indicators.append(f"High domain entropy ({domain_entropy:.2f}) indicates potential algorithmically generated domain (DGA)")

    if suspicious_keywords_count >= 2:
        risk_points += 0.30
        indicators.append(f"Multiple security/credential keywords detected in URL: {', '.join(found_keywords[:3])}")
    elif suspicious_keywords_count == 1:
        risk_points += 0.12
        indicators.append(f"Security-sensitive keyword in URL: '{found_keywords[0]}'")

    if has_url_encoding:
        risk_points += 0.15
        indicators.append("URL contains hex/percent-encoding to obscure target destination")

    if redirect_count >= 2:
        risk_points += 0.25
        indicators.append(f"Multiple HTTP redirects ({redirect_count}) detected")

    # Normalize URL risk score between 0.0 and 1.0
    url_risk = min(1.0, round(risk_points, 3))

    features: Dict[str, Any] = {
        "url": url,
        "hostname": hostname,
        "apex_domain": apex_domain,
        "url_length": url_length,
        "domain_length": domain_length,
        "num_subdomains": num_subdomains,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_special_chars": num_special_chars,
        "has_ip_address": has_ip_address,
        "uses_https": uses_https,
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "is_free_hosting_abuse": is_free_hosting_abuse,
        "has_at_symbol": has_at_symbol,
        "has_url_encoding": has_url_encoding,
        "redirect_count": redirect_count,
        "path_depth": path_depth,
        "query_param_count": query_param_count,
        "suspicious_keywords_found": found_keywords,
        "brand_in_subdomain": brand_in_subdomain,
        "domain_entropy": domain_entropy,
        "url_entropy": url_entropy,
    }

    return {
        "url_risk": url_risk,
        "features": features,
        "indicators": indicators,
    }
