"""
Centralized Domain Trust & Registrable Domain Extraction Module.
Leverages tldextract to accurately determine registrable apex domains,
strictly distinguishing trusted enterprise apex domains from user-content/PaaS subdomains
(e.g., sites.google.com, github.io, pages.dev).
"""
import re
from typing import Optional, Set, Tuple
import tldextract

# Extract with offline suffix list to avoid network delays
_extract = tldextract.TLDExtract(suffix_list_urls=None)


# User-content, PaaS, and free-hosting multi-tenant hosts that host user-uploaded content.
# NEVER treat these as trusted apex domains even if they belong to Google, Microsoft, Cloudflare, etc.
USER_CONTENT_HOSTS: Set[str] = {
    # Google User Content & Cloud
    "sites.google.com",
    "docs.google.com",
    "forms.google.com",
    "drive.google.com",
    "script.google.com",
    "storage.googleapis.com",
    "firebaseapp.com",
    "web.app",
    "appspot.com",
    "blogspot.com",
    # Microsoft & Azure
    "azurewebsites.net",
    "blob.core.windows.net",
    "cloudapp.net",
    "sharepoint.com",
    "forms.office.com",
    # GitHub / GitLab
    "github.io",
    "gitlab.io",
    # Cloudflare / Fastly / PaaS
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "render.com",
    "surge.sh",
    "glitch.me",
    "repl.co",
    "000webhostapp.com",
    "weebly.com",
    "wixsite.com",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "duckdns.org",
    "loca.lt"
}

# High-reputation global apex domains (registrable domains)
# Legitimate enterprise organizations where official services reside.
HIGH_TRUST_REGISTRABLE_DOMAINS: Set[str] = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "wikipedia.org",
    "wikimedia.org",
    "mozilla.org",
    "w3.org",
    "ietf.org",
    "nih.gov",
    "cdc.gov",
    "nasa.gov",
    "arxiv.org",
    "cloudflare.com",
    "amazon.com",
    "paypal.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "netflix.com",
    "adobe.com"
}

# High-trust public suffixes (Government, Military, Accredited Higher Education)
HIGH_TRUST_SUFFIXES: Set[str] = {"gov", "mil", "edu"}


def parse_domain_parts(url_or_host: str) -> Tuple[str, str, str, str]:
    """
    Parses a URL or host into (subdomain, domain, suffix, registered_domain).
    Example: 'https://login.security.google.com/path' -> ('login.security', 'google', 'com', 'google.com')
    """
    if not url_or_host:
        return "", "", "", ""

    clean = url_or_host.strip()
    if "://" not in clean:
        clean = "http://" + clean

    extracted = _extract(clean)
    subdomain = (extracted.subdomain or "").lower()
    domain = (extracted.domain or "").lower()
    suffix = (extracted.suffix or "").lower()
    registered_domain = (extracted.registered_domain or "").lower()

    return subdomain, domain, suffix, registered_domain


def is_user_content_host(url_or_host: str) -> bool:
    """
    Checks whether a URL or hostname is located on multi-tenant user content hosting
    (e.g. sites.google.com, foo.github.io, bar.pages.dev).
    Such hosts must NEVER receive trusted domain exemptions.
    """
    subdomain, domain, suffix, reg_domain = parse_domain_parts(url_or_host)
    fqdn = f"{subdomain}.{reg_domain}".strip(".") if subdomain else reg_domain

    for uch in USER_CONTENT_HOSTS:
        if fqdn == uch or fqdn.endswith("." + uch):
            return True
    return False


def get_registrable_domain(url_or_host: str) -> str:
    """
    Returns the effective registrable domain (e.g. 'google.com' for 'sites.google.com').
    """
    _, _, _, reg_domain = parse_domain_parts(url_or_host)
    return reg_domain


def is_trusted_domain(url_or_host: str) -> bool:
    """
    Checks whether a domain is a high-reputation domain.
    Returns False immediately if the host is a user-content platform (e.g. sites.google.com),
    preventing open-redirect and user-uploaded phishing bypasses.
    """
    if is_user_content_host(url_or_host):
        return False

    subdomain, domain, suffix, reg_domain = parse_domain_parts(url_or_host)

    if reg_domain in HIGH_TRUST_REGISTRABLE_DOMAINS:
        return True

    # Check for gov / mil / edu
    parts = suffix.split(".")
    if any(p in HIGH_TRUST_SUFFIXES for p in parts):
        return True

    return False

