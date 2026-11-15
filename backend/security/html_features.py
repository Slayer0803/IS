"""
HTML Structure, Forms, and Security Feature Extractor.
Analyzes rendered or fetched HTML DOM to extract forms, credential fields, external action targets,
scripts, iframes, and semantic security markers.
"""
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


SUSPICIOUS_PHRASES = [
    "verify your account", "account will be suspended", "confirm your identity",
    "login to continue", "reset password", "security alert", "payment required",
    "verify immediately", "unauthorized activity", "temporary lock", "update payment method",
    "billing problem", "validate credentials", "sign in with your account", "session expired",
    "phishing page", "social engineering", "phishing", "trick you", "fake update",
    "software is out-of-date", "mimics a dialogue", "claim your prize", "restore your wallet"
]


def extract_html_features(html_content: str, base_url: str = "") -> Dict[str, Any]:
    """
    Parses HTML document and extracts structural security features, login form configurations,
    cross-domain action mismatches, and text content.
    """
    if not html_content or not isinstance(html_content, str):
        return {
            "html_risk": 0.0,
            "features": {
                "title": "",
                "has_login_form": False,
                "has_password_field": False,
                "visible_text": "",
                "num_forms": 0,
            },
            "indicators": ["Empty or unparseable HTML content"],
        }

    soup = BeautifulSoup(html_content, "html.parser")

    # Check for meta refresh cloaking / stealth redirects before decomposing tags
    has_meta_refresh = False
    meta_refresh_target = ""
    meta_tag = soup.find("meta", attrs={"http-equiv": lambda h: h and h.lower() == "refresh"})
    if meta_tag and meta_tag.get("content"):
        content_val = meta_tag["content"].lower()
        if "url=" in content_val:
            has_meta_refresh = True
            meta_refresh_target = content_val.split("url=")[-1].strip(" '\"")

    # Detect credential exfiltration gateways (Telegram bot, Discord webhook, Formsubmit)
    html_lower_raw = html_content.lower()
    has_exfiltration_endpoint = False
    exfil_gateway = ""
    if "api.telegram.org/bot" in html_lower_raw:
        has_exfiltration_endpoint = True
        exfil_gateway = "Telegram Bot API (Credential Exfiltration Gateway)"
    elif "discord.com/api/webhooks" in html_lower_raw:
        has_exfiltration_endpoint = True
        exfil_gateway = "Discord Webhook (Exfiltration Gateway)"
    elif "formsubmit.co" in html_lower_raw or "formspree.io" in html_lower_raw:
        has_exfiltration_endpoint = True
        exfil_gateway = "Third-party Form Relay (FormSubmit/FormSpree)"

    # Clean out script, style, and comments for visible text
    for tag in soup(["script", "style", "noscript", "svg", "path"]):
        tag.decompose()

    # Title & Headings
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    headings = [h.get_text(strip=True) for h in soup.find_all(["h1", "h2", "h3"]) if h.get_text(strip=True)]

    # Visible Text
    visible_text = soup.get_text(separator=" ", strip=True)
    visible_text_lower = visible_text.lower()

    # Form analysis
    forms = soup.find_all("form")
    num_forms = len(forms)
    has_login_form = False
    has_password_field = False
    cross_domain_forms = []
    empty_action_forms = 0
    hidden_input_count = 0
    num_input_fields = len(soup.find_all("input"))

    base_domain = urlparse(base_url).hostname or ""

    for form in forms:
        action = form.get("action", "").strip()
        method = form.get("method", "get").lower()

        # Check for password fields
        pw_inputs = form.find_all("input", {"type": lambda t: t and t.lower() == "password"})
        if pw_inputs:
            has_password_field = True
            has_login_form = True

        # Check for username / email inputs
        text_inputs = form.find_all("input", {"type": lambda t: not t or t.lower() in ("text", "email", "tel")})
        if text_inputs and pw_inputs:
            has_login_form = True

        # Check action target
        if not action or action in ("#", "javascript:void(0);"):
            empty_action_forms += 1
        elif action.startswith(("http://", "https://")):
            action_domain = urlparse(action).hostname or ""
            if base_domain and action_domain and base_domain != action_domain:
                # Compare apex domains
                base_parts = base_domain.split(".")[-2:]
                action_parts = action_domain.split(".")[-2:]
                if base_parts != action_parts:
                    cross_domain_forms.append({
                        "form_action": action,
                        "action_domain": action_domain,
                        "base_domain": base_domain
                    })

        hidden_inputs = form.find_all("input", {"type": lambda t: t and t.lower() == "hidden"})
        hidden_input_count += len(hidden_inputs)

    # Global password or sensitive field check (outside forms)
    all_pw_inputs = soup.find_all("input", {"type": lambda t: t and "password" in t.lower()})
    if all_pw_inputs:
        has_password_field = True
        has_login_form = True

    # Regex fallback for malformed or unclosed tags
    if not has_password_field and re.search(r'<input[^>]*type=[\'"]?password', html_content, re.IGNORECASE):
        has_password_field = True
        has_login_form = True

    # Check for sensitive inputs (SSN, PIN, CVV, seed phrase, crypto wallet)
    has_sensitive_fields = False
    sensitive_keywords = ["ssn", "pin", "cvv", "seed", "mnemonic", "card_number", "private_key", "secret_key"]
    for inp in soup.find_all("input"):
        attrs_str = " ".join([str(inp.get(k, "")).lower() for k in ["name", "id", "placeholder", "aria-label"]])
        if any(sk in attrs_str for sk in sensitive_keywords):
            has_sensitive_fields = True
            has_password_field = True
            break

    # Links analysis
    all_anchors = soup.find_all("a", href=True)
    num_links = len(all_anchors)
    empty_links = 0
    external_links = 0

    for a in all_anchors:
        href = a["href"].strip()
        if not href or href in ("#", "javascript:void(0)", "javascript:;", "./#"):
            empty_links += 1
        elif href.startswith(("http://", "https://")):
            link_domain = urlparse(href).hostname or ""
            if base_domain and link_domain and base_domain != link_domain:
                external_links += 1

    empty_link_ratio = (empty_links / num_links) if num_links > 0 else 0.0
    external_link_ratio = (external_links / num_links) if num_links > 0 else 0.0

    # Iframes
    iframes = soup.find_all("iframe")
    num_iframes = len(iframes)

    # Disabled contextmenu or right-click defense evasion
    body_tag = soup.find("body")
    has_context_menu_disabled = False
    if body_tag:
        oncontext = body_tag.get("oncontextmenu", "").lower()
        if "return false" in oncontext or "event.preventdefault" in oncontext:
            has_context_menu_disabled = True

    # Image alt text & count
    images = soup.find_all("img")
    num_images = len(images)
    image_alts = [img.get("alt", "").strip() for img in images if img.get("alt")]

    # Suspicious phrases detected
    detected_phrases = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in visible_text_lower]

    # Calculate HTML risk score and gather indicators
    risk_points = 0.0
    indicators: List[str] = []

    if has_exfiltration_endpoint:
        risk_points += 0.50
        indicators.append(f"Direct threat actor exfiltration channel detected: {exfil_gateway}")

    if has_meta_refresh:
        risk_points += 0.35
        indicators.append(f"Meta refresh redirect cloaking to: '{meta_refresh_target}'")

    if has_sensitive_fields:
        risk_points += 0.35
        indicators.append("Collection fields for sensitive data (SSN / PIN / CVV / Crypto Seed phrase)")

    if cross_domain_forms:
        risk_points += 0.45
        indicators.append(
            f"Cross-domain form submission detected: Form posts credentials to external domain '{cross_domain_forms[0]['action_domain']}'"
        )

    if has_password_field:
        risk_points += 0.25
        indicators.append("Credential collection interface: Password input field detected")

    if has_login_form:
        risk_points += 0.15
        indicators.append("Authentication / Login form identified")

    if empty_action_forms > 0 and has_password_field:
        risk_points += 0.20
        indicators.append("Password form has empty or dummy action target ('#' / javascript)")

    if empty_link_ratio > 0.45 and num_links >= 5:
        risk_points += 0.18
        indicators.append(f"High percentage of dummy/broken links ({empty_link_ratio:.0%}) typical of cloned phishing templates")

    if has_context_menu_disabled:
        risk_points += 0.15
        indicators.append("Page disables right-click context menu (anti-analysis evasion technique)")

    if detected_phrases:
        risk_points += min(0.30, len(detected_phrases) * 0.10)
        indicators.append(f"Security-sensitive phrases in page content: {', '.join(detected_phrases[:3])}")

    if num_iframes >= 2:
        risk_points += 0.10
        indicators.append(f"Multiple embedded iframes ({num_iframes}) present")

    html_risk = min(1.0, round(risk_points, 3))

    features: Dict[str, Any] = {
        "title": title,
        "headings": headings[:5],
        "visible_text_preview": visible_text[:300] + ("..." if len(visible_text) > 300 else ""),
        "visible_text": visible_text,
        "num_forms": num_forms,
        "has_login_form": has_login_form,
        "has_password_field": has_password_field,
        "num_input_fields": num_input_fields,
        "cross_domain_forms": cross_domain_forms,
        "empty_action_forms": empty_action_forms,
        "hidden_input_count": hidden_input_count,
        "num_links": num_links,
        "empty_link_ratio": round(empty_link_ratio, 3),
        "external_link_ratio": round(external_link_ratio, 3),
        "num_iframes": num_iframes,
        "num_images": num_images,
        "image_alts": image_alts[:5],
        "has_context_menu_disabled": has_context_menu_disabled,
        "detected_suspicious_phrases": detected_phrases,
    }

    return {
        "html_risk": html_risk,
        "features": features,
        "indicators": indicators,
    }
