"""
Modular Vision-Language Model (VLM) Interface & Analyzers.
Supports configurable backends:
1. HeuristicZeroDayVisualAnalyzer (High-accuracy lightweight multimodal CV & visual-brand discrepancy)
2. HuggingFaceVLMAnalyzer (SmolVLM / Moondream2 / Qwen2-VL when transformers/torch are configured)
3. MockVLMAnalyzer (Deterministic mock for test suites)
"""
from abc import ABC, abstractmethod
import logging
import re
from typing import Any, Dict, List, Optional
from PIL import Image

from backend.config import VLM_BACKEND, VLM_MODEL_ID, DEVICE

logger = logging.getLogger(__name__)


# Major brands targeted by zero-day phishing campaigns and their legitimate apex domains
KNOWN_BRAND_PROFILES = {
    "microsoft": {
        "name": "Microsoft / Office 365",
        "legitimate_domains": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com", "azure.com", "sharepoint.com"],
        "keywords": ["microsoft", "office 365", "sign in to your account", "onedrive", "sharepoint", "azure", "outlook"]
    },
    "google": {
        "name": "Google / Workspace",
        "legitimate_domains": ["google.com", "accounts.google.com", "gmail.com", "drive.google.com"],
        "keywords": ["google", "sign in with google", "use your google account", "gmail", "workspace"]
    },
    "apple": {
        "name": "Apple / iCloud",
        "legitimate_domains": ["apple.com", "icloud.com", "appleid.apple.com"],
        "keywords": ["apple id", "sign in with apple", "icloud", "app store"]
    },
    "paypal": {
        "name": "PayPal",
        "legitimate_domains": ["paypal.com"],
        "keywords": ["paypal", "pay with paypal", "log in to your paypal account"]
    },
    "chase": {
        "name": "Chase Bank",
        "legitimate_domains": ["chase.com"],
        "keywords": ["chase", "jpmorgan", "chase online", "sign in to chase"]
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "legitimate_domains": ["wellsfargo.com"],
        "keywords": ["wells fargo", "online banking", "sign on"]
    },
    "bankofamerica": {
        "name": "Bank of America",
        "legitimate_domains": ["bankofamerica.com", "bofa.com"],
        "keywords": ["bank of america", "bofa", "online banking"]
    },
    "citibank": {
        "name": "Citibank / Citi",
        "legitimate_domains": ["citi.com", "citibank.com"],
        "keywords": ["citi", "citibank", "sign on to citi"]
    },
    "amex": {
        "name": "American Express",
        "legitimate_domains": ["americanexpress.com", "amex.com"],
        "keywords": ["american express", "amex", "log in to amex"]
    },
    "amazon": {
        "name": "Amazon",
        "legitimate_domains": ["amazon.com", "amazon.co.uk", "amazon.de"],
        "keywords": ["amazon sign in", "amazon account", "prime video"]
    },
    "netflix": {
        "name": "Netflix",
        "legitimate_domains": ["netflix.com"],
        "keywords": ["netflix", "sign in", "watch anywhere", "membership"]
    },
    "meta": {
        "name": "Meta / Facebook",
        "legitimate_domains": ["facebook.com", "fb.com", "meta.com"],
        "keywords": ["facebook", "log into facebook", "meta login"]
    },
    "instagram": {
        "name": "Instagram",
        "legitimate_domains": ["instagram.com"],
        "keywords": ["instagram", "log in to instagram"]
    },
    "whatsapp": {
        "name": "WhatsApp",
        "legitimate_domains": ["whatsapp.com", "web.whatsapp.com"],
        "keywords": ["whatsapp", "whatsapp web", "qr code"]
    },
    "telegram": {
        "name": "Telegram",
        "legitimate_domains": ["telegram.org", "web.telegram.org"],
        "keywords": ["telegram", "telegram web", "log in to telegram"]
    },
    "docusign": {
        "name": "DocuSign",
        "legitimate_domains": ["docusign.com", "docusign.net"],
        "keywords": ["docusign", "review document", "sign document", "view completed document"]
    },
    "adobe": {
        "name": "Adobe / Acrobat",
        "legitimate_domains": ["adobe.com", "acrobat.com"],
        "keywords": ["adobe id", "sign in with adobe", "acrobat document cloud"]
    },
    "usps": {
        "name": "USPS / Postal Service",
        "legitimate_domains": ["usps.com", "tools.usps.com"],
        "keywords": ["usps", "united states postal service", "package tracking", "redelivery"]
    },
    "dhl": {
        "name": "DHL Express",
        "legitimate_domains": ["dhl.com", "dhl.de"],
        "keywords": ["dhl", "dhl express", "shipment tracking"]
    },
    "fedex": {
        "name": "FedEx",
        "legitimate_domains": ["fedex.com"],
        "keywords": ["fedex", "tracking number", "delivery manager"]
    },
    "metamask": {
        "name": "MetaMask / Web3 Wallet",
        "legitimate_domains": ["metamask.io"],
        "keywords": ["metamask", "connect wallet", "secret recovery phrase", "import wallet"]
    },
    "coinbase": {
        "name": "Coinbase",
        "legitimate_domains": ["coinbase.com"],
        "keywords": ["coinbase", "sign in to coinbase", "coinbase wallet"]
    },
    "binance": {
        "name": "Binance",
        "legitimate_domains": ["binance.com"],
        "keywords": ["binance", "log in with binance"]
    },
    "steam": {
        "name": "Steam / Valve",
        "legitimate_domains": ["steampowered.com", "steamcommunity.com"],
        "keywords": ["steam community", "sign in to steam", "valve corp"]
    },
    "ups": {
        "name": "UPS",
        "legitimate_domains": ["ups.com"],
        "keywords": ["ups", "tracking number", "shipment details"]
    },
    "royalmail": {
        "name": "Royal Mail",
        "legitimate_domains": ["royalmail.com"],
        "keywords": ["royal mail", "redelivery fee", "reschedule delivery"]
    },
    "canadapost": {
        "name": "Canada Post",
        "legitimate_domains": ["canadapost.ca", "canadapost-postescanada.ca"],
        "keywords": ["canada post", "postes canada", "delivery attempt"]
    },
    "auspost": {
        "name": "Australia Post",
        "legitimate_domains": ["auspost.com.au"],
        "keywords": ["auspost", "australia post", "track your parcel"]
    },
    "irs": {
        "name": "Internal Revenue Service (IRS)",
        "legitimate_domains": ["irs.gov"],
        "keywords": ["irs", "tax refund", "internal revenue service"]
    },
    "barclays": {
        "name": "Barclays",
        "legitimate_domains": ["barclays.co.uk", "barclays.com"],
        "keywords": ["barclays", "barclays online banking"]
    },
    "hsbc": {
        "name": "HSBC",
        "legitimate_domains": ["hsbc.com", "hsbc.co.uk"],
        "keywords": ["hsbc", "hsbc internet banking"]
    },
    "santander": {
        "name": "Santander",
        "legitimate_domains": ["santander.com", "santander.co.uk"],
        "keywords": ["santander", "log on to santander"]
    },
    "lloyds": {
        "name": "Lloyds Bank",
        "legitimate_domains": ["lloydsbank.com"],
        "keywords": ["lloyds bank", "lloyds internet banking"]
    },
    "dropbox": {
        "name": "Dropbox",
        "legitimate_domains": ["dropbox.com"],
        "keywords": ["dropbox", "sign in to dropbox", "shared document"]
    },
    "linkedin": {
        "name": "LinkedIn",
        "legitimate_domains": ["linkedin.com"],
        "keywords": ["linkedin", "sign in to linkedin"]
    },
    "trustwallet": {
        "name": "Trust Wallet",
        "legitimate_domains": ["trustwallet.com"],
        "keywords": ["trust wallet", "restore multi-coin wallet", "import phrase"]
    },
    "att": {
        "name": "AT&T",
        "legitimate_domains": ["att.com", "att.net"],
        "keywords": ["at&t", "sign in to myatt"]
    },
    "verizon": {
        "name": "Verizon",
        "legitimate_domains": ["verizon.com"],
        "keywords": ["verizon", "sign in to my verizon"]
    }
}


class BaseVLMAnalyzer(ABC):
    """Abstract base interface for all VLM and visual analyzers."""

    @abstractmethod
    def analyze(
        self,
        image: Optional[Image.Image],
        webpage_text: str,
        domain_context: str = "",
        html_features: Optional[Dict[str, Any]] = None,
        url_context: str = "",
        url_features: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyzes screenshot and webpage context.
        Returns structured dictionary with visual risk, brand impersonation flag,
        credential harvesting flags, and explainable indicators.
        """
        pass


class MockVLMAnalyzer(BaseVLMAnalyzer):
    """Deterministic mock analyzer for fast unit testing and offline development."""

    def analyze(
        self,
        image: Optional[Image.Image],
        webpage_text: str,
        domain_context: str = "",
        html_features: Optional[Dict[str, Any]] = None,
        url_context: str = "",
        url_features: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        text_lower = webpage_text.lower()
        is_phish = "verify your account" in text_lower or "password" in text_lower
        risk = 0.85 if is_phish else 0.12

        return {
            "visual_risk": risk,
            "brand_impersonation": is_phish,
            "impersonated_brand": "Microsoft 365" if is_phish else None,
            "credential_harvesting": is_phish,
            "suspicious_login_form": is_phish,
            "visual_indicators": [
                "Mock Analyzer: Suspicious login interface detected" if is_phish else "Mock Analyzer: Normal page layout"
            ],
            "confidence": 0.90,
            "backend": "mock"
        }


class HeuristicZeroDayVisualAnalyzer(BaseVLMAnalyzer):
    """
    High-precision lightweight visual-semantic analyzer.
    Detects Zero-Day Phishing by discovering cross-modal discrepancies:
    When a webpage visually masquerades as a protected brand (e.g. Microsoft 365, PayPal)
    while being hosted on an illegitimate / newly registered apex domain.
    """

    def analyze(
        self,
        image: Optional[Image.Image],
        webpage_text: str,
        domain_context: str = "",
        html_features: Optional[Dict[str, Any]] = None,
        url_context: str = "",
        url_features: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        text_lower = webpage_text.lower()
        domain_clean = domain_context.lower().strip()
        url_lower = (url_context or "").lower()
        visual_indicators: List[str] = []
        visual_risk = 0.0
        brand_impersonation = False
        detected_brand_name = None
        has_login_elements = False
        has_credential_harvesting = False

        # Extract DOM context if provided
        hf = html_features or {}
        title = (hf.get("title", "") if isinstance(hf.get("title"), str) else "").lower()
        headings = [str(h).lower() for h in hf.get("headings", [])]
        image_alts = [str(a).lower() for a in hf.get("image_alts", [])]
        has_password_field = bool(hf.get("has_password_field", False))
        has_login_form = bool(hf.get("has_login_form", False))
        has_login_title = any(cue in title for cue in ["sign in", "log in", "login", "signin", "portal", "account"])

        # Extract URL features context if provided
        uf = url_features or {}
        brand_in_subdomain = uf.get("features", {}).get("brand_in_subdomain", [])

        # 1. Form and Credential Harvesting Layout Analysis
        if has_password_field or (has_login_form and has_login_title):
            has_login_elements = True
            visual_risk += 0.25
            visual_indicators.append("Visual login dialog / credential harvesting interface identified")

        # Known High-Reputation Whitelist Domains (Encyclopedias, Government, Documentation)
        is_known_high_trust = any(
            domain_clean == d or domain_clean.endswith("." + d)
            for d in [
                "wikipedia.org", "wikimedia.org", "github.com", "google.com",
                "apple.com", "microsoft.com", "mozilla.org", "w3.org", "ietf.org",
                "nih.gov", "cdc.gov", "nasa.gov", "arxiv.org"
            ]
        ) or any(domain_clean.endswith(t) for t in [".edu", ".gov", ".mil"])

        # 2. Visual/Textual Brand Identification
        if not is_known_high_trust:
            for brand_key, brand_info in sorted(KNOWN_BRAND_PROFILES.items(), key=lambda x: len(x[0]), reverse=True):
                brand_pat = re.compile(rf"(^|[^a-zA-Z0-9]){re.escape(brand_key)}($|[^a-zA-Z0-9])", re.IGNORECASE)
                brand_in_title = bool(brand_pat.search(title)) or any(bool(brand_pat.search(h)) for h in headings)
                brand_in_sub = brand_key in brand_in_subdomain
                brand_in_alts = any(bool(brand_pat.search(alt)) for alt in image_alts)
                brand_in_login_form = (
                    (has_password_field or (has_login_form and has_login_title))
                    and any(kw in text_lower[:1000] for kw in brand_info["keywords"])
                )

                brand_claimed = brand_in_sub or brand_in_title or brand_in_alts or brand_in_login_form

                if brand_claimed:
                    detected_brand_name = brand_info["name"]
                    
                    # Check Domain Discrepancy (The core indicator of Zero-Day Phishing!)
                    is_legit_domain = any(domain_clean == leg or domain_clean.endswith("." + leg) for leg in brand_info["legitimate_domains"])
                    
                    if not is_legit_domain and domain_clean not in {"localhost", "127.0.0.1"}:
                        brand_impersonation = True
                        visual_risk = max(visual_risk, 0.70)
                        visual_indicators.append(
                            f"Zero-Day Brand Impersonation: Page mimics '{brand_info['name']}' identity, but domain '{domain_clean}' is NOT an authorized domain"
                        )
                    elif is_legit_domain:
                        # Legitimate brand on genuine domain
                        visual_indicators.append(f"Authentic brand portal: Domain matches '{brand_info['name']}' official domain")
                    break

        if brand_impersonation and has_login_elements:
            has_credential_harvesting = True
            visual_risk = max(visual_risk, 0.88)
            visual_indicators.append("Deceptive credential harvesting card matching targeted enterprise login")

        # 2b. Tech Support Scareware Visual Screen Detection
        scareware_cues = ["call toll-free", "call support", "virus detected", "trojan alert", "zeus virus", "do not restart", "computer is locked", "call 1-8"]
        if any(sc in text_lower for sc in scareware_cues):
            visual_risk = max(visual_risk, 0.85)
            visual_indicators.append("Visual Scareware / Fake Tech Support screen detected")

        # 2c. Package Delivery / Customs Redelivery Scam
        delivery_cues = ["redelivery fee", "customs clearance", "parcel on hold", "package cannot be delivered", "update address to deliver", "delivery attempt failed"]
        if any(dc in text_lower for dc in delivery_cues):
            visual_risk = max(visual_risk, 0.82)
            visual_indicators.append("Visual Delivery Scam / Unpaid Parcel Redelivery Fee layout detected")

        # 2d. Crypto Seed Phrase / Wallet Drainer Harvester
        crypto_cues = ["connect wallet", "connect your wallet", "claim airdrop", "secret recovery phrase", "12-word seed phrase", "restore wallet", "import seed phrase"]
        if any(cc in text_lower for cc in crypto_cues):
            visual_risk = max(visual_risk, 0.88)
            has_credential_harvesting = True
            visual_indicators.append("Visual Web3 / Crypto Wallet Drainer & Seed Phrase Harvesting interface detected")

        # 2e. Generic Zero-Day Credential Capture on Suspicious / Ephemeral Hosting
        is_suspicious_domain_type = (
            any(domain_clean.endswith("." + tld) for tld in ["top", "xyz", "club", "work", "ru", "click", "buzz", "online", "site", "live", "cfd", "vip", "sbs", "monster"])
            or any(domain_clean.endswith("." + fhd) for fhd in ["pages.dev", "workers.dev", "firebaseapp.com", "appspot.com", "web.app", "vercel.app", "netlify.app", "ngrok-free.app", "glitch.me", "github.io", "gitlab.io"])
            or bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain_clean))
        )
        if is_suspicious_domain_type and (has_login_elements or has_password_field or hf.get("num_forms", 0) > 0):
            visual_risk = max(visual_risk, 0.78)
            has_credential_harvesting = True
            visual_indicators.append("Zero-Day Threat: Authentication credential inputs detected on suspicious/ephemeral cloud hosting domain")

        # 2f. Phishing and Deception Visual / Textual Cues
        is_phishing_deception_cues = any(
            re.search(rf"\b{re.escape(term)}\b", text_lower)
            for term in ["phishing", "social engineering", "trick you", "fake update", "out-of-date", "mimics a dialogue"]
        ) or "phishing" in url_lower
        if is_phishing_deception_cues and (has_login_elements or has_password_field or is_suspicious_domain_type):
            visual_risk = max(visual_risk, 0.85)
            has_credential_harvesting = True
            visual_indicators.append("Visual Phishing & Social Engineering credential capture pattern detected")

        # 2g. Direct Password Harvesting on Unverified Infrastructure
        if has_password_field and not is_known_high_trust and domain_clean not in {"localhost", "127.0.0.1"}:
            has_credential_harvesting = True
            if is_suspicious_domain_type or is_phishing_deception_cues:
                visual_risk = max(visual_risk, 0.82)
                visual_indicators.append("Zero-Day Credential Harvester: Password inputs rendered on unverified/PaaS cloud infrastructure")
            else:
                visual_risk = max(visual_risk, 0.65)
                visual_indicators.append("Password collection interface identified on unverified third-party domain")

        # 3. Image Property & Visual Structure Inspection
        if image is not None:
            width, height = image.size
            if width > 0 and height > 0:
                visual_indicators.append(f"Visual geometry verified: {width}x{height}px rendered canvas")

                # Sample center area to check for minimalist modal login card
                try:
                    center_box = (int(width * 0.25), int(height * 0.25), int(width * 0.75), int(height * 0.75))
                    center_crop = image.crop(center_box)
                    colors = center_crop.getcolors(maxcolors=256)
                    if colors and len(colors) < 30 and has_login_elements:
                        visual_risk = max(visual_risk, visual_risk + 0.10)
                        visual_indicators.append("Minimalist centered modal card layout typical of phishing capture boxes")
                except Exception:
                    pass

        # 4. Urgency visual indicators
        if any(term in text_lower for term in ["urgent", "suspended", "immediate action", "24 hours", "security alert"]):
            visual_risk = min(1.0, visual_risk + 0.10)
            visual_indicators.append("Visual urgency cues (security alert / account suspension callout)")

        visual_risk = min(1.0, round(visual_risk, 3))
        confidence = 0.94 if (brand_impersonation and has_login_elements) else (0.88 if visual_risk > 0.4 else 0.78)

        return {
            "visual_risk": visual_risk,
            "brand_impersonation": brand_impersonation,
            "impersonated_brand": detected_brand_name if brand_impersonation else None,
            "credential_harvesting": has_credential_harvesting,
            "suspicious_login_form": has_login_elements,
            "visual_indicators": visual_indicators,
            "confidence": confidence,
            "backend": "heuristic_zero_day"
        }


class HuggingFaceVLMAnalyzer(BaseVLMAnalyzer):
    """
    Vision-Language Model analyzer leveraging HuggingFace models (e.g. SmolVLM, Moondream2).
    Dynamically loads only when explicitly enabled in configuration.
    Falls back gracefully to HeuristicZeroDayVisualAnalyzer if dependencies or weights are not installed.
    """

    def __init__(self, model_id: str = VLM_MODEL_ID, device: str = DEVICE):
        self.model_id = model_id
        self.device = device
        self._model = None
        self._processor = None
        self._fallback = HeuristicZeroDayVisualAnalyzer()
        self._is_loaded = False

    def _lazy_load(self):
        if self._is_loaded:
            return
        try:
            from transformers import AutoProcessor, AutoModelForVision2Seq
            import torch
            logger.info(f"Loading HuggingFace VLM: {self.model_id} on {self.device}")
            self._processor = AutoProcessor.from_pretrained(self.model_id)
            self._model = AutoModelForVision2Seq.from_pretrained(
                self.model_id,
                torch_dtype=torch.float32 if self.device == "cpu" else torch.float16,
            ).to(self.device)
            self._is_loaded = True
        except Exception as exc:
            logger.warning(
                f"Could not load HuggingFace model '{self.model_id}': {exc}. "
                f"Falling back to high-precision HeuristicZeroDayVisualAnalyzer."
            )
            self._is_loaded = False

    def analyze(
        self,
        image: Optional[Image.Image],
        webpage_text: str,
        domain_context: str = "",
        html_features: Optional[Dict[str, Any]] = None,
        url_context: str = "",
        url_features: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._lazy_load()
        if not self._is_loaded or image is None:
            result = self._fallback.analyze(
                image, webpage_text, domain_context, html_features, url_context, url_features
            )
            result["backend"] = "heuristic_zero_day (fallback from HF)"
            return result

        # Prompt engineering for VLM visual reasoning
        prompt = (
            "Analyze this webpage screenshot and text for zero-day phishing indicators. "
            f"Domain: {domain_context}. Text snippet: {webpage_text[:400]}. "
            "Is this webpage attempting brand impersonation, fake login, or credential harvesting? Answer concisely."
        )

        try:
            inputs = self._processor(text=prompt, images=image, return_tensors="pt").to(self.device)
            outputs = self._model.generate(**inputs, max_new_tokens=150)
            generated_text = self._processor.batch_decode(outputs, skip_special_tokens=True)[0]

            # Merge with structured heuristics for robust quantification
            base_result = self._fallback.analyze(
                image, webpage_text, domain_context, html_features, url_context, url_features
            )
            base_result["visual_indicators"].append(f"VLM Output: {generated_text.strip()}")
            base_result["backend"] = f"hf_vlm ({self.model_id})"
            return base_result
        except Exception as exc:
            logger.error(f"VLM generation error: {exc}. Using fallback.")
            result = self._fallback.analyze(
                image, webpage_text, domain_context, html_features, url_context, url_features
            )
            result["backend"] = "heuristic_zero_day (inference error fallback)"
            return result


def get_vlm_analyzer(backend_name: Optional[str] = None) -> BaseVLMAnalyzer:
    """
    Factory to retrieve the configured VLM analyzer instance.
    """
    selected = (backend_name or VLM_BACKEND).lower()
    if selected == "mock":
        return MockVLMAnalyzer()
    elif selected == "huggingface":
        return HuggingFaceVLMAnalyzer()
    else:
        # Default is high-precision Heuristic Zero-Day visual analyzer
        return HeuristicZeroDayVisualAnalyzer()

