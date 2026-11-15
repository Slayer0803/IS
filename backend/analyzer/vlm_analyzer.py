"""
Modular Vision-Language Model (VLM) Interface & Visual Analyzers.
Supports configurable backends:
1. DOMBrandDiscrepancyVisualAnalyzer (Lightweight perceptual hashing & cross-modal brand discrepancy)
2. HuggingFaceVLMAnalyzer (SmolVLM / Moondream2 / Qwen2-VL when transformers/torch are installed)
3. MockVLMAnalyzer (Deterministic mock for test suites)

Zero-Day Phishing Detection Principle:
Detects when a webpage masquerades visually/semantically as a protected brand (e.g. Microsoft 365, PayPal)
while the registrable domain (parsed via tldextract) does not match the brand's authorized registrable domains,
or when credential harvesting is hosted on multi-tenant user content platforms.
"""
from abc import ABC, abstractmethod
import logging
import re
from typing import Any, Dict, List, Optional, Set
from PIL import Image

from backend.config import DEVICE, VLM_BACKEND, VLM_MODEL_ID
from backend.security.trusted_domains import (
    get_registrable_domain,
    is_trusted_domain,
    is_user_content_host,
    parse_domain_parts,
)

logger = logging.getLogger(__name__)


# Official registrable domains for major brands targeted by zero-day phishing
BRAND_OFFICIAL_REGISTRABLE_DOMAINS: Dict[str, Set[str]] = {
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com", "azure.com", "sharepoint.com", "msn.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citi.com", "citibank.com"},
    "amex": {"americanexpress.com", "amex.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es", "amazon.it", "amazon.ca", "amazon.co.jp"},
    "netflix": {"netflix.com"},
    "meta": {"facebook.com", "fb.com", "meta.com", "instagram.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "telegram": {"telegram.org"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com", "acrobat.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "metamask": {"metamask.io"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "trustwallet": {"trustwallet.com"},
    "irs": {"irs.gov"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "santander": {"santander.com", "santander.co.uk"},
    "lloyds": {"lloydsbank.com"},
    "att": {"att.com", "att.net"},
    "verizon": {"verizon.com"}
}

KNOWN_BRAND_PROFILES = {
    "microsoft": {
        "name": "Microsoft / Office 365",
        "keywords": ["microsoft", "office 365", "sign in to your account", "onedrive", "sharepoint", "azure", "outlook"]
    },
    "google": {
        "name": "Google / Workspace",
        "keywords": ["google", "sign in with google", "use your google account", "gmail", "workspace"]
    },
    "apple": {
        "name": "Apple / iCloud",
        "keywords": ["apple id", "sign in with apple", "icloud", "app store"]
    },
    "paypal": {
        "name": "PayPal",
        "keywords": ["paypal", "pay with paypal", "log in to your paypal account"]
    },
    "chase": {
        "name": "Chase Bank",
        "keywords": ["chase", "jpmorgan", "chase online", "sign in to chase"]
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "keywords": ["wells fargo", "online banking", "sign on"]
    },
    "bankofamerica": {
        "name": "Bank of America",
        "keywords": ["bank of america", "bofa", "online banking"]
    },
    "citibank": {
        "name": "Citibank / Citi",
        "keywords": ["citi", "citibank", "sign on to citi"]
    },
    "amex": {
        "name": "American Express",
        "keywords": ["american express", "amex", "log in to amex"]
    },
    "amazon": {
        "name": "Amazon",
        "keywords": ["amazon sign in", "amazon account", "prime video"]
    },
    "netflix": {
        "name": "Netflix",
        "keywords": ["netflix", "sign in", "watch anywhere", "membership"]
    },
    "meta": {
        "name": "Meta / Facebook",
        "keywords": ["facebook", "log into facebook", "meta login"]
    },
    "instagram": {
        "name": "Instagram",
        "keywords": ["instagram", "log in to instagram"]
    },
    "whatsapp": {
        "name": "WhatsApp",
        "keywords": ["whatsapp", "whatsapp web", "qr code"]
    },
    "telegram": {
        "name": "Telegram",
        "keywords": ["telegram", "telegram web", "log in to telegram"]
    },
    "docusign": {
        "name": "DocuSign",
        "keywords": ["docusign", "review document", "sign document", "view completed document"]
    },
    "adobe": {
        "name": "Adobe / Acrobat",
        "keywords": ["adobe id", "sign in with adobe", "acrobat document cloud"]
    },
    "usps": {
        "name": "USPS / Postal Service",
        "keywords": ["usps", "united states postal service", "package tracking", "redelivery"]
    },
    "dhl": {
        "name": "DHL Express",
        "keywords": ["dhl", "dhl express", "shipment tracking"]
    },
    "fedex": {
        "name": "FedEx",
        "keywords": ["fedex", "tracking number", "delivery manager"]
    },
    "metamask": {
        "name": "MetaMask / Web3 Wallet",
        "keywords": ["metamask", "connect wallet", "secret recovery phrase", "import wallet"]
    },
    "coinbase": {
        "name": "Coinbase",
        "keywords": ["coinbase", "sign in to coinbase", "coinbase wallet"]
    },
    "binance": {
        "name": "Binance",
        "keywords": ["binance", "log in with binance"]
    },
    "steam": {
        "name": "Steam / Valve",
        "keywords": ["steam community", "sign in to steam", "valve corp"]
    },
    "ups": {
        "name": "UPS",
        "keywords": ["ups", "tracking number", "shipment details"]
    },
    "trustwallet": {
        "name": "Trust Wallet",
        "keywords": ["trust wallet", "restore multi-coin wallet", "import phrase"]
    },
    "irs": {
        "name": "Internal Revenue Service (IRS)",
        "keywords": ["irs", "tax refund", "internal revenue service"]
    },
    "barclays": {
        "name": "Barclays",
        "keywords": ["barclays", "barclays online banking"]
    },
    "hsbc": {
        "name": "HSBC",
        "keywords": ["hsbc", "hsbc internet banking"]
    },
    "santander": {
        "name": "Santander",
        "keywords": ["santander", "log on to santander"]
    },
    "lloyds": {
        "name": "Lloyds Bank",
        "keywords": ["lloyds bank", "lloyds internet banking"]
    },
    "dropbox": {
        "name": "Dropbox",
        "keywords": ["dropbox", "sign in to dropbox", "shared document"]
    },
    "linkedin": {
        "name": "LinkedIn",
        "keywords": ["linkedin", "sign in to linkedin"]
    },
    "att": {
        "name": "AT&T",
        "keywords": ["at&t", "sign in to myatt"]
    },
    "verizon": {
        "name": "Verizon",
        "keywords": ["verizon", "sign in to my verizon"]
    }
}


def compute_perceptual_difference_hash(image: Image.Image) -> str:
    """
    Computes a 64-bit gradient difference hash (dHash) from the PIL image.
    Enables structural layout comparison independent of image resolution.
    """
    try:
        # Resize to 9x8 grayscale
        resized = image.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
        pixels = list(resized.getdata())
        diff = []
        for row in range(8):
            for col in range(8):
                left_pixel = pixels[row * 9 + col]
                right_pixel = pixels[row * 9 + col + 1]
                diff.append("1" if left_pixel > right_pixel else "0")
        return hex(int("".join(diff), 2))[2:].zfill(16)
    except Exception:
        return "0" * 16


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
        is_synthetic: bool = False
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
        is_synthetic: bool = False
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
            "backend": "mock",
            "is_synthetic_preview": is_synthetic
        }


class DOMBrandDiscrepancyVisualAnalyzer(BaseVLMAnalyzer):
    """
    Multimodal DOM & Visual Brand Discrepancy Analyzer.
    Combines perceptual layout hashing with cross-modal registrable domain comparison.
    Zero-Day Detection Engine: Identifies brand mimicry on unauthorized registrable domains
    or multi-tenant user content hosting (e.g. sites.google.com, github.io).
    """

    def analyze(
        self,
        image: Optional[Image.Image],
        webpage_text: str,
        domain_context: str = "",
        html_features: Optional[Dict[str, Any]] = None,
        url_context: str = "",
        url_features: Optional[Dict[str, Any]] = None,
        is_synthetic: bool = False
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

        # Extract Registrable Domain using tldextract
        subdomain, _, _, registrable_domain = parse_domain_parts(domain_clean or url_context)
        is_user_content = is_user_content_host(domain_clean or url_context)

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

        # 1. Visual Perceptual Layout Inspection (Real visual feature)
        dhash = "none"
        if image is not None:
            width, height = image.size
            if width > 0 and height > 0:
                dhash = compute_perceptual_difference_hash(image)
                label_suffix = " (Synthetic Fallback Preview)" if is_synthetic else " (Live Headless Render)"
                visual_indicators.append(
                    f"Visual canvas geometry: {width}x{height}px [dHash: {dhash[:8]}...]{label_suffix}"
                )

                # Center modal detection: check for centered credential harvesting card
                try:
                    center_box = (int(width * 0.25), int(height * 0.25), int(width * 0.75), int(height * 0.75))
                    center_crop = image.crop(center_box)
                    colors = center_crop.getcolors(maxcolors=256)
                    if colors and len(colors) < 30 and (has_password_field or has_login_form):
                        visual_risk = max(visual_risk, 0.35)
                        visual_indicators.append("Visual layout analysis: Minimalist centered modal dialog detected")
                except Exception:
                    pass

        # 2. Form & Credential Harvesting Detection
        if has_password_field or (has_login_form and has_login_title):
            has_login_elements = True
            visual_risk = max(visual_risk, 0.30)
            visual_indicators.append("Credential input interface identified (password/login elements)")

        # 3. Registrable Domain Brand Impersonation Matching (Phase 2.3)
        for brand_key, brand_info in sorted(KNOWN_BRAND_PROFILES.items(), key=lambda x: len(x[0]), reverse=True):
            brand_pat = re.compile(rf"(^|[^a-zA-Z0-9]){re.escape(brand_key)}($|[^a-zA-Z0-9])", re.IGNORECASE)
            brand_in_title = bool(brand_pat.search(title)) or any(bool(brand_pat.search(h)) for h in headings)
            brand_in_sub = brand_key in brand_in_subdomain
            brand_in_alts = any(bool(brand_pat.search(alt)) for alt in image_alts)
            brand_in_login_form = (
                (has_password_field or has_login_form)
                and any(kw in text_lower[:1200] for kw in brand_info["keywords"])
            )

            brand_claimed = brand_in_sub or brand_in_title or brand_in_alts or brand_in_login_form

            if brand_claimed:
                detected_brand_name = brand_info["name"]
                official_domains = BRAND_OFFICIAL_REGISTRABLE_DOMAINS.get(brand_key, set())

                # Check if the registrable domain matches official brand domains
                matches_official_domain = registrable_domain in official_domains

                # If matches official domain, BUT is on user-content host (e.g. sites.google.com hosting Microsoft login),
                # it is NOT authorized!
                if matches_official_domain and not is_user_content:
                    visual_indicators.append(
                        f"Authentic brand portal: Domain '{registrable_domain}' matches official {brand_info['name']} infrastructure"
                    )
                else:
                    # Brand impersonation detected!
                    brand_impersonation = True
                    visual_risk = max(visual_risk, 0.75)
                    host_desc = f"user-content host '{domain_clean}'" if is_user_content else f"unauthorized registrable domain '{registrable_domain}'"
                    visual_indicators.append(
                        f"Zero-Day Brand Impersonation: Page mimics {brand_info['name']} identity, but is hosted on {host_desc}"
                    )
                break

        if brand_impersonation and has_login_elements:
            has_credential_harvesting = True
            visual_risk = max(visual_risk, 0.90)
            visual_indicators.append("Deceptive credential harvesting targeting enterprise brand identity")

        # 4. Tech Support Scareware Detection
        scareware_cues = ["call toll-free", "call support", "virus detected", "trojan alert", "zeus virus", "do not restart", "computer is locked"]
        if any(sc in text_lower for sc in scareware_cues):
            visual_risk = max(visual_risk, 0.85)
            visual_indicators.append("Visual Scareware / Fake Tech Support screen detected")

        # 5. Package Redelivery Scam Detection
        delivery_cues = ["redelivery fee", "customs clearance", "parcel on hold", "package cannot be delivered", "update address to deliver"]
        if any(dc in text_lower for dc in delivery_cues):
            visual_risk = max(visual_risk, 0.82)
            visual_indicators.append("Visual Delivery Scam / Unpaid Parcel Redelivery Fee layout detected")

        # 6. Web3 / Seed Phrase Wallet Drainer
        crypto_cues = ["connect wallet", "connect your wallet", "claim airdrop", "secret recovery phrase", "12-word seed phrase", "restore wallet", "import seed phrase"]
        if any(cc in text_lower for cc in crypto_cues):
            visual_risk = max(visual_risk, 0.88)
            has_credential_harvesting = True
            visual_indicators.append("Visual Web3 / Crypto Wallet Drainer & Seed Phrase Harvesting interface detected")

        # 7. Unverified / User-Content Authentication Harvesting
        if (has_password_field or has_login_elements) and is_user_content:
            has_credential_harvesting = True
            visual_risk = max(visual_risk, 0.80)
            visual_indicators.append("Credential inputs rendered on multi-tenant user content platform")

        # 8. Password collection on non-trusted domain
        if has_password_field and not is_trusted_domain(domain_clean):
            has_credential_harvesting = True
            visual_risk = max(visual_risk, 0.65)
            visual_indicators.append("Password input rendered on unverified third-party domain")

        # Bounded normalization
        visual_risk = min(1.0, round(visual_risk, 3))
        signal_confidence = 0.95 if (brand_impersonation and has_login_elements) else (0.85 if visual_risk > 0.4 else 0.75)

        return {
            "visual_risk": visual_risk,
            "brand_impersonation": brand_impersonation,
            "impersonated_brand": detected_brand_name if brand_impersonation else None,
            "credential_harvesting": has_credential_harvesting,
            "suspicious_login_form": has_login_elements,
            "visual_indicators": visual_indicators,
            "confidence": signal_confidence,
            "dhash": dhash,
            "backend": "dom_brand_discrepancy",
            "is_synthetic_preview": is_synthetic
        }


# Alias for backward compatibility
HeuristicZeroDayVisualAnalyzer = DOMBrandDiscrepancyVisualAnalyzer


class HuggingFaceVLMAnalyzer(BaseVLMAnalyzer):
    """
    Vision-Language Model analyzer leveraging HuggingFace models (e.g. SmolVLM, Moondream2).
    Dynamically loads only when explicitly enabled via VLM_BACKEND=huggingface.
    Falls back cleanly to DOMBrandDiscrepancyVisualAnalyzer if transformers/torch are missing.
    Never passes synthetic previews to real visual weights.
    """

    def __init__(self, model_id: str = VLM_MODEL_ID, device: str = DEVICE):
        self.model_id = model_id
        self.device = device
        self._model = None
        self._processor = None
        self._fallback = DOMBrandDiscrepancyVisualAnalyzer()
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
                f"Using DOMBrandDiscrepancyVisualAnalyzer."
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
        is_synthetic: bool = False
    ) -> Dict[str, Any]:
        # Never pass synthetic previews to a deep vision-language model
        if is_synthetic or image is None:
            res = self._fallback.analyze(
                image=image,
                webpage_text=webpage_text,
                domain_context=domain_context,
                html_features=html_features,
                url_context=url_context,
                url_features=url_features,
                is_synthetic=is_synthetic
            )
            res["backend"] = "smolvlm_fallback_synthetic_skipped"
            return res

        self._lazy_load()
        if not self._is_loaded:
            return self._fallback.analyze(
                image=image,
                webpage_text=webpage_text,
                domain_context=domain_context,
                html_features=html_features,
                url_context=url_context,
                url_features=url_features,
                is_synthetic=is_synthetic
            )

        # SmolVLM Vision Prompting
        try:
            prompt = (
                f"Analyze this webpage screenshot for phishing threats. "
                f"Domain: {domain_context}. Does it imitate a major brand? Does it contain login inputs?"
            )
            inputs = self._processor(text=prompt, images=image, return_tensors="pt").to(self.device)
            generated_ids = self._model.generate(**inputs, max_new_tokens=150)
            generated_text = self._processor.batch_decode(generated_ids, skip_special_tokens=True)[0]

            is_phish = any(cue in generated_text.lower() for cue in ["phishing", "fake", "impersonat", "credential harvest"])
            return {
                "visual_risk": 0.88 if is_phish else 0.15,
                "brand_impersonation": is_phish,
                "impersonated_brand": None,
                "credential_harvesting": is_phish,
                "suspicious_login_form": is_phish,
                "visual_indicators": [f"VLM ({self.model_id}): {generated_text[:120]}"],
                "confidence": 0.90,
                "backend": f"huggingface_{self.model_id}",
                "is_synthetic_preview": False
            }
        except Exception as exc:
            logger.error(f"SmolVLM inference failure: {exc}")
            return self._fallback.analyze(
                image=image,
                webpage_text=webpage_text,
                domain_context=domain_context,
                html_features=html_features,
                url_context=url_context,
                url_features=url_features,
                is_synthetic=is_synthetic
            )


def get_vlm_analyzer() -> BaseVLMAnalyzer:
    """Factory function for initializing the configured visual analyzer."""
    backend = VLM_BACKEND.lower()
    if backend == "mock":
        return MockVLMAnalyzer()
    elif backend in ("huggingface", "smolvlm"):
        return HuggingFaceVLMAnalyzer()
    else:
        return DOMBrandDiscrepancyVisualAnalyzer()
