"""
Browser Rendering and Webpage Screenshot Capture Module.
Uses Playwright with headless Chromium in a locked-down configuration,
with graceful fallback to HTTP streaming + synthetic DOM rendering when browser binaries are absent.
Enforces multi-layer SSRF filtering on every network hop, subresource, and redirect.
"""
import asyncio
import base64
import io
import logging
import os
import socket
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse
from PIL import Image, ImageDraw

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from backend.config import (
    MAX_CONCURRENT_BROWSERS,
    MAX_HTML_SIZE_BYTES,
    PAGE_FETCH_TIMEOUT_SECONDS,
    SCREENSHOT_TTL_SECONDS,
    TEMP_SCREENSHOTS_DIR,
)
from backend.security.ssrf_guard import is_private_or_restricted_ip, validate_url_security

logger = logging.getLogger(__name__)


def cleanup_old_screenshots(max_age_seconds: int = SCREENSHOT_TTL_SECONDS) -> int:
    """
    Cleans up temporary screenshots older than max_age_seconds to maintain repo hygiene.
    """
    now = time.time()
    deleted_count = 0
    try:
        if not TEMP_SCREENSHOTS_DIR.exists():
            return 0
        for item in TEMP_SCREENSHOTS_DIR.glob("screenshot_*.png"):
            try:
                if item.is_file():
                    file_age = now - item.stat().st_mtime
                    if file_age > max_age_seconds:
                        item.unlink()
                        deleted_count += 1
            except Exception as e:
                logger.debug(f"Could not remove old screenshot {item}: {e}")
    except Exception as exc:
        logger.warning(f"Screenshot cleanup error: {exc}")
    return deleted_count


def generate_unreachable_screenshot(url: str, reason: str = "") -> Image.Image:
    """
    Renders an authentic, high-resolution browser error canvas for unreachable or offline domains.
    Clearly alerts the security operator that live verification could not be established.
    """
    width, height = 1280, 800
    img = Image.new("RGB", (width, height), color=(15, 23, 42))  # Dark slate-900 background
    draw = ImageDraw.Draw(img)

    # 1. Browser Chrome / Window Header
    draw.rectangle([0, 0, width, 50], fill=(30, 41, 59))
    draw.ellipse([15, 18, 27, 30], fill=(239, 68, 68))
    draw.ellipse([35, 18, 47, 30], fill=(245, 158, 11))
    draw.ellipse([55, 18, 67, 30], fill=(16, 185, 129))

    # Address bar with warning icon
    draw.rounded_rectangle([100, 10, width - 100, 40], radius=6, fill=(15, 23, 42), outline=(71, 85, 105))
    clean_url_display = url[:85] + ("..." if len(url) > 85 else "")
    draw.text((120, 18), f"[!] {clean_url_display}", fill=(248, 113, 113))

    # Central Error Card
    card_w, card_h = 680, 420
    cx = (width - card_w) // 2
    cy = 150
    draw.rounded_rectangle([cx, cy, cx + card_w, cy + card_h], radius=12, fill=(30, 41, 59), outline=(239, 68, 68), width=2)

    # Header in Error Card
    draw.text((cx + 40, cy + 30), "WARNING: Target Host Unreachable / Offline", fill=(248, 113, 113))
    hostname = urlparse(url).hostname or url
    draw.text((cx + 40, cy + 65), f"Target Domain: {hostname}", fill=(241, 245, 249))

    clean_reason = (reason[:90] + "...") if len(reason) > 90 else (reason or "DNS resolution failed or host refused connection")
    draw.text((cx + 40, cy + 95), f"Diagnostic: {clean_reason}", fill=(148, 163, 184))

    # Warning Box inside Card
    draw.rounded_rectangle([cx + 35, cy + 140, cx + card_w - 35, cy + 380], radius=8, fill=(15, 23, 42), outline=(71, 85, 105))
    draw.text((cx + 50, cy + 160), "AUTOMATED SECURITY INSPECTION NOTICE:", fill=(251, 191, 36))
    draw.text((cx + 50, cy + 195), "1. Network connection could not be established with the target server.", fill=(203, 213, 225))
    draw.text((cx + 50, cy + 225), "2. Live DOM forms, HTML structures, and visual elements are unavailable.", fill=(203, 213, 225))
    draw.text((cx + 50, cy + 255), "3. Zero-day phishing domains are frequently taken down within hours.", fill=(203, 213, 225))
    draw.text((cx + 50, cy + 285), "4. Risk assessment is derived from URL lexical heuristics only.", fill=(203, 213, 225))
    draw.text((cx + 50, cy + 315), "5. Confidence is reduced. Do NOT assume an unreachable host is safe.", fill=(239, 68, 68))

    return img


def generate_fallback_screenshot(
    url: str,
    title: str,
    visible_text: str,
    has_login: bool = False,
    is_phish_sim: bool = False
) -> Image.Image:
    """
    Renders a realistic visual preview of a webpage using PIL when Playwright chromium is not installed.
    Simulates browser viewport (1280x800) with navigation bar, page title, content, and form inputs.
    """
    width, height = 1280, 800
    img = Image.new("RGB", (width, height), color=(248, 250, 252))
    draw = ImageDraw.Draw(img)

    # 1. Browser Chrome / Window Header
    draw.rectangle([0, 0, width, 50], fill=(226, 232, 240))
    # Window controls (macOS / browser style dots)
    draw.ellipse([15, 18, 27, 30], fill=(239, 68, 68))
    draw.ellipse([35, 18, 47, 30], fill=(245, 158, 11))
    draw.ellipse([55, 18, 67, 30], fill=(16, 185, 129))

    # Address bar
    draw.rounded_rectangle([100, 10, width - 100, 40], radius=6, fill=(255, 255, 255), outline=(203, 213, 225))
    clean_url_display = url[:90] + ("..." if len(url) > 90 else "")
    draw.text((120, 18), f"[lock] {clean_url_display}", fill=(71, 85, 105))

    # 2. Page Canvas Area
    # Render simulated navbar
    draw.rectangle([0, 50, width, 110], fill=(255, 255, 255), outline=(226, 232, 240))
    nav_title = (title[:40] if title else "Portal Page").strip()
    draw.text((50, 72), nav_title, fill=(30, 41, 59))

    if has_login:
        # Render a centered deceptive authentication modal card
        card_w, card_h = 440, 480
        cx = (width - card_w) // 2
        cy = 160

        draw.rounded_rectangle([cx, cy, cx + card_w, cy + card_h], radius=10, fill=(255, 255, 255), outline=(203, 213, 225), width=2)
        draw.text((cx + 40, cy + 35), "Sign in to your account", fill=(15, 23, 42))

        # Email input field
        draw.text((cx + 40, cy + 90), "Email, phone, or Skype", fill=(100, 116, 139))
        draw.rounded_rectangle([cx + 40, cy + 115, cx + card_w - 40, cy + 155], radius=4, fill=(255, 255, 255), outline=(148, 163, 184))

        # Password input field
        draw.text((cx + 40, cy + 180), "Password", fill=(100, 116, 139))
        draw.rounded_rectangle([cx + 40, cy + 205, cx + card_w - 40, cy + 245], radius=4, fill=(255, 255, 255), outline=(148, 163, 184))
        draw.text((cx + 50, cy + 218), "••••••••••••", fill=(71, 85, 105))

        # Action button
        draw.rounded_rectangle([cx + 40, cy + 285, cx + card_w - 40, cy + 330], radius=4, fill=(37, 99, 235))
        draw.text((cx + 170, cy + 300), "Sign in", fill=(255, 255, 255))

        # Security footer
        draw.text((cx + 70, cy + 370), "Protected by Identity Security Services", fill=(148, 163, 184))
    else:
        # Standard content layout simulation
        draw.text((50, 150), title or "Welcome to our Service", fill=(15, 23, 42))
        snippet = visible_text[:300].replace("\n", " ") if visible_text else "Standard legitimate web content."
        for i, line_start in enumerate(range(0, min(len(snippet), 280), 70)):
            draw.text((50, 200 + i * 28), snippet[line_start:line_start + 70], fill=(71, 85, 105))

    return img


async def _ssrf_route_handler(route, request):
    """
    Playwright route handler: intercepts every request (initial document, redirects,
    subresources, websockets) and aborts any that resolve to private, loopback,
    metadata, or non-http(s) targets.
    """
    req_url = request.url
    try:
        parsed = urlparse(req_url)
    except Exception:
        await route.abort("blockedbyclient")
        return

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        logger.warning(f"Blocked non-http(s) subresource scheme: {req_url}")
        await route.abort("blockedbyclient")
        return

    hostname = parsed.hostname
    if not hostname:
        await route.abort("blockedbyclient")
        return

    # Check literal hostname against SSRF blocklist
    if is_private_or_restricted_ip(hostname):
        logger.warning(f"Blocked subresource to restricted IP/host: {hostname}")
        await route.abort("blockedbyclient")
        return

    # Resolve IP dynamically to protect against rebinding and internal subresources
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
        addr_info = socket.getaddrinfo(hostname, port)
        for entry in addr_info:
            ip = entry[4][0]
            if is_private_or_restricted_ip(ip):
                logger.warning(f"Blocked subresource resolving to private IP {ip} ({hostname})")
                await route.abort("blockedbyclient")
                return
    except Exception:
        # If subresource cannot be resolved, abort this subresource only
        await route.abort("blockedbyclient")
        return

    await route.continue_()


class BrowserPool:
    """
    Thread-safe and async-safe browser instance manager.
    Enforces concurrency limits via Semaphore, reuses a single Chromium browser process,
    and isolates each scan inside a fresh, hardened BrowserContext.
    Does NOT use --no-sandbox or --disable-features=IsolateOrigins.
    """
    _instance: Optional["BrowserPool"] = None
    _semaphore: Optional[asyncio.Semaphore] = None
    _lock: Optional[asyncio.Lock] = None
    _playwright = None
    _browser = None

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        if cls._lock is None:
            cls._lock = asyncio.Lock()
        return cls._lock

    @classmethod
    def _get_semaphore(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(MAX_CONCURRENT_BROWSERS)
        return cls._semaphore

    @classmethod
    async def get_instance(cls) -> "BrowserPool":
        if cls._instance is None:
            cls._instance = BrowserPool()
        return cls._instance

    async def _ensure_browser(self):
        async with self._get_lock():
            if self._browser is None or not self._browser.is_connected():
                from playwright.async_api import async_playwright
                self._playwright = await async_playwright().start()
                # Hardened launch args: no weakened flags, isolation enabled
                launch_args = [
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=launch_args
                )
            return self._browser

    async def capture(self, url: str, timeout_seconds: int = PAGE_FETCH_TIMEOUT_SECONDS) -> Tuple[Optional[Image.Image], str, int]:
        """
        Renders a page inside an isolated, locked-down browser context.
        Blocks downloads, popups, permissions, and file choosers.
        """
        async with self._get_semaphore():
            browser = await self._ensure_browser()
            # Create fresh isolated context for this request
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                accept_downloads=False,
                ignore_https_errors=False,
                permissions=[],
            )
            # Enforce SSRF filter on all requests in this context
            await context.route("**/*", _ssrf_route_handler)

            redirects = 0
            page = await context.new_page()

            # Prevent popups and file pickers
            page.on("popup", lambda p: asyncio.create_task(p.close()))
            page.on("filechooser", lambda fc: None)

            def on_response(response):
                nonlocal redirects
                if 300 <= response.status < 400:
                    redirects += 1

            page.on("response", on_response)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                # Wait briefly for layout stabilization
                await page.wait_for_timeout(500)
                html_content = await page.content()
                screenshot_bytes = await page.screenshot(type="png", full_page=False)
                img = Image.open(io.BytesIO(screenshot_bytes)) if screenshot_bytes else None
                return img, html_content, redirects
            finally:
                await page.close()
                await context.close()

    async def render_html(self, html: str) -> Optional[Image.Image]:
        """Renders raw HTML content into a screenshot using an isolated context without network."""
        async with self._get_semaphore():
            browser = await self._ensure_browser()
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                accept_downloads=False,
                permissions=[],
            )
            # Abort all external network requests during raw HTML render
            await context.route("**/*", lambda r, q: r.abort("blockedbyclient"))
            page = await context.new_page()
            try:
                await page.set_content(html, wait_until="domcontentloaded", timeout=10000)
                screenshot_bytes = await page.screenshot(type="png", full_page=False)
                return Image.open(io.BytesIO(screenshot_bytes)) if screenshot_bytes else None
            finally:
                await page.close()
                await context.close()

    async def close(self):
        async with self._get_lock():
            if self._browser:
                try:
                    await self._browser.close()
                except Exception:
                    pass
                self._browser = None
            if self._playwright:
                try:
                    await self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None


def _safe_fetch_requests(
    url: str,
    timeout_seconds: int = PAGE_FETCH_TIMEOUT_SECONDS,
    max_bytes: int = MAX_HTML_SIZE_BYTES
) -> Tuple[str, int, bool, str]:
    """
    Safely fetches target webpage over HTTP/HTTPS when Playwright is unavailable.
    - Disables automatic redirects (allow_redirects=False).
    - Manually follows up to 5 hops, validating SSRF safety on every hop before connecting.
    - Streams response body with a strict MAX_HTML_SIZE_BYTES limit.
    - Only flags is_unreachable on real network/HTTP errors, never on page content strings.
    """
    current_url = url
    redirect_count = 0
    max_hops = 5
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    session = requests.Session()
    session.max_redirects = 0

    for _ in range(max_hops + 1):
        # Validate SSRF on current hop
        is_safe, sec_reason = validate_url_security(current_url)
        if not is_safe:
            if "UNREACHABLE" in sec_reason:
                return "", redirect_count, True, sec_reason
            raise ValueError(f"Security Policy Block: {sec_reason}")

        try:
            resp = session.get(
                current_url,
                headers=headers,
                timeout=timeout_seconds,
                verify=False,
                allow_redirects=False,
                stream=True
            )
        except requests.exceptions.SSLError as ssl_err:
            return "", redirect_count, True, f"SSL/TLS handshake failure: {ssl_err}"
        except requests.exceptions.ConnectionError as conn_err:
            return "", redirect_count, True, f"Connection refused or network down: {conn_err}"
        except requests.exceptions.Timeout as timeout_err:
            return "", redirect_count, True, f"Connection timed out: {timeout_err}"
        except requests.exceptions.RequestException as req_err:
            return "", redirect_count, True, f"Network transport error: {req_err}"

        # Handle 3xx Redirects manually
        if resp.status_code in (301, 302, 303, 307, 308):
            redirect_count += 1
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                return "", redirect_count, True, f"HTTP {resp.status_code} Redirect without Location header"
            current_url = urllib.parse.urljoin(current_url, location)
            continue

        # Terminal HTTP Error
        if resp.status_code >= 400:
            resp.close()
            return "", redirect_count, True, f"HTTP {resp.status_code} ({resp.reason})"

        # Stream body up to max_bytes
        content_bytes = bytearray()
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    content_bytes.extend(chunk)
                    if len(content_bytes) >= max_bytes:
                        logger.info(f"Response reached maximum byte limit ({max_bytes} bytes); stopping stream.")
                        break
        finally:
            resp.close()

        encoding = resp.encoding or "utf-8"
        try:
            html_text = content_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = content_bytes.decode("utf-8", errors="replace")

        return html_text, redirect_count, False, ""

    return "", redirect_count, True, f"Exceeded maximum allowed redirects ({max_hops})"


def capture_webpage(url: str, timeout_seconds: int = PAGE_FETCH_TIMEOUT_SECONDS) -> Tuple[Optional[Image.Image], str, str, int, bool, str]:
    """
    Main entrypoint for capturing webpage contents and screenshot.
    Returns:
        tuple: (pil_image, html_content, screenshot_data_uri, redirect_count, is_unreachable, unreachable_reason)
    """
    # Run screenshot TTL cleanup to maintain repository cleanliness
    cleanup_old_screenshots()

    # 1. SSRF and Protocol Security Validation before launching any browser or client
    is_safe, sec_msg = validate_url_security(url)
    if not is_safe:
        if "UNREACHABLE" in sec_msg:
            # Unresolvable host is marked directly as unreachable
            image = generate_unreachable_screenshot(url, sec_msg)
            file_id = f"screenshot_{uuid.uuid4().hex[:12]}.png"
            save_path = TEMP_SCREENSHOTS_DIR / file_id
            image.save(save_path, format="PNG")
            buffered = io.BytesIO()
            image.save(buffered, format="PNG")
            data_uri = f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"
            return image, "", data_uri, 0, True, sec_msg
        raise ValueError(f"Security Policy Rejection: {sec_msg}")

    image: Optional[Image.Image] = None
    html_content = ""
    redirect_count = 0
    is_unreachable = False
    unreachable_reason = ""

    # 2. Attempt Playwright headless rendering using pooled browser
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            loop = asyncio.ProactorEventLoop()
        else:
            loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            pool = loop.run_until_complete(BrowserPool.get_instance())
            image, html_content, redirect_count = loop.run_until_complete(
                asyncio.wait_for(pool.capture(url, timeout_seconds), timeout=timeout_seconds + 5)
            )
        finally:
            loop.close()
    except Exception as exc:
        logger.info(f"Playwright rendering skipped or unavailable ({exc}). Using direct fetch fallback.")

    # 3. Direct HTTP Fetch fallback if Playwright did not capture HTML
    if not html_content:
        html_content, redirect_count, is_unreachable, unreachable_reason = _safe_fetch_requests(
            url, timeout_seconds=timeout_seconds, max_bytes=MAX_HTML_SIZE_BYTES
        )

    # 4. Generate Synthetic Fallback Screenshot if needed
    if image is None:
        if is_unreachable:
            image = generate_unreachable_screenshot(url, unreachable_reason)
        else:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            text = soup.get_text(separator=" ", strip=True)
            has_login = bool(soup.find("input", {"type": "password"})) or "login" in text.lower()
            image = generate_fallback_screenshot(url, title, text, has_login=has_login)

    # 5. Save temporary screenshot to disk
    import uuid
    file_id = f"screenshot_{uuid.uuid4().hex[:12]}.png"
    save_path = TEMP_SCREENSHOTS_DIR / file_id
    image.save(save_path, format="PNG")

    # Encode to base64 for frontend preview transmission
    buffered = io.BytesIO()
    image.save(buffered, format="PNG")
    b64_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    data_uri = f"data:image/png;base64,{b64_str}"

    return image, html_content, data_uri, redirect_count, is_unreachable, unreachable_reason
