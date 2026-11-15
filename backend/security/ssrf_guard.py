"""
SSRF (Server-Side Request Forgery) protection and URL validation module.
Enforces strict defense-in-depth against accessing internal services, cloud metadata endpoints,
private network ranges, and dangerous protocol schemes.
"""
import ipaddress
import re
import socket
from urllib.parse import urlparse
from backend.config import SSRF_PROTECTION_ENABLED


DANGEROUS_SCHEMES = {
    "file", "gopher", "ftp", "tftp", "data", "javascript",
    "vbscript", "ldap", "dict", "jar", "netdoc", "mailto"
}
ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata IP addresses and internal endpoints to strictly block
CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack IPv4
    "fd00:ec2::254",    # AWS IPv6 metadata
    "metadata.google.internal",
    "100.100.100.200",  # Alibaba Cloud metadata
}

# Special network ranges that must never be accessed by the scanner
ADDITIONAL_RESTRICTED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("198.18.0.0/15"),     # Network interconnect benchmarking
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use (Class E)
    ipaddress.ip_network("255.255.255.255/32"), # Limited broadcast
    ipaddress.ip_network("fc00::/7"),          # Unique Local IPv6
    ipaddress.ip_network("fe80::/10"),         # Link-Local Unicast IPv6
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6
]


class SSRFValidationError(ValueError):
    """Raised when a URL violates SSRF safety rules."""
    pass


def is_private_or_restricted_ip(ip_str: str) -> bool:
    """
    Checks if an IP address string is loopback, private, link-local, multicast,
    cloud metadata, carrier-grade NAT, or reserved.
    Returns False if ip_str is not a valid IP address.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    clean_ip = ip_str.strip().strip("[]")

    if clean_ip in CLOUD_METADATA_IPS:
        return True

    try:
        ip = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False  # Not an IP address

    # Standard RFC1918 / loopback / link-local checks
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Check additional restricted CIDRs
    for net in ADDITIONAL_RESTRICTED_NETWORKS:
        try:
            if ip in net:
                return True
        except TypeError:
            continue

    return False


def validate_url_security(url: str) -> tuple[bool, str]:
    """
    Validates a URL against SSRF and protocol manipulation attacks.
    Localhost and private IP exemptions are strictly prohibited.
    Returns: (is_safe: bool, rejection_reason: str)
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty."

    url = url.strip()
    if len(url) > 2048:
        return False, "URL exceeds maximum allowed length of 2048 characters."

    # Inspect scheme before modifying URL
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", url)
    if scheme_match:
        initial_scheme = scheme_match.group(1).lower()
        if initial_scheme in DANGEROUS_SCHEMES:
            return False, f"Forbidden protocol scheme '{initial_scheme}'. Only HTTP and HTTPS are permitted."
        if initial_scheme not in ALLOWED_SCHEMES:
            return False, f"Unsupported scheme '{initial_scheme}'. Only HTTP and HTTPS are permitted."

    # Prepend scheme if missing
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Malformed URL: {exc}"

    scheme = parsed.scheme.lower()
    if scheme in DANGEROUS_SCHEMES:
        return False, f"Forbidden protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid domain name or host."

    if not SSRF_PROTECTION_ENABLED:
        return True, "SSRF protection disabled in config"

    # Reject localhost/loopback by hostname unconditionally (no localhost exemption)
    lower_host = hostname.lower().strip(".")
    if (
        lower_host in {"localhost", "localhost.localdomain", "broadcasthost", "127.0.0.1", "::1"}
        or lower_host.endswith(".localhost")
        or lower_host.endswith(".local")
        or lower_host.endswith(".internal")
        or lower_host.endswith(".localdomain")
    ):
        return False, "Requests to localhost, local domains, and internal networks are blocked by SSRF protection."

    # Direct literal IP check
    if is_private_or_restricted_ip(hostname):
        return False, f"Direct access to private or restricted IP ({hostname}) is blocked."

    # Resolve hostname to IPv4/IPv6 addresses to prevent DNS rebinding & private IP access
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
        addr_info = socket.getaddrinfo(hostname, port)
        resolved_ips = {entry[4][0] for entry in addr_info}
    except (socket.gaierror, socket.herror, OSError) as exc:
        # Unresolvable host: Treat explicitly as unreachable, not as validated!
        return False, f"UNREACHABLE: Domain '{hostname}' could not be resolved (NXDOMAIN / DNS failure): {exc}"
    except Exception as exc:
        return False, f"UNREACHABLE: DNS resolution failed for '{hostname}': {exc}"

    if not resolved_ips:
        return False, f"UNREACHABLE: No IP addresses resolved for '{hostname}'."

    for ip_addr in resolved_ips:
        if is_private_or_restricted_ip(ip_addr):
            return False, f"URL resolves to restricted IP ({ip_addr}). Access blocked."

    return True, "Valid and safe URL"

