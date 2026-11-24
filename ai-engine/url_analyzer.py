
import ipaddress
import re
from urllib.parse import urlsplit


SUSPICIOUS_KEYWORDS = [
    "verify",
    "password",
    "login",
    "update-account",
    "confirm",
    "secure-account",
    "banking",
    "wallet",
    "free-gift",
    "claim-prize",
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
}


def analyze_url(url: str):
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    if len(url) > 2048:
        raise ValueError("URL is too long")

    if re.search(r"[\x00-\x20\x7f]", url):
        raise ValueError(
            "URL contains invalid whitespace or control characters"
        )

    parsed = urlsplit(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported"
        )

    if not parsed.netloc:
        raise ValueError("URL must contain a hostname")

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid hostname or port")

    if not hostname:
        raise ValueError("Invalid hostname")

    hostname = hostname.lower().rstrip(".")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "URLs containing user information are not supported"
        )

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Invalid port")

    indicators = []
    score = 0

    # Rule 1: HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        score += 15
        indicators.append(
            "URL does not use HTTPS"
        )

    # Rule 2: IP address instead of domain
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
        score += 25

        indicators.append(
            "URL uses an IP address instead of a domain"
        )

    except ValueError:
        pass

    # Rule 3: Long URL
    if len(url) > 100:
        score += 15
        indicators.append(
            "URL is unusually long"
        )

    # Rule 4: Suspicious keywords
    lower_url = url.lower()

    matches = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lower_url
    ]

    if matches:
        score += min(len(matches) * 10, 30)

        indicators.append(
            "Contains potentially suspicious keywords: "
            + ", ".join(matches)
        )

    # Rule 5: Multiple subdomains
    # Do not count dots in IP addresses as subdomains.
    if not is_ip_address and hostname.count(".") >= 3:
        score += 15
        indicators.append(
            "URL contains multiple subdomains"
        )

    # Rule 6: @ symbol
    if "@" in url:
        score += 20
        indicators.append(
            "URL contains an @ symbol"
        )

    # Rule 7: URL shortening service
    if hostname in SHORTENERS:
        score += 20
        indicators.append(
            "URL uses a known shortening service"
        )

    # Final score
    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not indicators:
        indicators.append(
            "No suspicious patterns detected by the current rules"
        )

    explanation = (
        "This is a heuristic URL risk estimate based on "
        "visible URL characteristics. It does not verify "
        "whether the destination is malicious or safe."
    )

    return {
        "status": "COMPLETED",
        "scan_type": "URL",
        "url": url,
        "hostname": hostname,
        "prediction": (
            "SUSPICIOUS"
            if risk_level in {"MEDIUM", "HIGH"}
            else "NO_INDICATORS_DETECTED"
        ),
        "risk_score": float(score),
        "risk_level": risk_level,
        "indicators": indicators,
        "explanation": explanation,
        "model_version": "url-rules-1.0",
    }
