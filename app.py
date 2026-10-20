"""
MyCyber Tool — Flask web backend
URL heuristic scanner ported from the Tkinter desktop app.
"""

import ipaddress
import re
from urllib.parse import unquote, urlparse

from flask import Flask, flash, redirect, render_template, request, url_for

app = Flask(__name__)
app.secret_key = "mycyber-tool-dev-key-change-in-production"

# ----------------- Website URL heuristic checker -----------------
DANGEROUS_KEYWORDS = (
    "paypa1", "secure-login", "update-account", "crypto-bonus",
    "verify-account", "confirm-password", "reset-password",
    "claim-reward", "wallet-connect", "seed-phrase",
)
SUSPICIOUS_KEYWORDS = (
    "free-games", "free-prize", "login", "signin", "sign-in", "verify",
    "password", "passwd", "credential", "wallet", "unlock", "urgent",
    "suspended", "limited-time", "bank-secure", "secure-account",
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at",
}
RISKY_TLDS = {
    "zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "loan",
    "work", "rest", "country", "link", "kim",
}
KNOWN_BRANDS = {
    "paypal": ("paypal.com",),
    "google": ("google.com", "youtube.com", "gmail.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "netflix": ("netflix.com",),
    "bankofamerica": ("bankofamerica.com",),
}
STATUS_RANK = {"Safe": 0, "Suspicious": 1, "Dangerous": 2}

_URL_LIKE_RE = re.compile(
    r"(?:https?://|ftp://)[^\s<>\"']+|"
    r"(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
    r"(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)


def _registrable_host(host):
    host = host.lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        return host
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _looks_like_ip(host):
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _keyword_in_text(blob, keyword):
    """Match a phrase even if hyphens are dropped or swapped for _ / %20."""
    blob = blob.lower()
    variants = {
        keyword.lower(),
        keyword.lower().replace("-", ""),
        keyword.lower().replace("-", "_"),
        keyword.lower().replace("-", " "),
    }
    return any(variant in blob for variant in variants if variant)


def _raise_status(current, candidate):
    if STATUS_RANK[candidate] > STATUS_RANK[current]:
        return candidate
    return current


def _is_valid_domain_host(host):
    """True when urlparse yielded a usable hostname or IP."""
    if not host:
        return False
    host = host.lower().rstrip(".")
    if host == "localhost":
        return True
    if _looks_like_ip(host):
        return True
    if "." not in host:
        return False
    return bool(
        re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}",
            host,
        )
        or "xn--" in host
    )


def extract_first_valid_url(raw_text):
    """
    Clean mixed text / multiple URLs and return the first candidate with a
    valid domain (via urllib.parse). Returns None when nothing usable is found.
    """
    text = (raw_text or "").strip()
    if not text:
        return None

    candidates = []
    for token in re.split(r"[\s,;|\"'<>]+", text):
        token = token.strip(".,)]}>)")
        if token:
            candidates.append(token)
    for match in _URL_LIKE_RE.finditer(text):
        candidates.append(match.group(0).rstrip(".,)]}>)"))

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        to_parse = candidate if "://" in candidate else "https://" + candidate
        try:
            parsed = urlparse(to_parse)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()
        if _is_valid_domain_host(host):
            return candidate if "://" in candidate else "https://" + candidate
    return None


def analyze_url(raw_url):
    """Offline URL-string heuristics. Not a live Safe Browsing lookup."""
    findings = []
    status = "Safe"
    text = extract_first_valid_url(raw_url)
    if not text:
        return None, "Please enter a valid URL", []

    original_scheme = ""
    if "://" in text:
        original_scheme = text.split("://", 1)[0].lower()
    else:
        text = "https://" + text

    try:
        parsed = urlparse(text)
    except ValueError:
        return None, "Please enter a valid URL", []

    scheme = (parsed.scheme or original_scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not _is_valid_domain_host(host):
        return None, "Please enter a valid URL", []

    path_blob = unquote(
        (parsed.path or "") + "?" + (parsed.query or "") + "#" + (parsed.fragment or "")
    ).lower()
    full = unquote(text).lower()

    if scheme in {"javascript", "data", "vbscript"}:
        status = _raise_status(status, "Dangerous")
        findings.append(("Unsafe scheme", "High", f"The {scheme}: prefix can run code instead of opening a site."))
    elif scheme == "file":
        status = _raise_status(status, "Suspicious")
        findings.append(("Local file link", "Medium", "file: links open something on disk, not a normal website."))
    elif scheme not in {"http", "https"}:
        status = _raise_status(status, "Suspicious")
        findings.append(("Unusual scheme", "Medium", f"Scheme '{scheme or '(none)'}' is not a typical website."))

    if "@" in (parsed.netloc or ""):
        status = _raise_status(status, "Dangerous")
        findings.append(("Userinfo trick", "High", "An @ in the host can hide the real destination."))

    if _looks_like_ip(host):
        status = _raise_status(status, "Dangerous")
        findings.append(("IP address host", "High", "Phishing pages often skip a real domain and use a raw IP."))
    if "xn--" in host:
        status = _raise_status(status, "Dangerous")
        findings.append(("Punycode domain", "High", "Internationalized names can mimic well-known brands."))
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        status = _raise_status(status, "Suspicious")
        findings.append(("Many subdomains", "Medium", "A long chain of subdomains is a common lure."))
    tld = labels[-1] if labels else ""
    if tld in RISKY_TLDS:
        status = _raise_status(status, "Suspicious")
        findings.append(("Uncommon TLD", "Medium", f".{tld} is frequently abused in junk or phishing mail."))
    if host in SHORTENERS:
        status = _raise_status(status, "Suspicious")
        findings.append(("URL shortener", "Medium", "The real destination is hidden behind a short link."))
    if re.search(r"[^\x00-\x7f]", host):
        status = _raise_status(status, "Dangerous")
        findings.append(("Non-ASCII host", "High", "Lookalike Unicode characters can impersonate a brand."))

    registrable = _registrable_host(host)
    official_hosts = {item for names in KNOWN_BRANDS.values() for item in names}
    if registrable not in official_hosts:
        for brand, official in KNOWN_BRANDS.items():
            impersonated = False
            lookalike = False
            for label in labels:
                normalized = label.replace("-", "")
                tweaked = normalized.replace("0", "o").replace("1", "l").replace("3", "e")
                if normalized == brand or normalized.startswith(brand):
                    impersonated = True
                    break
                if tweaked == brand:
                    lookalike = True
                    break
            if impersonated:
                status = _raise_status(status, "Dangerous")
                findings.append(
                    ("Brand impersonation", "High", f"Mentions '{brand}' but is not an official {brand} domain.")
                )
                break
            if lookalike:
                status = _raise_status(status, "Dangerous")
                findings.append(("Lookalike brand", "High", f"The host resembles '{brand}' with swapped letters."))
                break

    if scheme == "http" or original_scheme == "http":
        status = _raise_status(status, "Suspicious")
        findings.append(
            (
                "Insecure connection",
                "High",
                "Uses http:// instead of https://. The page is not encrypted and can be altered in transit.",
            )
        )

    dangerous_hits = [word for word in DANGEROUS_KEYWORDS if _keyword_in_text(full, word)]
    if dangerous_hits:
        status = _raise_status(status, "Dangerous")
        findings.append(
            (
                "Phishing keyword",
                "High",
                "Dangerous lure terms: " + ", ".join(dangerous_hits) + ". Treat this link as unsafe.",
            )
        )

    suspicious_hits = [
        word for word in SUSPICIOUS_KEYWORDS
        if _keyword_in_text(full, word) and word not in dangerous_hits
    ]
    if suspicious_hits:
        status = _raise_status(status, "Suspicious")
        extra = " Combined with other warnings this is treated as high risk." if status == "Dangerous" else ""
        findings.append(
            (
                "Suspicious keyword",
                "Medium",
                "Suspicious terms: " + ", ".join(suspicious_hits[:6]) + "." + extra,
            )
        )
        if len(suspicious_hits) >= 3 or (scheme == "http" and suspicious_hits):
            status = _raise_status(status, "Dangerous")

    ext_hits = re.findall(r"\.(exe|apk|bat|dmg|scr)(?=[^a-z0-9]|$)", path_blob, flags=re.I)
    if not ext_hits:
        ext_hits = re.findall(r"\.(exe|apk|bat|dmg|scr)(?=[^a-z0-9]|$)", full, flags=re.I)
    if ext_hits:
        unique_exts = sorted({"." + item.lower() for item in ext_hits})
        status = _raise_status(status, "Dangerous")
        findings.append(
            (
                "Dangerous file type",
                "High",
                "The path contains " + ", ".join(unique_exts) + ". This is treated as a malware download risk.",
            )
        )
    if re.search(r"\.(pdf|jpg|jpeg|png|gif|html?|docx?|zip)\.(exe|apk|bat|dmg|scr)\b", path_blob):
        status = _raise_status(status, "Dangerous")
        findings.append(("Double extension", "High", "A fake document name hides a real program extension."))

    if len(text) > 180:
        status = _raise_status(status, "Suspicious")
        findings.append(("Very long URL", "Low", "Unusually long addresses are used to bury the real host."))
    if text.count("%") >= 8:
        status = _raise_status(status, "Suspicious")
        findings.append(("Heavy encoding", "Medium", "Lots of % encoding can hide the true path."))

    summaries = {
        "Dangerous": "Do not open this link. High-severity phishing or malware patterns were found.",
        "Suspicious": "Warning: insecure or lure-like patterns were found. Verify the real domain before visiting.",
        "Safe": "No strong phishing or malware URL patterns were found (heuristic check only).",
    }
    if status == "Safe" and not findings:
        findings.append(("Clean structure", "Info", "Host, scheme, and path look ordinary."))

    return status, summaries[status], findings


# ----------------- Flask routes -----------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    raw_input = ""
    scanned_url = None

    if request.method == "POST":
        raw_input = (request.form.get("url") or "").strip()
        cleaned_url = extract_first_valid_url(raw_input)
        if not cleaned_url:
            flash("Please enter a valid URL", "error")
            return redirect(url_for("index"))

        status, summary, findings = analyze_url(cleaned_url)
        if status is None:
            flash("Please enter a valid URL", "error")
            return redirect(url_for("index"))

        scanned_url = cleaned_url
        high_n = sum(1 for item in findings if item[1] == "High")
        med_n = sum(1 for item in findings if item[1] == "Medium")
        result = {
            "status": status,
            "summary": summary,
            "findings": findings,
            "high": high_n,
            "medium": med_n,
            "total": len(findings),
        }

    return render_template(
        "index.html",
        result=result,
        raw_input=raw_input,
        scanned_url=scanned_url,
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
