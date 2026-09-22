import socket
import ssl
import codecs
import hashlib
import urllib.parse
import requests
import re
import urllib3
import mmh3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from agent.db import save_scan_features, save_novel_candidate
from agent.tech_classifier import predict_technologies

TECH_SIGNATURES = {
    "Apache":    {"headers": ["server:apache"],           "cpe_keyword": "apache http_server"},
    "Nginx":     {"headers": ["server:nginx"],            "cpe_keyword": "nginx nginx"},
    "IIS":       {"headers": ["server:iis", "server:microsoft-iis"], "cpe_keyword": "microsoft iis"},
    "PHP":       {"headers": ["x-powered-by:php"],        "cpe_keyword": "php php"},
    "WordPress": {"html_patterns": ["wp-content", "wp-includes"], "cpe_keyword": "wordpress wordpress"},
    "Drupal":    {"headers": ["x-generator:drupal"],      "cpe_keyword": "drupal drupal"},
    "Django":    {"html_patterns": ["csrfmiddlewaretoken"],"cpe_keyword": "djangoproject django"},
    "Express":   {"headers": ["x-powered-by:express"],   "cpe_keyword": "expressjs express"},
    "jQuery":    {"html_patterns": ["jquery.min.js", "jquery-"], "cpe_keyword": "jquery jquery"},
    "Bootstrap": {"html_patterns": ["bootstrap.min.css"], "cpe_keyword": "getbootstrap bootstrap"},
    "OpenSSL":   {"headers": ["server:openssl"],          "cpe_keyword": "openssl openssl"},
}

def _extract_cookies(resp: requests.Response) -> list:
    """Extract cookie names and attributes (HttpOnly, Secure, SameSite, Path)."""
    cookies = []
    try:
        for c in resp.cookies:
            # Check HttpOnly attribute
            httponly = bool(
                getattr(c, "has_nonstandard_attr", lambda x: False)("HttpOnly")
                or (getattr(c, "_rest", None) and any("httponly" in k.lower() for k in c._rest.keys()))
            )
            samesite = getattr(c, "samesite", None) or (c._rest.get("SameSite") if getattr(c, "_rest", None) else None)
            cookies.append({
                "name": c.name,
                "domain": c.domain,
                "path": c.path,
                "secure": bool(c.secure),
                "httponly": httponly,
                "samesite": samesite
            })
    except Exception:
        pass
    return cookies

def _extract_favicon_hash(target_url: str, html_content: str, ua: dict) -> int | None:
    """
    Fetch the favicon (via <link rel='icon'> or /favicon.ico) and compute
    the Shodan-style mmh3 hash of base64-encoded bytes.
    """
    fav_url = None
    # 1. Look for icon in HTML
    m = re.search(r'<link[^>]+rel=["\']?(?:shortcut )?icon["\']?[^>]+href=["\']?([^"\'>\s]+)', html_content, re.IGNORECASE)
    if m:
        fav_url = urllib.parse.urljoin(target_url, m.group(1))
    else:
        # Fallback to standard location
        fav_url = urllib.parse.urljoin(target_url, "/favicon.ico")

    try:
        fav_resp = requests.get(fav_url, headers=ua, timeout=3, verify=False, allow_redirects=True)
        if fav_resp.status_code == 200 and fav_resp.content:
            b64_encoded = codecs.encode(fav_resp.content, "base64")
            return mmh3.hash(b64_encoded)
    except Exception:
        pass
    return None

def _extract_tls_metadata(hostname: str) -> dict:
    """
    Extract TLS certificate metadata (issuer CN, SAN entries) via standard ssl module.
    """
    tls_info = {
        "has_ssl": False,
        "issuer_cn": "",
        "subject_cn": "",
        "expires": "",
        "san_entries": []
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    tls_info["has_ssl"] = True
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    tls_info["issuer_cn"] = issuer_dict.get("commonName", "")
                    tls_info["subject_cn"] = subject_dict.get("commonName", "")
                    tls_info["expires"] = cert.get("notAfter", "")
                    tls_info["san_entries"] = [val for typ, val in cert.get("subjectAltName", []) if typ == "DNS"]
    except Exception:
        # If default context fails (e.g. self-signed or unverified), test basic SSL handshake
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_info["has_ssl"] = True
        except Exception:
            pass
    return tls_info

def _extract_error_dom(target_url: str, ua: dict) -> dict:
    """
    Send a deliberately-malformed-path request to fingerprint error page structure
    (hash of DOM tag sequence, ignoring dynamic content).
    """
    error_dom = {
        "dom_hash": "",
        "tag_count": 0,
        "common_tags": []
    }
    malformed_url = urllib.parse.urljoin(target_url, "/__bron_probe_404_err_fingerprint__")
    try:
        err_resp = requests.get(malformed_url, headers=ua, timeout=4, verify=False, allow_redirects=False)
        tags = re.findall(r'<([a-zA-Z0-9]+)', err_resp.text)
        if tags:
            tag_sequence = ",".join(t.lower() for t in tags)
            error_dom["dom_hash"] = hashlib.sha256(tag_sequence.encode("utf-8")).hexdigest()[:16]
            error_dom["tag_count"] = len(tags)
            error_dom["common_tags"] = list(dict.fromkeys(t.lower() for t in tags))[:10]
    except Exception:
        pass
    return error_dom

def run_recon(target_url: str) -> dict:
    """
    Executes DNS, HTTP scans, multi-signal feature extraction, and probabilistic ensemble
    technology detection. Retains verbatim the downstream contract required by Stage 2.
    """
    result = {
        "target_url": target_url,
        "ip_addresses": [],
        "headers": {},
        "security_headers": {},
        "detected_technologies": [],
        "errors": []
    }

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    hostname = target_url.split("//")[-1].split("/")[0].split(":")[0]

    try:
        ips = socket.getaddrinfo(hostname, None)
        seen = set()
        for info in ips:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                result["ip_addresses"].append(ip)
    except socket.gaierror as e:
        result["errors"].append(f"DNS resolution failed: {str(e)}")

    ua = {"User-Agent": "Mozilla/5.0 (compatible; SecurityAnalyzer/1.0)"}
    html_content = ""
    cookies = []

    try:
        resp = requests.get(target_url, headers=ua, timeout=10, allow_redirects=True, verify=False)
        result["headers"] = dict(resp.headers)
        html_content = resp.text[:50000]
        cookies = _extract_cookies(resp)
        result["security_headers"] = {
            h: {"value": resp.headers.get(h), "present": resp.headers.get(h) is not None}
            for h in [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Content-Type-Options", "X-Frame-Options",
                "X-XSS-Protection", "Referrer-Policy", "Permissions-Policy"
            ]
        }
    except Exception as e:
        result["errors"].append(f"HTTP request failed: {str(e)}")

    # Multi-signal feature extraction
    favicon_hash = _extract_favicon_hash(target_url, html_content, ua)
    tls_cert = _extract_tls_metadata(hostname)
    error_dom = _extract_error_dom(target_url, ua)

    feature_blob = {
        "target_url": target_url,
        "headers": result["headers"],
        "cookies": cookies,
        "favicon_hash": favicon_hash,
        "tls_cert": tls_cert,
        "error_dom": error_dom,
        "html_content": html_content
    }

    # Store full feature blob per scan in SQLite persistence
    try:
        save_scan_features(target_url, feature_blob)
    except Exception as e:
        result["errors"].append(f"Persistence error: {str(e)}")

    # 1. Exact-string signature detection (preserves version extraction)
    headers_lower = {k.lower(): str(v).lower() for k, v in result["headers"].items()}
    html_lower = html_content.lower()
    signature_detected = {}

    for tech_name, sigs in TECH_SIGNATURES.items():
        found, version = False, None
        for sig in sigs.get("headers", []):
            key, _, val = sig.partition(":")
            if val in headers_lower.get(key, ""):
                found = True
                m = re.search(r"[\d]+\.[\d]+\.?[\d]*", headers_lower.get(key, ""))
                if m:
                    version = m.group()
                break
        if not found:
            for pat in sigs.get("html_patterns", []):
                if pat in html_lower:
                    found = True
                    m = re.search(rf"{re.escape(pat)}[/\-]?([\d]+\.[\d]+\.?[\d]*)", html_lower)
                    if m:
                        version = m.group(1)
                    break
        if found:
            signature_detected[tech_name] = {
                "name": tech_name,
                "version": version,
                "cpe_keyword": sigs["cpe_keyword"]
            }

    # 2. Probabilistic Classifier Inference
    classifier_detected = []
    max_confidence = 0.0
    try:
        clf_result = predict_technologies(feature_blob, threshold=0.7)
        classifier_detected = clf_result.get("detected", [])
        max_confidence = clf_result.get("max_confidence", 0.0)
    except Exception as e:
        result["errors"].append(f"Classifier inference warning: {str(e)}")

    # 3. Ensemble Merge:
    # - If both agree, keep signature match's reliable version-extraction result
    # - If classifier detects tech that signature missed, add it with cpe_keyword
    final_detected = []
    seen_names = set()

    # Build a quick confidence lookup from classifier results
    clf_confidence_map = {item["name"]: item["confidence"] for item in classifier_detected}

    for tech_name, tech_data in signature_detected.items():
        # Mark as both if classifier also detected it above threshold
        if tech_name in clf_confidence_map:
            tech_data["detection_method"] = "signature+classifier"
            tech_data["confidence"] = clf_confidence_map[tech_name]
        else:
            tech_data["detection_method"] = "signature"
            tech_data["confidence"] = None
        final_detected.append(tech_data)
        seen_names.add(tech_name)

    for clf_item in classifier_detected:
        tech_name = clf_item["name"]
        if tech_name not in seen_names:
            # Attempt version extraction if patterns match, otherwise None
            version = None
            sigs = TECH_SIGNATURES.get(tech_name, {})
            for sig in sigs.get("headers", []):
                key, _, _ = sig.partition(":")
                m = re.search(r"[\d]+\.[\d]+\.?[\d]*", headers_lower.get(key, ""))
                if m:
                    version = m.group()
                    break
            if not version:
                for pat in sigs.get("html_patterns", []):
                    m = re.search(rf"{re.escape(pat)}[/\-]?([\d]+\.[\d]+\.?[\d]*)", html_lower)
                    if m:
                        version = m.group(1)
                        break

            final_detected.append({
                "name": tech_name,
                "version": version,
                "cpe_keyword": clf_item.get("cpe_keyword", sigs.get("cpe_keyword", f"{tech_name.lower()} {tech_name.lower()}")),
                "detection_method": "classifier",
                "confidence": clf_item.get("confidence")
            })
            seen_names.add(tech_name)

    result["detected_technologies"] = final_detected
    result["cookies"] = cookies
    result["favicon_hash"] = favicon_hash
    result["tls_cert"] = tls_cert
    result["error_dom"] = error_dom

    # 4. Fallback for unknown / novel tech:
    # Stash feature vector in novel_candidates table if below confidence threshold across all known labels
    if not final_detected or max_confidence < 0.7:
        try:
            save_novel_candidate(target_url, feature_blob, max_confidence)
        except Exception:
            pass

    return result
