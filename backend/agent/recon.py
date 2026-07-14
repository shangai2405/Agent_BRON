import socket
import requests
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# does dns nd http scans for tech detection....
def run_recon(target_url: str) -> dict:
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
        # loop dns ips to save unique ones....
        for info in ips:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                result["ip_addresses"].append(ip)
    except socket.gaierror as e:
        result["errors"].append(f"DNS resolution failed: {str(e)}")

    ua = {"User-Agent": "Mozilla/5.0 (compatible; SecurityAnalyzer/1.0)"}
    html_content = ""
    try:
        resp = requests.get(target_url, headers=ua, timeout=10, allow_redirects=True, verify=False)
        result["headers"] = dict(resp.headers)
        html_content = resp.text[:50000]
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

    headers_lower = {k.lower(): v.lower() for k, v in result["headers"].items()}
    html_lower = html_content.lower()
    detected = []
    # loop standard tech signatures to check match....
    for tech_name, sigs in TECH_SIGNATURES.items():
        found, version = False, None
        # check headers for tech version match....
        for sig in sigs.get("headers", []):
            key, _, val = sig.partition(":")
            if val in headers_lower.get(key, ""):
                found = True
                m = re.search(r"[\d]+\.[\d]+\.?[\d]*", headers_lower.get(key, ""))
                if m: version = m.group()
                break
        if not found:
            # check html tags if page matches tech pattern....
            for pat in sigs.get("html_patterns", []):
                if pat in html_lower:
                    found = True
                    m = re.search(rf"{re.escape(pat)}[/\-]?([\d]+\.[\d]+\.?[\d]*)", html_lower)
                    if m: version = m.group(1)
                    break
        if found:
            detected.append({"name": tech_name, "version": version, "cpe_keyword": sigs["cpe_keyword"]})
    result["detected_technologies"] = detected
    return result
