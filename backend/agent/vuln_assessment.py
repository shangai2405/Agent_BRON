import os
import time
import requests
from dotenv import load_dotenv

from .msf_client import MSFClient
from .msf_mapper import MSFMapper

load_dotenv()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEV_COLORS = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44cc44","NONE":"#888888","UNKNOWN":"#888888"}

# helper to map score to severity levels....
def cvss_to_sev(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"


CWE_ENRICHMENTS = {
    "CWE-79": {
        "cause": "Improper neutralization of user-controllable input before it is placed in output web pages (reflected, stored, or DOM-based XSS).",
        "attacker_action": "Inject malicious scripts into web pages viewed by other users, which can hijack sessions, steal cookies, or deface/redirect pages.",
        "solution": "Implement strict context-aware output encoding (HTML, JavaScript, CSS context), employ Content Security Policy (CSP), and sanitize inputs."
    },
    "CWE-89": {
        "cause": "Improper neutralization of special elements in SQL commands constructed from user inputs.",
        "attacker_action": "Execute arbitrary SQL queries on the backend database, allowing unauthorized reading, updating, or deleting of sensitive records.",
        "solution": "Use parameterized queries or prepared statements, avoid dynamic query string construction, and use safe Object Relational Mappers (ORMs)."
    },
    "CWE-22": {
        "cause": "Improper validation of file paths in user input, allowing relative or absolute paths containing special characters (like '../').",
        "attacker_action": "Access or read sensitive system files (configurations, credentials, source code) stored outside the web document root.",
        "solution": "Avoid direct user input in file paths. Resolve and validate absolute paths against a whitelist of permitted directories, or use indexes."
    },
    "CWE-20": {
        "cause": "The application does not validate or incorrectly validates input that can affect control flow, data flow, or system resources.",
        "attacker_action": "Supply malformed inputs to cause application crashes (denial of service), bypass authentication protocols, or trigger other logical exploits.",
        "solution": "Implement robust input validation checking length, format, boundaries, and type on all entry points using strict allowlists."
    },
    "CWE-200": {
        "cause": "The application unintentionally exposes sensitive system details, configuration keys, user data, or stack traces to unauthorized parties.",
        "attacker_action": "Leverage exposed information to gain deep knowledge of internal systems and architecture, facilitating further system compromise.",
        "solution": "Disable verbose error pages in production, sanitize system outputs/logs, and implement strict least-privilege access controls on APIs."
    },
    "CWE-287": {
        "cause": "Failure to properly verify the identity of a user when credentials or sessions are established.",
        "attacker_action": "Bypass authentication screens, conduct credential stuffing or brute force attacks, forge session tokens, and access victim profiles.",
        "solution": "Adopt secure authentication libraries, enforce strong password complexity policies, require Multi-Factor Authentication (MFA), and secure session IDs."
    },
    "CWE-352": {
        "cause": "The application does not verify whether a state-changing request originated from a trusted source or page.",
        "attacker_action": "Force authenticated users into performing unintended actions (such as email changes or transactions) via malicious links or cross-site payloads.",
        "solution": "Generate and validate cryptographic anti-CSRF tokens for all state-changing endpoints, and set Cookie SameSite attributes to Strict/Lax."
    },
    "CWE-416": {
        "cause": "Referencing memory using a pointer after the pointer has been freed, causing memory corruption or unexpected execution behavior.",
        "attacker_action": "Execute arbitrary code in system space or trigger memory access violations to crash applications (Denial of Service).",
        "solution": "Assign freed pointers to NULL, utilize modern memory-safe programming languages or smart pointers, and perform strict unit testing on allocations."
    },
    "CWE-125": {
        "cause": "Attempting to read data outside the memory boundaries of the designated buffer.",
        "attacker_action": "Read confidential program memory or cause process termination (Denial of Service) via read access violations.",
        "solution": "Validate that all array/pointer offsets are within strict index limits, use safe standard libraries, and compile with address sanitizers."
    },
    "CWE-476": {
        "cause": "Dereferencing a pointer that is expected to point to valid memory but is actually NULL.",
        "attacker_action": "Cause the host application to crash, resulting in a Denial of Service (DoS) for all active sessions.",
        "solution": "Always verify that objects or pointers are not null before execution, and use language safety operators to gracefully handle empty values."
    },
    "CWE-119": {
        "cause": "Improper restriction of memory operations within the bounds of a buffer, leading to read/write overflows.",
        "attacker_action": "Overwrite return addresses in application stack memory, hijacking instruction execution pointers to run remote malicious payloads.",
        "solution": "Replace unsafe functions (like strcpy, gets) with bounds-checked alternatives (strncpy), and enable modern compiler stack protection."
    },
    "CWE-190": {
        "cause": "An arithmetic operation results in an integer value that is too large or too small to be represented in the allocated variable type.",
        "attacker_action": "Wrap numerical values to bypass access validations, trigger undersized memory allocations, or cause subsequent buffer overflows.",
        "solution": "Incorporate bounds checking prior to math operations, select sufficiently large variable types, or use safe integer math modules."
    },
    "CWE-601": {
        "cause": "Client redirection targets are dynamically taken from user-supplied parameters without domain verification.",
        "attacker_action": "Redirect users to phishing sites that mimic authentic login panels, leveraging the authority of the original trusted domain.",
        "solution": "Avoid user-defined redirect targets. If dynamic redirects are required, strictly check targets against an allowed whitelist of local relative URLs."
    },
    "CWE-434": {
        "cause": "Allowing file uploads to paths accessible to the web server without verifying file extensions or file content types.",
        "attacker_action": "Upload executable scripts (like PHP, JSP, ASP) and trigger them via direct HTTP access, achieving remote code execution.",
        "solution": "Validate extensions against strict allowlists, rename uploaded documents, store files outside the web root, and restrict upload folder execution."
    },
    "CWE-502": {
        "cause": "Deserializing serialized data objects received from untrusted environments without checking the object types or structure.",
        "attacker_action": "Inject manipulated serialized objects containing system commands, achieving remote command execution when the application processes them.",
        "solution": "Avoid deserializing untrusted objects; use standard message formats (like JSON) and employ HMAC signatures to verify message integrity."
    }
}

def enrich_cve_details(cve):
    cwes = cve.get("cwes", [])
    severity = cve.get("severity", "UNKNOWN").upper()
    tech = cve.get("tech", "the software component")

    cause = None
    attacker_action = None
    solution = None

    # Try matching by primary CWE
    for cwe_id in cwes:
        if cwe_id in CWE_ENRICHMENTS:
            cause = CWE_ENRICHMENTS[cwe_id]["cause"]
            attacker_action = CWE_ENRICHMENTS[cwe_id]["attacker_action"]
            solution = CWE_ENRICHMENTS[cwe_id]["solution"]
            break

    # If not matched, try searching text for keywords
    if not cause:
        desc_lower = cve.get("description", "").lower()
        for cwe_id, enrich in CWE_ENRICHMENTS.items():
            name_keyword = ""
            if cwe_id == "CWE-79": name_keyword = "cross-site scripting"
            elif cwe_id == "CWE-89": name_keyword = "sql injection"
            elif cwe_id == "CWE-22": name_keyword = "directory traversal"
            elif cwe_id == "CWE-20": name_keyword = "input validation"
            elif cwe_id == "CWE-200": name_keyword = "information disclosure"
            elif cwe_id == "CWE-287": name_keyword = "authentication bypass"
            elif cwe_id == "CWE-352": name_keyword = "csrf"
            elif cwe_id == "CWE-416": name_keyword = "use-after-free"
            elif cwe_id == "CWE-125": name_keyword = "out-of-bounds read"
            elif cwe_id == "CWE-476": name_keyword = "null pointer"
            elif cwe_id == "CWE-119": name_keyword = "buffer overflow"
            elif cwe_id == "CWE-190": name_keyword = "integer overflow"
            elif cwe_id == "CWE-601": name_keyword = "open redirect"
            elif cwe_id == "CWE-434": name_keyword = "file upload"
            elif cwe_id == "CWE-502": name_keyword = "deserialization"

            if name_keyword and name_keyword in desc_lower:
                cause = enrich["cause"]
                attacker_action = enrich["attacker_action"]
                solution = enrich["solution"]
                break

    # Fallback to general severity-based templates
    if not cause:
        if severity == "CRITICAL":
            cause = f"A critical software vulnerability exists in the {tech} software module, exposing core functions."
            attacker_action = f"Attackers can exploit this flaw to execute arbitrary system commands, bypass security access screens, or extract entire datasets."
            solution = f"Immediately upgrade {tech} to the latest version. Implement network containment rules to shield high-risk APIs, and configure a Web Application Firewall."
        elif severity == "HIGH":
            cause = f"A high-severity input parsing or access verification flaw is present within the {tech} software package."
            attacker_action = f"Attackers can leverage this bypass to access private resources, write malicious settings, or trigger memory exhaustion crashes."
            solution = f"Update the {tech} deployment to a secure version. Audit authentication pathways and validate boundary constraints on input parameters."
        elif severity == "MEDIUM":
            cause = f"A medium-risk logical flaw or resource management issue exists in the {tech} stack."
            attacker_action = f"Attackers could exploit this to trigger Denial of Service conditions, extract system configuration info, or conduct cross-site spoofing."
            solution = f"Configure access control lists to prevent public discovery of {tech} services. Install the latest component updates."
        else:
            cause = f"A low-risk security anomaly or informative exposure exists in {tech}."
            attacker_action = f"Attackers might acquire system diagnostic signatures or trigger local errors without direct control."
            solution = f"Apply routine patches to {tech} and configure headers/footers to avoid displaying version banners."

    cve["cause"] = cause
    cve["attacker_action"] = attacker_action
    cve["solution"] = solution

# query nvd to get cves for technology....
def fetch_cves(tech, max_results=5):
    keyword = tech.get("cpe_keyword", tech.get("name",""))
    try:
        resp = requests.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": max_results}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return [{"error": str(e), "tech": tech["name"]}]

    cves = []
    # loop vulnerabilities in json response....
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        description = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
        cvss_score, severity = 0.0, "UNKNOWN"
        # loop metrics keys to grab cvss score....
        for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            ml = cve.get("metrics",{}).get(key,[])
            if ml:
                cd = ml[0].get("cvssData",{})
                cvss_score = cd.get("baseScore", 0.0)
                severity = ml[0].get("baseSeverity", cvss_to_sev(cvss_score)).upper()
                break
        cwes = [d["value"] for w in cve.get("weaknesses",[]) for d in w.get("description",[]) if d.get("value","").startswith("CWE-")]
        cve_record = {
            "cve_id": cve_id, "tech": tech["name"], "tech_version": tech.get("version"),
            "description": description,
            "cvss_score": cvss_score, "severity": severity,
            "severity_color": SEV_COLORS.get(severity,"#888888"),
            "cwes": cwes, "published": cve.get("published","")[:10],
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }
        enrich_cve_details(cve_record)
        cves.append(cve_record)
    return cves


# run check on all found techs....
def run_vuln_assessment(detected_technologies):
    all_cves, errors, tech_summary = [], [], {}

    # --- Metasploit integration ---
    # Set up the RPC client + mapper ONCE, outside the loop, so we don't
    # reopen an msfrpcd connection for every technology scanned.
    # Requires MSF_RPC_PASS in your .env (see msf_client.py / docker-compose msfrpc service).
    msf_client = MSFClient(password=os.environ["MSF_RPC_PASS"])
    mapper = MSFMapper(msf_client)

    # loop all detected technologies to query cves....
    for i, tech in enumerate(detected_technologies):
        if i > 0: time.sleep(6)
        cves = fetch_cves(tech, max_results=5)
        valid = [c for c in cves if "error" not in c]
        err   = [c for c in cves if "error" in c]

        # --- Metasploit integration ---
        # For each valid CVE found for this tech, check whether Metasploit
        # has a matching exploit module. Adds 'msf_modules' (list of module
        # names) and 'exploit_available' (bool) to each cve_record.
        valid = mapper.enrich_vulnerabilities(valid)

        all_cves.extend(valid)
        if err: errors.append(f"{tech['name']}: {err[0]['error']}")
        tech_summary[tech["name"]] = {
            "cve_count": len(valid),
            "max_severity": max((c["severity"] for c in valid), default="NONE"),
            "max_cvss": max((c["cvss_score"] for c in valid), default=0.0),
            # convenient rollup for the report/compliance stage
            "exploitable_cve_count": sum(1 for c in valid if c.get("exploit_available"))
        }
    all_cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return {"total_cves": len(all_cves), "cves": all_cves, "tech_summary": tech_summary, "errors": errors}