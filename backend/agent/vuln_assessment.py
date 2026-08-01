import time
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEV_COLORS = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#ffcc00","LOW":"#44cc44","NONE":"#888888","UNKNOWN":"#888888"}

# helper to map score to severity levels....
def cvss_to_sev(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"


def enrich_cve_details(cve):
    severity = cve.get("severity", "UNKNOWN").upper()
    tech = cve.get("tech", "the software component")
    
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
    # loop all detected technologies to query cves....
    for i, tech in enumerate(detected_technologies):
        if i > 0: time.sleep(6)
        cves = fetch_cves(tech, max_results=5)
        valid = [c for c in cves if "error" not in c]
        err   = [c for c in cves if "error" in c]
        all_cves.extend(valid)
        if err: errors.append(f"{tech['name']}: {err[0]['error']}")
        tech_summary[tech["name"]] = {
            "cve_count": len(valid),
            "max_severity": max((c["severity"] for c in valid), default="NONE"),
            "max_cvss": max((c["cvss_score"] for c in valid), default=0.0)
        }
    all_cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return {"total_cves": len(all_cves), "cves": all_cves, "tech_summary": tech_summary, "errors": errors}
