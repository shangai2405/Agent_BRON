import json, os

DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "attack_to_nist.json")

CWE_TO_OWASP = {
    "CWE-89":  {"id":"A03:2021","name":"Injection"},
    "CWE-79":  {"id":"A03:2021","name":"Injection"},
    "CWE-287": {"id":"A07:2021","name":"Identification and Authentication Failures"},
    "CWE-200": {"id":"A02:2021","name":"Cryptographic Failures"},
    "CWE-352": {"id":"A01:2021","name":"Broken Access Control"},
    "CWE-22":  {"id":"A01:2021","name":"Broken Access Control"},
    "CWE-119": {"id":"A04:2021","name":"Insecure Design"},
    "CWE-434": {"id":"A04:2021","name":"Insecure Design"},
    "CWE-502": {"id":"A08:2021","name":"Software and Data Integrity Failures"},
    "CWE-601": {"id":"A10:2021","name":"Server-Side Request Forgery"},
    "CWE-416": {"id":"A06:2021","name":"Vulnerable and Outdated Components"},
    "CWE-125": {"id":"A06:2021","name":"Vulnerable and Outdated Components"},
    "CWE-476": {"id":"A06:2021","name":"Vulnerable and Outdated Components"},
    "CWE-190": {"id":"A06:2021","name":"Vulnerable and Outdated Components"},
    "CWE-20":  {"id":"A03:2021","name":"Injection"},
}

# read attack technique mapping file....
def load_attack_mapping():
    try:
        with open(DATA_FILE) as f: return json.load(f)
    except: return {}

# compile compliance mapping report details....
def run_compliance_mapping(bron_result, recon_result):
    mapping = load_attack_mapping()
    techniques = bron_result.get("unique_attack_techniques", [])
    chains = bron_result.get("chains", [])

    nist_findings, cis_findings, owasp_findings = {}, {}, {}

    # loop attack techniques to lookup nist nd cis controls....
    for t in techniques:
        m = mapping.get(t["id"], {})
        # loop nist controls to save findings....
        for i, ctrl in enumerate(m.get("nist", [])):
            nist_findings.setdefault(ctrl, {"control":ctrl,"description":m["nist_desc"][i] if i<len(m.get("nist_desc",[]))else "","triggered_by":[]})["triggered_by"].append(t["id"])
        # loop cis controls to save findings....
        for i, ctrl in enumerate(m.get("cis", [])):
            cis_findings.setdefault(ctrl, {"control":ctrl,"description":m["cis_desc"][i] if i<len(m.get("cis_desc",[]))else "","triggered_by":[]})["triggered_by"].append(t["id"])

    # loop threat chains to get owasp mappings....
    for chain in chains:
        # loop cwes to match owasp categories....
        for cwe in chain.get("cwes", []):
            owasp = CWE_TO_OWASP.get(cwe["id"])
            if owasp:
                oid = owasp["id"]
                owasp_findings.setdefault(oid,{"id":oid,"name":owasp["name"],"triggered_by_cwes":[]})
                if cwe["id"] not in owasp_findings[oid]["triggered_by_cwes"]:
                    owasp_findings[oid]["triggered_by_cwes"].append(cwe["id"])

    sec_h = recon_result.get("security_headers", {})
    header_compliance = [{"header":h,"status":"PASS" if d["present"] else "FAIL","value":d.get("value","")} for h,d in sec_h.items()]

    nist_score   = max(0, 100 - len(nist_findings)*10)
    cis_score    = max(0, 100 - len(cis_findings)*10)
    owasp_score  = max(0, 100 - len(owasp_findings)*12)
    header_score = (sum(1 for d in sec_h.values() if d["present"]) / max(len(sec_h),1)) * 100
    overall      = round((nist_score + cis_score + owasp_score + header_score) / 4)

    return {
        "nist_800_53": list(nist_findings.values()),
        "cis_controls": list(cis_findings.values()),
        "owasp_top10": list(owasp_findings.values()),
        "security_headers": header_compliance,
        "scores": {
            "nist_compliance": round(nist_score),
            "cis_compliance": round(cis_score),
            "owasp_compliance": round(owasp_score),
            "security_headers": round(header_score),
            "overall": overall
        }
    }
