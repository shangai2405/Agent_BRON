import logging
from typing import Optional, Dict, Any, List

try:
    import arango
    ARANGO_AVAILABLE = True
except ImportError:
    ARANGO_AVAILABLE = False

BRON_HOST = "http://bron.alfa.csail.mit.edu:8529"
BRON_DB   = "BRON"
BRON_USER = "guest"
BRON_PASS = "guest"

CWE_TO_CAPEC_FALLBACK = {
    "CWE-79":  [("CAPEC-86",  "XSS via HTTP Query Strings"),
                ("CAPEC-198", "XSS via HTTP Headers")],
    "CWE-89":  [("CAPEC-66",  "SQL Injection"),
                ("CAPEC-7",   "Blind SQL Injection")],
    "CWE-22":  [("CAPEC-126", "Path Traversal"),
                ("CAPEC-139", "Relative Path Traversal")],
    "CWE-20":  [("CAPEC-28",  "Fuzzing for Application Mapping")],
    "CWE-200": [("CAPEC-118", "Collect and Analyze Information")],
    "CWE-287": [("CAPEC-114", "Authentication Abuse"),
                ("CAPEC-196", "Session Credential Falsification")],
    "CWE-352": [("CAPEC-62",  "Cross-Site Request Forgery"),
                ("CAPEC-60",  "Reusing Session IDs")],
    "CWE-416": [("CAPEC-46",  "Overflow Variables and Tags")],
    "CWE-125": [("CAPEC-540", "Overread Buffers")],
    "CWE-476": [("CAPEC-46",  "Overflow Variables and Tags")],
    "CWE-119": [("CAPEC-100", "Overflow Buffers"),
                ("CAPEC-14",  "Client-side Injection-induced Buffer Overflow")],
    "CWE-190": [("CAPEC-92",  "Forced Integer Overflow")],
    "CWE-601": [("CAPEC-194", "Fake the Source of Data")],
    "CWE-434": [("CAPEC-1",   "Accessing HTTP Cookies"),
                ("CAPEC-17",  "Accessing/Intercepting/Modifying HTTP Cookies")],
    "CWE-502": [("CAPEC-586", "Object Injection")],
}

CAPEC_TO_TECHNIQUE_FALLBACK = {
    "CAPEC-86":  [("T1059", "Command and Scripting Interpreter")],
    "CAPEC-198": [("T1189", "Drive-by Compromise")],
    "CAPEC-66":  [("T1190", "Exploit Public-Facing Application")],
    "CAPEC-7":   [("T1190", "Exploit Public-Facing Application")],
    "CAPEC-126": [("T1083", "File and Directory Discovery")],
    "CAPEC-139": [("T1190", "Exploit Public-Facing Application")],
    "CAPEC-28":  [("T1190", "Exploit Public-Facing Application")],
    "CAPEC-118": [("T1046", "Network Service Discovery")],
    "CAPEC-114": [("T1078", "Valid Accounts")],
    "CAPEC-196": [("T1078", "Valid Accounts")],
    "CAPEC-62":  [("T1204", "User Execution")],
    "CAPEC-60":  [("T1539", "Steal Web Session Cookie")],
    "CAPEC-100": [("T1210", "Exploitation of Remote Services")],
    "CAPEC-14":  [("T1210", "Exploitation of Remote Services")],
    "CAPEC-194": [("T1189", "Drive-by Compromise")],
    "CAPEC-1":   [("T1110", "Brute Force")],
    "CAPEC-17":  [("T1110", "Brute Force")],
    "CAPEC-46":  [("T1499", "Endpoint Denial of Service")],
    "CAPEC-540": [("T1046", "Network Service Discovery")],
    "CAPEC-586": [("T1059", "Command and Scripting Interpreter")],
    "CAPEC-92":  [("T1499", "Endpoint Denial of Service")],
}

TECHNIQUE_TO_TACTIC_FALLBACK = {
    "T1059": "Execution",
    "T1189": "Initial Access",
    "T1190": "Initial Access",
    "T1083": "Discovery",
    "T1046": "Discovery",
    "T1078": "Defense Evasion / Persistence",
    "T1204": "Execution",
    "T1539": "Credential Access",
    "T1210": "Lateral Movement",
    "T1110": "Credential Access",
    "T1499": "Impact",
}

CWE_NAMES = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-22": "Path Traversal",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Information Exposure",
    "CWE-287": "Improper Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-416": "Use After Free",
    "CWE-125": "Out-of-bounds Read",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-119": "Buffer Overflow",
    "CWE-190": "Integer Overflow",
    "CWE-601": "URL Redirection to Untrusted Site",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
}

CVE_INBOUND_AQL = """
FOR cve IN cve
    FILTER cve.original_id == "{cve_id}"
    LIMIT 1
    LET cwe_docs = (
        FOR cwe IN 1..1 INBOUND cve CweCve
            LET mit_texts = (
                FOR mit IN 1..1 OUTBOUND cwe CweCwe_mitigation
                    RETURN DISTINCT mit.metadata.Description
            )
            RETURN {{
                id: cwe.original_id, 
                name: cwe.name,
                description: cwe.metadata.description,
                short_description: cwe.metadata.short_description,
                mitigations: mit_texts
            }}
    )
    LET capec_docs = (
        FOR cwe IN 1..1 INBOUND cve CweCve
            FOR capec IN 1..1 INBOUND cwe CapecCwe
                RETURN DISTINCT {{
                    id: capec.original_id, 
                    name: capec.name,
                    description: capec.metadata.description
                }}
    )
    LET technique_docs = (
        FOR cwe IN 1..1 INBOUND cve CweCve
            FOR capec IN 1..1 INBOUND cwe CapecCwe
                FOR technique IN 1..1 INBOUND capec TechniqueCapec
                    RETURN DISTINCT {{id: technique.original_id, name: technique.name}}
    )
    LET tactic_docs = (
        FOR cwe IN 1..1 INBOUND cve CweCve
            FOR capec IN 1..1 INBOUND cwe CapecCwe
                FOR technique IN 1..1 INBOUND capec TechniqueCapec
                    FOR tactic IN 1..1 INBOUND technique TacticTechnique
                        RETURN DISTINCT {{id: tactic.original_id, name: tactic.name}}
    )
    RETURN {{
        cwe: cwe_docs,
        capec: capec_docs,
        technique: technique_docs,
        tactic: tactic_docs
    }}
"""

# setup db client to connect to arangodb....
def get_bron_client() -> Optional[Any]:
    if not ARANGO_AVAILABLE:
        return None
    try:
        client = arango.ArangoClient(hosts=BRON_HOST)
        db = client.db(BRON_DB, username=BRON_USER, password=BRON_PASS, auth_method="basic")
        db.collections()
        return db
    except Exception as e:
        logging.warning(f"BRON connection failed: {e}")
        return None

# query database using real aql traversal....
def query_bron_for_cve(cve_id: str, db: Any) -> Optional[Dict]:
    try:
        aql = CVE_INBOUND_AQL.format(cve_id=cve_id)
        cursor = db.aql.execute(aql)
        # loop through cursor docs to return match....
        for doc in cursor:
            return doc
    except Exception as e:
        logging.warning(f"BRON AQL query failed for {cve_id}: {e}")
    return None

# format live database result fields....
def build_chain_from_bron(cve: Dict, bron_data: Optional[Dict]) -> Dict:
    cve_id = cve["cve_id"]

    chain = {
        "cve_id": cve_id,
        "tech": cve["tech"],
        "severity": cve["severity"],
        "cvss_score": cve["cvss_score"],
        "source": "bron_live",
        "cwes": [],
        "capecs": [],
        "attack_techniques": [],
        "tactics": [],
        "cause": None,
        "attacker_action": None,
        "solution": None
    }

    if bron_data:
        # loop cwe nodes to prepend prefixes....
        for d in (bron_data.get("cwe") or []):
            cwe_raw_id = str(d["id"])
            cwe_id = f"CWE-{cwe_raw_id}" if not cwe_raw_id.startswith("CWE-") else cwe_raw_id
            chain["cwes"].append({
                "id": cwe_id,
                "name": d.get("name") or CWE_NAMES.get(cwe_id, d.get("name") or cwe_id)
            })

        # loop capec nodes to format ids....
        for d in (bron_data.get("capec") or []):
            capec_raw_id = str(d["id"])
            capec_id = f"CAPEC-{capec_raw_id}" if not capec_raw_id.startswith("CAPEC-") else capec_raw_id
            chain["capecs"].append({
                "id": capec_id,
                "name": d.get("name") or capec_id
            })

        chain["attack_techniques"] = [
            {
                "id": d["id"],
                "name": d.get("name", d["id"]),
                "tactic": TECHNIQUE_TO_TACTIC_FALLBACK.get(d["id"], "Unknown"),
            }
            for d in (bron_data.get("technique") or [])
        ]
        chain["tactics"] = [
            {"id": d["id"], "name": d.get("name", d["id"])}
            for d in (bron_data.get("tactic") or [])
        ]

        # Extract root causes from CWE descriptions
        cwe_descs = []
        for d in (bron_data.get("cwe") or []):
            desc = d.get("description") or d.get("short_description")
            if desc:
                cwe_descs.append(desc.strip())
        if cwe_descs:
            chain["cause"] = " | ".join(cwe_descs)

        # Extract attacker actions from CAPEC descriptions
        capec_descs = []
        for d in (bron_data.get("capec") or []):
            desc = d.get("description")
            if desc:
                capec_id_label = f"CAPEC-{d['id']}" if not str(d['id']).startswith("CAPEC-") else d['id']
                capec_descs.append(f"[{capec_id_label}] {desc.strip()}")
        if capec_descs:
            chain["attacker_action"] = " ".join(capec_descs[:2])

        # Extract solutions from CWE mitigations
        mit_texts = []
        for d in (bron_data.get("cwe") or []):
            for mit in (d.get("mitigations") or []):
                if mit and mit.strip():
                    mit_texts.append(mit.strip())
        if mit_texts:
            chain["solution"] = " ".join(mit_texts[:2])

    return chain

# format static chain when database offline....
def build_chain_from_fallback(cve: Dict) -> Dict:
    chain = {
        "cve_id": cve["cve_id"],
        "tech": cve["tech"],
        "severity": cve["severity"],
        "cvss_score": cve["cvss_score"],
        "source": "fallback_mappings",
        "cwes": [],
        "capecs": [],
        "attack_techniques": [],
        "tactics": [],
    }

    seen_capec = set()
    seen_technique = set()

    # loop top cwes to map fallback capecs....
    for cwe_id in cve.get("cwes", [])[:3]:
        chain["cwes"].append({
            "id": cwe_id,
            "name": CWE_NAMES.get(cwe_id, cwe_id)
        })
        # loop capecs to find threat techniques....
        for capec_id, capec_name in CWE_TO_CAPEC_FALLBACK.get(cwe_id, [])[:2]:
            if capec_id not in seen_capec:
                seen_capec.add(capec_id)
                chain["capecs"].append({"id": capec_id, "name": capec_name})
                # loop attack techniques to get tactics....
                for tech_id, tech_name in CAPEC_TO_TECHNIQUE_FALLBACK.get(capec_id, []):
                    if tech_id not in seen_technique:
                        seen_technique.add(tech_id)
                        chain["attack_techniques"].append({
                            "id": tech_id,
                            "name": tech_name,
                            "tactic": TECHNIQUE_TO_TACTIC_FALLBACK.get(tech_id, "Unknown")
                        })

    return chain

# main function for mapping threat chains....
def run_bron_mapping(cves: List[Dict]) -> Dict:
    bron_db = get_bron_client()
    bron_online = bron_db is not None

    chains = []
    # loop top cves to build graph mappings....
    for cve in cves[:10]:
        bron_data = None
        if bron_online:
            bron_data = query_bron_for_cve(cve["cve_id"], bron_db)

        if bron_data and (bron_data.get("cwe") or bron_data.get("capec") or bron_data.get("technique")):
            chain = build_chain_from_bron(cve, bron_data)
        else:
            chain = build_chain_from_fallback(cve)

        if chain["cwes"] or chain["capecs"] or chain["attack_techniques"]:
            chains.append(chain)

    all_techniques: Dict[str, Dict] = {}
    # loop formatted chains to count unique techniques....
    for chain in chains:
        # loop attack techniques to links related cves....
        for t in chain["attack_techniques"]:
            if t["id"] not in all_techniques:
                all_techniques[t["id"]] = {**t, "related_cves": []}
            all_techniques[t["id"]]["related_cves"].append(chain["cve_id"])

    return {
        "bron_source": "live_arangodb" if bron_online else "fallback_mappings",
        "bron_online": bron_online,
        "chains": chains,
        "unique_attack_techniques": list(all_techniques.values()),
        "total_chains": len(chains),
    }
