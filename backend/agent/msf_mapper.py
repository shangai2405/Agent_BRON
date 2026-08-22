from .msf_client import MSFClient


class MSFMapper:
    """
    Takes CVE records produced by vuln_assessment.fetch_cves() and checks
    whether Metasploit has a matching exploit module for each one.
    Does NOT run or execute anything -- enrichment/discovery only.
    """

    def __init__(self, msf_client: MSFClient):
        self.msf = msf_client

    def enrich_vulnerabilities(self, vuln_list: list[dict]) -> list[dict]:
        """
        vuln_list: [{ "cve_id": "CVE-2023-XXXX", "cvss_score": 7.5, ... }, ...]
        Adds:
          - msf_modules: list of MSF module names referencing this CVE
          - exploit_available: bool, True if any modules were found
        """
        for vuln in vuln_list:
            cve = vuln.get("cve_id")
            if cve:
                vuln["msf_modules"] = self.msf.search_by_cve(cve)
                vuln["exploit_available"] = len(vuln["msf_modules"]) > 0
            else:
                vuln["msf_modules"] = []
                vuln["exploit_available"] = False
        return vuln_list