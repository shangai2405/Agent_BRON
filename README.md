# BRON Security Agent

A simple web application for passive domain security analysis, vulnerability assessment, and compliance mapping.

## What it Does

This tool performs a passive scan on any target domain to look up:
1. **Vulnerabilities**: Queries the NVD API to find CVEs associated with the domain's server software and libraries.
2. **Compliance Alignments**: Maps the vulnerabilities to standard security frameworks like NIST SP 800-53, CIS Controls, and OWASP Top 10.

---

## File Structure

### Backend Files (`backend/`)
* **[app.py](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/backend/app.py)**: The main Flask server. It exposes the API endpoints (`/api/analyze` and `/api/health`) and serves the frontend webpage.
* **[agent/recon.py](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/backend/agent/recon.py)**: Resolves the domain IP address and fingerprints server technologies (like Nginx, Apache, PHP) by scanning response headers and HTML patterns.
* **[agent/vuln_assessment.py](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/backend/agent/vuln_assessment.py)**: Takes the detected technologies and queries the NVD API to find matching CVE vulnerabilities and scores.
* **[agent/bron_mapper.py](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/backend/agent/bron_mapper.py)**: Maps vulnerabilities (CVEs) to CWEs, CAPECs, and ATT&CK techniques by querying the BRON ArangoDB instance (or uses fallback mappings if offline).
* **[agent/compliance.py](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/backend/agent/compliance.py)**: Matches vulnerabilities and attack techniques against compliance standards (NIST SP 800-53, CIS Controls, and OWASP Top 10) to calculate compliance scores.

### Frontend Files (`frontend/`)
* **[index.html](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/frontend/index.html)**: The simple search page structure.
* **[app.js](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/frontend/app.js)**: Simple JavaScript code that calls the backend API and prints the results in the browser tables.
* **[styles.css](file:///Users/shangai/Documents/CODING%20CLUBS/BRON/frontend/styles.css)**: Custom basic dark-mode layout.

---

## How to Run

1. **Start the Flask server**:
   ```bash
   python3 backend/app.py
   ```
2. **Open your browser**:
   Go to: **[http://localhost:5050/](http://localhost:5050/)**
3. Type in any domain (e.g., `example.com`) and click **Analyze**.


USERNAME AND PASSWORD 

user 	pass123
