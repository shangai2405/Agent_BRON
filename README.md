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

### 1. Configure virtual environment & install requirements
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Metasploit RPC Setup (required for exploit-enrichment)
The vulnerability assessment stage checks CVEs against Metasploit's exploit module database. This requires a running `msfrpcd` container and a shared password between the backend and Docker Compose.

* Copy the example env files and set the same `MSF_RPC_PASS` value in both:
  ```bash
  cp backend/.env.example backend/.env
  cp bron-source/.env.example bron-source/.env
  ```
  Edit both `.env` files to set `MSF_RPC_PASS` to the same password value. No quotes or spaces around `=`.
* Start the Metasploit RPC container:
  ```bash
  cd bron-source
  docker-compose up -d msfrpc --force-recreate
  docker logs msfrpc
  ```
  Wait for `MSGRPC starting... (NO SSL)` in the logs before continuing.

### 3. Launch Flask server
Ensure your virtual environment is active:
```bash
cd backend
source venv/bin/activate
python3 app.py
```
Open **[http://localhost:5050/](http://localhost:5050/)** in your web browser.

---

## Troubleshooting

* `KeyError: 'MSF_RPC_PASS'` → `.env` is missing or Flask was not restarted after editing.
* `MsfRPC: Authentication failed` → password in `backend/.env` doesn't match `bron-source/.env`.
* First scan takes longer than usual because it compiles a cached index map of all Metasploit exploit modules for fast subsequent lookups.

---

## Login Credentials

| Username | Password | Role |
| :--- | :--- | :--- |
| **`admin`** | **`bron123`** | Administrator Access |
| **`user`** | **`pass123`** | Standard User |
