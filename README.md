# BRON Security & Compliance Agent

A multi-stage web application pipeline for passive domain reconnaissance, NVD vulnerability scanning, threat intelligence mapping via the MITRE BRON graph, and compliance translation.

---

## Features

1. **Passive Reconnaissance**: Resolves IP addresses, extracts HTTP response headers, and detects running technologies (e.g., Apache, Nginx, PHP, OpenSSL, jQuery).
2. **Vulnerability Assessment**: Queries NVD CVE API v2 for detected technology stacks to retrieve CVSS ratings, published dates, and mitigation recommendations.
3. **Metasploit Exploit Integration**: Cross-references CVE IDs with a locally running Metasploit instance over MsfRPC to check for known exploit modules and displays them.
4. **MITRE BRON Threat Traversal**: Connects to the public MITRE BRON ArangoDB database to map identified vulnerabilities to weakness standards (CWE), attack patterns (CAPEC), and enterprise tactics (ATT&CK).
5. **Compliance Translation**: Maps ATT&CK techniques and CWEs to NIST SP 800-53 controls, CIS Controls, and OWASP Top 10 categories to calculate security scores.

---

## File Structure

```text
BRON/
├── backend/
│   ├── app.py                     # Main Flask server entry point (port 5050)
│   ├── requirements.txt           # Python backend dependencies
│   ├── .env                       # Environment variables config (ignored in Git)
│   ├── data/
│   │   └── attack_to_nist.json    # Static ATT&CK -> NIST/CIS/OWASP mapping database
│   └── agent/
│       ├── __init__.py            # Package initialization
│       ├── recon.py               # Passive DNS & tech signature fingerprinting
│       ├── vuln_assessment.py     # CVE collection & vulnerability enrichment
│       ├── msf_client.py          # Metasploit RPC client integration
│       ├── msf_mapper.py          # Matches CVEs to MSF modules
│       ├── bron_mapper.py         # MITRE BRON database graph traversal logic
│       └── compliance.py          # Compliance control scoring mapping
├── frontend/
│   ├── index.html                 # Main dashboard structural interface
│   ├── styles.css                 # Dark-mode styling, overlays, and drawer components
│   └── app.js                     # Dashboard interaction, steppers, and filters
├── bron-source/                   # Submodule directory containing compose configuration
│   └── docker-compose.yml         # Container configuration for ArangoDB and Metasploit RPC
├── .gitignore                     # Git ignore rules for cached, venv, and secret files
├── msfinstall                     # Metasploit Framework package installer script
└── README.md                      # Project documentation
```

---

## Prerequisites & Installation

### 1. Repository Setup & Git Flow
If you are pulling/running this repository for the first time, clone the repository and switch to the active development branch:
```bash
git clone https://github.com/shangai2405/Agent_BRON.git
cd Agent_BRON
git checkout shangai
git pull origin shangai
```

### 2. Configure Backend Virtual Environment
Create a virtual environment inside the `backend` directory and install the requirements:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Metasploit RPC Setup (required for exploit-availability enrichment)

The vulnerability assessment stage checks CVEs against Metasploit's exploit module database. This requires a running `msfrpcd` container and a shared password between the backend and Docker Compose.

1. Copy the example env files and fill in a password (use the same value in both):
```bash
cp backend/.env.example backend/.env
cp bron-source/.env.example bron-source/.env
```
   Edit both `.env` files and set `MSF_RPC_PASS` to the same value in each. No quotes, no spaces around the `=`.

2. Start the Metasploit RPC container:
```bash
cd bron-source
docker-compose up -d msfrpc --force-recreate
docker logs msfrpc
```
   Wait for `MSGRPC ready at ...` or `MSGRPC starting... (NO SSL)` in the logs before continuing.

3. Restart the backend so it picks up the password:
```bash
cd backend
python3 app.py
```

**Troubleshooting:**
- `KeyError: 'MSF_RPC_PASS'` → `.env` is missing or Flask wasn't restarted after editing it.
- `MsfRPC: Authentication failed` → the password in `backend/.env` doesn't match `bron-source/.env`. They must be identical.
- First vulnerability-assessment run after startup is slower than usual — it builds a one-time CVE-to-module index across all Metasploit modules.

---

## How to Start the Application

### 1. Launch the Backend Server
Make sure your virtual environment is active, then launch the Flask server:
```bash
cd backend
source venv/bin/activate
python3 app.py
```
The server will start up on **`http://localhost:5050`**.

### 2. Open the UI
Go to your browser and open:
👉 **[http://localhost:5050/](http://localhost:5050/)**

---

## Dashboard Login Credentials

| Username | Password | Role |
| :--- | :--- | :--- |
| **`admin`** | **`bron123`** | Administrator Access |
| **`user`** | **`pass123`** | Standard Audit View |
