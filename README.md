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

### 3. Setup Local Secrets & Configuration
Create a `.env` file in the `backend/` directory to configure the Metasploit RPC credentials:
```bash
touch .env
echo "MSF_RPC_PASS=your-strong-password-here" >> .env
```

---

## Running Infrastructure Services

Ensure you have Docker installed. Use the Compose file located in `bron-source/` to start the backend services:

```bash
cd bron-source
# Start ArangoDB and Metasploit RPC container
docker compose up -d
```

* **ArangoDB**: Runs locally to cache/load graph elements or verify connections.
* **Metasploit RPC (`msfrpcd`)**: Starts a background Metasploit container with MSF API endpoints listening on port `55553`.

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
