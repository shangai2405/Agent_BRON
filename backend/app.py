import json
from datetime import datetime
import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from agent.recon import run_recon
from agent.vuln_assessment import run_vuln_assessment
from agent.bron_mapper import run_bron_mapping
from agent.compliance import run_compliance_mapping

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BACKEND_DIR), "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data or not data.get("target"):
        return jsonify({"error": "Missing target"}), 400

    target = data["target"].strip()
    if not target:
        return jsonify({"error": "Target cannot be empty"}), 400

    pipeline_result = {
        "target": target,
        "started_at": datetime.utcnow().isoformat(),
        "stages": {}
    }

    try:
        print(f"Stage 1: Recon - {target}")
        recon = run_recon(target)
        pipeline_result["stages"]["recon"] = {"status": "done", "data": recon}
    except Exception as e:
        pipeline_result["stages"]["recon"] = {"status": "error", "error": str(e)}
        return jsonify(pipeline_result), 200

    detected_tech = recon.get("detected_technologies", [])

    try:
        print(f"Stage 2: Vulnerability Assessment - {len(detected_tech)} technologies")
        if detected_tech:
            vuln = run_vuln_assessment(detected_tech)
        else:
            vuln = {
                "total_cves": 0,
                "cves": [],
                "tech_summary": {},
                "errors": ["No technologies detected to assess"]
            }
        pipeline_result["stages"]["vulnerability"] = {"status": "done", "data": vuln}
    except Exception as e:
        pipeline_result["stages"]["vulnerability"] = {"status": "error", "error": str(e)}
        vuln = {"cves": [], "total_cves": 0, "tech_summary": {}, "errors": [str(e)]}

    try:
        print(f"Stage 3: BRON Mapping - {vuln['total_cves']} CVEs")
        bron = run_bron_mapping(vuln.get("cves", []))
        pipeline_result["stages"]["bron"] = {"status": "done", "data": bron}
    except Exception as e:
        pipeline_result["stages"]["bron"] = {"status": "error", "error": str(e)}
        bron = {"chains": [], "unique_attack_techniques": [], "total_chains": 0}

    try:
        print("Stage 4: Compliance Mapping")
        compliance = run_compliance_mapping(bron, recon)
        pipeline_result["stages"]["compliance"] = {"status": "done", "data": compliance}
    except Exception as e:
        pipeline_result["stages"]["compliance"] = {"status": "error", "error": str(e)}

    pipeline_result["completed_at"] = datetime.utcnow().isoformat()
    pipeline_result["status"] = "complete"

    return jsonify(pipeline_result), 200

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("Starting backend on http://localhost:5050")
    app.run(host="0.0.0.0", port=5050, debug=True)
