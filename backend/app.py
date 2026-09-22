import json
from datetime import datetime
import os
from flask import Flask, request, jsonify, send_from_directory, Response, stream_with_context
from flask_cors import CORS
from dotenv import load_dotenv
load_dotenv()

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
        
        # Merge live BRON threat details back into Stage 2 CVEs dynamically
        if bron.get("bron_online") and bron.get("chains"):
            chain_map = {c["cve_id"]: c for c in bron.get("chains", [])}
            for cve in vuln.get("cves", []):
                chain = chain_map.get(cve["cve_id"])
                if chain:
                    if chain.get("cause"):
                        cve["cause"] = chain["cause"]
                    if chain.get("attacker_action"):
                        cve["attacker_action"] = chain["attacker_action"]
                    if chain.get("solution"):
                        cve["solution"] = chain["solution"]
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

@app.route("/api/analyze/stream", methods=["GET", "POST"])
def analyze_stream():
    if request.method == "POST":
        data = request.get_json() or {}
        target = data.get("target", "").strip()
    else:
        target = request.args.get("target", "").strip()

    if not target:
        return jsonify({"error": "Target cannot be empty"}), 400

    def generate():
        pipeline_result = {
            "target": target,
            "started_at": datetime.utcnow().isoformat(),
            "stages": {}
        }

        # Stage 1: Reconnaissance
        yield f"data: {json.dumps({'stage': 'recon', 'status': 'active', 'message': 'Resolving DNS & probing HTTP headers...', 'progress': 15})}\n\n"
        try:
            recon = run_recon(target)
            pipeline_result["stages"]["recon"] = {"status": "done", "data": recon}
            detected_tech = recon.get("detected_technologies", [])
            tech_names = [t.get("name") for t in detected_tech]
            msg = f"Recon complete: {len(detected_tech)} technologies found" + (f" ({', '.join(tech_names[:3])})" if tech_names else "")
            yield f"data: {json.dumps({'stage': 'recon', 'status': 'done', 'data': recon, 'message': msg, 'progress': 30})}\n\n"
        except Exception as e:
            pipeline_result["stages"]["recon"] = {"status": "error", "error": str(e)}
            yield f"data: {json.dumps({'stage': 'recon', 'status': 'error', 'error': str(e), 'progress': 30})}\n\n"
            detected_tech = []
            recon = {}

        # Stage 2: Vulnerability Assessment
        yield f"data: {json.dumps({'stage': 'vulnerability', 'status': 'active', 'message': f'Querying NVD CVEs across {len(detected_tech)} software components...', 'progress': 45})}\n\n"
        try:
            if detected_tech:
                vuln = run_vuln_assessment(detected_tech)
            else:
                vuln = {"total_cves": 0, "cves": [], "tech_summary": {}, "errors": ["No technologies detected to assess"]}
            pipeline_result["stages"]["vulnerability"] = {"status": "done", "data": vuln}
            cve_count = vuln.get("total_cves", 0)
            yield f"data: {json.dumps({'stage': 'vulnerability', 'status': 'done', 'data': vuln, 'message': f'Vulnerability analysis complete: {cve_count} CVEs evaluated', 'progress': 65})}\n\n"
        except Exception as e:
            pipeline_result["stages"]["vulnerability"] = {"status": "error", "error": str(e)}
            vuln = {"cves": [], "total_cves": 0, "tech_summary": {}, "errors": [str(e)]}
            yield f"data: {json.dumps({'stage': 'vulnerability', 'status': 'error', 'error': str(e), 'progress': 65})}\n\n"

        # Stage 3: BRON Threat Graph Mapping
        total_cves_count = vuln.get("total_cves", 0)
        yield f"data: {json.dumps({'stage': 'bron', 'status': 'active', 'message': f'Traversing MITRE ATT&CK & BRON threat graph for {total_cves_count} CVEs...', 'progress': 75})}\n\n"
        try:
            bron = run_bron_mapping(vuln.get("cves", []))
            pipeline_result["stages"]["bron"] = {"status": "done", "data": bron}
            if bron.get("bron_online") and bron.get("chains"):
                chain_map = {c["cve_id"]: c for c in bron.get("chains", [])}
                for cve in vuln.get("cves", []):
                    chain = chain_map.get(cve["cve_id"])
                    if chain:
                        if chain.get("cause"): cve["cause"] = chain["cause"]
                        if chain.get("attacker_action"): cve["attacker_action"] = chain["attacker_action"]
                        if chain.get("solution"): cve["solution"] = chain["solution"]
            chain_count = bron.get("total_chains", len(bron.get("chains", [])))
            yield f"data: {json.dumps({'stage': 'bron', 'status': 'done', 'data': bron, 'message': f'Threat graph mapped: {chain_count} attack chains linked', 'progress': 85})}\n\n"
        except Exception as e:
            pipeline_result["stages"]["bron"] = {"status": "error", "error": str(e)}
            bron = {"chains": [], "unique_attack_techniques": [], "total_chains": 0}
            yield f"data: {json.dumps({'stage': 'bron', 'status': 'error', 'error': str(e), 'progress': 85})}\n\n"

        # Stage 4: Compliance Mapping
        yield f"data: {json.dumps({'stage': 'compliance', 'status': 'active', 'message': 'Evaluating NIST 800-53, CIS, and OWASP Top 10 controls...', 'progress': 90})}\n\n"
        try:
            compliance = run_compliance_mapping(bron, recon)
            pipeline_result["stages"]["compliance"] = {"status": "done", "data": compliance}
            yield f"data: {json.dumps({'stage': 'compliance', 'status': 'done', 'data': compliance, 'message': 'Compliance scoring complete', 'progress': 98})}\n\n"
        except Exception as e:
            pipeline_result["stages"]["compliance"] = {"status": "error", "error": str(e)}
            yield f"data: {json.dumps({'stage': 'compliance', 'status': 'error', 'error': str(e), 'progress': 98})}\n\n"

        pipeline_result["completed_at"] = datetime.utcnow().isoformat()
        pipeline_result["status"] = "complete"

        # Final complete event
        yield f"data: {json.dumps({'stage': 'complete', 'status': 'complete', 'pipeline': pipeline_result, 'progress': 100, 'message': 'All stages completed successfully'})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("Starting backend on http://localhost:5050")
    app.run(host="0.0.0.0", port=5050, debug=True)
