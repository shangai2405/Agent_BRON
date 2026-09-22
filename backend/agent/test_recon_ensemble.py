import time
import json
import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.recon import run_recon, TECH_SIGNATURES
from agent.tech_classifier import predict_technologies, get_classifier_pipeline
from agent.db import get_connection, get_novel_candidates

def test_inference_latency():
    print("[1] Testing Classifier Inference Latency...")
    # Warm up
    get_classifier_pipeline()
    
    sample_blob = {
        "headers": {"server": "Apache/2.4.52", "x-powered-by": "PHP/8.1"},
        "cookies": [{"name": "PHPSESSID", "httponly": True}],
        "favicon_hash": 1089201940,
        "tls_cert": {"has_ssl": True, "issuer_cn": "Let's Encrypt", "san_entries": ["example.com"]},
        "error_dom": {"dom_hash": "abc12345", "tag_count": 15, "common_tags": ["html", "head", "body"]},
        "html_content": "<link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css'>"
    }

    start = time.perf_counter()
    res = predict_technologies(sample_blob, threshold=0.7)
    elapsed_ms = (time.perf_counter() - start) * 1000

    print(f"    Inference time: {elapsed_ms:.2f} ms (Constraint: < 200 ms)")
    assert elapsed_ms < 200, f"Inference took {elapsed_ms}ms which exceeds 200ms!"
    print("    Detected:", [d["name"] for d in res["detected"]])
    print("    PASSED!")

def test_recon_contract():
    print("\n[2] Testing run_recon Output Contract...")
    # Test against example.com or httpbin
    target = "https://example.com"
    start = time.perf_counter()
    recon_result = run_recon(target)
    total_time_ms = (time.perf_counter() - start) * 1000

    print(f"    Recon run completed in {total_time_ms:.2f} ms")
    assert "target_url" in recon_result
    assert "ip_addresses" in recon_result
    assert "headers" in recon_result
    assert "security_headers" in recon_result
    assert "detected_technologies" in recon_result
    assert "errors" in recon_result

    print(f"    Target: {recon_result['target_url']}")
    print(f"    IPs: {recon_result['ip_addresses']}")
    print(f"    Detected technologies: {recon_result['detected_technologies']}")

    for item in recon_result["detected_technologies"]:
        assert "name" in item, "Missing 'name' in detected technology item"
        assert "version" in item, "Missing 'version' in detected technology item"
        assert "cpe_keyword" in item, "Missing 'cpe_keyword' in detected technology item"

    print("    PASSED!")

def test_sqlite_persistence():
    print("\n[3] Testing SQLite Persistence (scan_features & novel_candidates)...")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_features")
        count_features = cursor.fetchone()[0]
        print(f"    Total scan_features entries: {count_features}")
        assert count_features > 0, "No scan features recorded in DB!"

        cursor.execute("SELECT COUNT(*) FROM novel_candidates")
        count_novel = cursor.fetchone()[0]
        print(f"    Total novel_candidates entries: {count_novel}")

    novel = get_novel_candidates(limit=5)
    print(f"    Retrieved {len(novel)} novel candidate records.")
    print("    PASSED!")

if __name__ == "__main__":
    test_inference_latency()
    test_recon_contract()
    test_sqlite_persistence()
    print("\n===============================")
    print("ALL RECON ENSEMBLE TESTS PASSED")
    print("===============================")
