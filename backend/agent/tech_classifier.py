import os
import sys
import json
import random
import hashlib
from typing import Dict, Any, List, Tuple, Optional
import joblib
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.multioutput import MultiOutputClassifier
import lightgbm as lgb

MODEL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tech_model.joblib")

# Global in-memory model cache for sub-millisecond inference latency
_CACHED_PIPELINE: Optional[Dict[str, Any]] = None

def get_tech_signatures() -> Dict[str, Dict[str, Any]]:
    """Import TECH_SIGNATURES from recon.py to ensure single source of truth."""
    try:
        from agent.recon import TECH_SIGNATURES
        return TECH_SIGNATURES
    except ImportError:
        # Fallback if imported from a different path
        recon_path = os.path.join(os.path.dirname(__file__), "recon.py")
        import importlib.util
        spec = importlib.util.spec_from_file_location("recon_module", recon_path)
        recon_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recon_mod)
        return recon_mod.TECH_SIGNATURES

def extract_vectorizer_features(feature_blob: Dict[str, Any]) -> Dict[str, float]:
    """
    Vectorize the multi-signal feature blob into a flat dictionary of numeric features:
    - Headers presence and key-value tokens
    - Cookie names and security flags (httponly, secure, samesite)
    - Favicon mmh3 hash bucketed/one-hot
    - TLS certificate metadata (issuer CN, SAN count)
    - Error page DOM tag structure hash & tag count
    - HTML pattern matches & hashed n-grams
    """
    vec_feats: Dict[str, float] = {}

    # 1. HTTP Headers
    headers = feature_blob.get("headers", {})
    if isinstance(headers, dict):
        for k, v in headers.items():
            k_lower = k.lower()
            v_lower = str(v).lower()
            vec_feats[f"hdr_present:{k_lower}"] = 1.0
            # Common identifying headers
            if k_lower in ("server", "x-powered-by", "x-generator", "via"):
                for token in v_lower.replace("/", " ").replace("-", " ").split():
                    if len(token) > 2:
                        vec_feats[f"hdr_tok:{k_lower}:{token}"] = 1.0

    # 2. Cookies
    cookies = feature_blob.get("cookies", [])
    if isinstance(cookies, list):
        for c in cookies:
            if isinstance(c, dict):
                c_name = c.get("name", "").lower()
                if c_name:
                    vec_feats[f"cookie_name:{c_name}"] = 1.0
                    # Cookie prefix n-grams (e.g. wp-, sess, phpsessid)
                    for prefix in ("wp", "php", "csrf", "sess", "connect", "drupal"):
                        if prefix in c_name:
                            vec_feats[f"cookie_prefix:{prefix}"] = 1.0
                    if c.get("httponly"):
                        vec_feats["cookie_attr:httponly"] = 1.0
                    if c.get("secure"):
                        vec_feats["cookie_attr:secure"] = 1.0
                    if c.get("samesite"):
                        vec_feats[f"cookie_attr:samesite_{str(c.get('samesite')).lower()}"] = 1.0
            elif isinstance(c, str):
                vec_feats[f"cookie_name:{c.lower()}"] = 1.0

    # 3. Favicon mmh3 Hash
    fav_hash = feature_blob.get("favicon_hash")
    if fav_hash is not None and fav_hash != 0:
        vec_feats["has_favicon"] = 1.0
        vec_feats[f"fav_hash:{fav_hash}"] = 1.0
        # Hashed bucket for unseen favicons
        bucket = abs(int(fav_hash)) % 100
        vec_feats[f"fav_bucket:{bucket}"] = 1.0
    else:
        vec_feats["has_favicon"] = 0.0

    # 4. TLS Certificate Metadata
    tls = feature_blob.get("tls_cert", {})
    if isinstance(tls, dict):
        has_ssl = 1.0 if tls.get("has_ssl") else 0.0
        vec_feats["tls_has_ssl"] = has_ssl
        issuer = str(tls.get("issuer_cn", "")).lower()
        if issuer:
            vec_feats[f"tls_issuer:{issuer}"] = 1.0
            for kw in ("let's encrypt", "cloudflare", "digicert", "cpanel", "amazon", "sectigo"):
                if kw in issuer:
                    vec_feats[f"tls_issuer_kw:{kw}"] = 1.0
        san_entries = tls.get("san_entries", [])
        vec_feats["tls_san_count"] = float(len(san_entries))
    else:
        vec_feats["tls_has_ssl"] = 0.0
        vec_feats["tls_san_count"] = 0.0

    # 5. Error Page DOM Tag Structure
    error_dom = feature_blob.get("error_dom", {})
    if isinstance(error_dom, dict):
        dom_hash = error_dom.get("dom_hash", "")
        if dom_hash:
            vec_feats[f"dom_hash:{dom_hash}"] = 1.0
        tag_count = error_dom.get("tag_count", 0)
        vec_feats["dom_tag_count"] = float(tag_count)
        for tag in error_dom.get("common_tags", []):
            vec_feats[f"dom_tag:{tag.lower()}"] = 1.0

    # 6. HTML Content patterns
    html_snippets = feature_blob.get("html_patterns_found", [])
    if isinstance(html_snippets, list):
        for pat in html_snippets:
            vec_feats[f"html_pattern:{pat.lower()}"] = 1.0

    html_content = feature_blob.get("html_content", "")
    if html_content:
        html_lower = html_content.lower()
        # Check characteristic tokens across known stacks
        tech_sigs = get_tech_signatures()
        for tech, sigs in tech_sigs.items():
            for pat in sigs.get("html_patterns", []):
                if pat.lower() in html_lower:
                    vec_feats[f"html_match:{tech}:{pat.lower()}"] = 1.0

    return vec_feats

def generate_seed_dataset(tech_sigs: Dict[str, Dict[str, Any]], num_samples: int = 400) -> Tuple[List[Dict[str, float]], np.ndarray, List[str]]:
    """
    Generate synthetic and pattern-derived training examples seeded from TECH_SIGNATURES.
    Creates positive, co-occurring (e.g. Apache+PHP+WordPress), obfuscated, and negative/generic samples.
    """
    tech_names = sorted(list(tech_sigs.keys()))
    X_samples: List[Dict[str, float]] = []
    Y_labels: List[List[int]] = []

    # Known domain characteristic profiles for synthetic training data
    known_profiles = {
        "WordPress": {
            "cookies": [{"name": "wordpress_logged_in_xyz", "httponly": True}, {"name": "wp-settings-1"}],
            "html": "<html><head><link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css'><script src='/wp-includes/js/jquery/jquery.min.js'></script></head><body><h1>Blog</h1></body></html>",
            "fav_hash": 1089201940, # Known WordPress Shodan favicon hash
            "error_dom": {"dom_hash": "wp_404_struct", "tag_count": 28, "common_tags": ["html", "head", "body", "div", "h1", "p"]}
        },
        "PHP": {
            "headers": {"x-powered-by": "PHP/8.1.12"},
            "cookies": [{"name": "PHPSESSID", "httponly": True}],
            "error_dom": {"dom_hash": "php_standard_err", "tag_count": 14, "common_tags": ["html", "body", "font", "table"]}
        },
        "Apache": {
            "headers": {"server": "Apache/2.4.52 (Ubuntu)"},
            "error_dom": {"dom_hash": "apache_404_struct", "tag_count": 18, "common_tags": ["html", "head", "title", "body", "h1", "p", "hr", "address"]}
        },
        "Nginx": {
            "headers": {"server": "nginx/1.22.0"},
            "error_dom": {"dom_hash": "nginx_404_struct", "tag_count": 12, "common_tags": ["html", "head", "title", "body", "center", "h1", "hr"]}
        },
        "IIS": {
            "headers": {"server": "Microsoft-IIS/10.0", "x-aspnet-version": "4.0.30319"},
            "cookies": [{"name": "ASP.NET_SessionId", "httponly": True}],
            "error_dom": {"dom_hash": "iis_detailed_err", "tag_count": 35, "common_tags": ["html", "body", "div", "fieldset", "h2", "h3"]}
        },
        "Drupal": {
            "headers": {"x-generator": "Drupal 10 (https://www.drupal.org)"},
            "cookies": [{"name": "SESS48a9f2", "httponly": True, "secure": True}],
            "html": "<head><script src='/core/assets/vendor/jquery/jquery.min.js'></script></head>",
            "fav_hash": -1445724597
        },
        "Django": {
            "cookies": [{"name": "csrftoken", "samesite": "Lax"}, {"name": "sessionid", "httponly": True}],
            "html": "<form><input type='hidden' name='csrfmiddlewaretoken' value='random_token_123'></form>",
            "error_dom": {"dom_hash": "django_debug_404", "tag_count": 42, "common_tags": ["html", "head", "body", "div", "h1", "table", "tr", "td"]}
        },
        "Express": {
            "headers": {"x-powered-by": "Express"},
            "cookies": [{"name": "connect.sid", "httponly": True}],
            "error_dom": {"dom_hash": "express_cannot_get", "tag_count": 8, "common_tags": ["html", "body", "pre"]}
        },
        "jQuery": {
            "html": "<script src='https://code.jquery.com/jquery-3.6.0.min.js'></script><script>$(document).ready(function(){});</script>"
        },
        "Bootstrap": {
            "html": "<link rel='stylesheet' href='/css/bootstrap.min.css'><div class='container'><button class='btn btn-primary'>Click</button></div>"
        },
        "OpenSSL": {
            "headers": {"server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"}
        }
    }

    # Generate diverse samples
    for _ in range(num_samples):
        sample_blob: Dict[str, Any] = {
            "headers": {},
            "cookies": [],
            "favicon_hash": None,
            "tls_cert": {"has_ssl": random.choice([True, False]), "issuer_cn": random.choice(["Let's Encrypt", "Cloudflare", "DigiCert", "Self-Signed"]), "san_entries": ["example.com"]},
            "error_dom": {},
            "html_content": ""
        }
        
        # Decide which techs are active in this sample (multi-label)
        active_techs = set()
        
        # 15% completely negative/generic clean site
        if random.random() > 0.15:
            # Pick 1 to 4 technologies that realistically co-exist
            primary = random.choice(tech_names)
            active_techs.add(primary)
            
            # Common stacks
            if primary == "WordPress":
                active_techs.add("PHP")
                if random.random() > 0.3: active_techs.add(random.choice(["Apache", "Nginx"]))
                if random.random() > 0.2: active_techs.add("jQuery")
            elif primary == "Drupal":
                active_techs.add("PHP")
                if random.random() > 0.3: active_techs.add("Apache")
            elif primary == "Django":
                if random.random() > 0.3: active_techs.add("Nginx")
                if random.random() > 0.4: active_techs.add("Bootstrap")
            elif primary == "PHP":
                if random.random() > 0.3: active_techs.add(random.choice(["Apache", "Nginx", "IIS"]))
            elif primary == "Apache" and random.random() > 0.5:
                active_techs.add("OpenSSL")

        # Synthesize the feature blob for active technologies
        for tech in active_techs:
            prof = known_profiles.get(tech, {})
            # Add headers (sometimes slightly obfuscated or version-stripped)
            for k, v in prof.get("headers", {}).items():
                if random.random() > 0.1: # 90% chance header is present
                    # 20% chance version is stripped (e.g. "nginx" instead of "nginx/1.22.0")
                    if random.random() < 0.2 and "/" in v:
                        v = v.split("/")[0]
                    sample_blob["headers"][k] = v
            
            # Add cookies
            for c in prof.get("cookies", []):
                if random.random() > 0.15:
                    sample_blob["cookies"].append(c)

            # Add HTML patterns
            if "html" in prof and random.random() > 0.1:
                sample_blob["html_content"] += "\n" + prof["html"]

            # Add favicon hash
            if "fav_hash" in prof and random.random() > 0.2:
                sample_blob["favicon_hash"] = prof["fav_hash"]

            # Add error DOM fingerprint
            if "error_dom" in prof and random.random() > 0.25:
                sample_blob["error_dom"] = prof["error_dom"]

        # Also add random benign noise headers & cookies
        if random.random() > 0.5:
            sample_blob["headers"]["content-type"] = "text/html; charset=UTF-8"
        if random.random() > 0.5:
            sample_blob["headers"]["cache-control"] = "max-age=3600"
        if random.random() > 0.7:
            sample_blob["cookies"].append({"name": f"_ga_{random.randint(100, 999)}", "httponly": False})

        # Vectorize feature blob
        feats = extract_vectorizer_features(sample_blob)
        X_samples.append(feats)

        # Multi-label binary vector for this sample
        y_vec = [1 if t in active_techs else 0 for t in tech_names]
        Y_labels.append(y_vec)

    return X_samples, np.array(Y_labels), tech_names

def train_model() -> Dict[str, Any]:
    """
    Train the multi-label LightGBM classifier on the TECH_SIGNATURES seed dataset
    and serialize the vectorizer + model to disk.
    """
    print("[+] Loading tech signatures and generating training seed...")
    tech_sigs = get_tech_signatures()
    X_dict, Y, tech_names = generate_seed_dataset(tech_sigs, num_samples=600)

    print(f"[+] Vectorizing {len(X_dict)} training samples across {len(tech_names)} technology classes...")
    vectorizer = DictVectorizer(sparse=True)
    X = vectorizer.fit_transform(X_dict)

    print("[+] Training MultiOutput LightGBM Classifier...")
    base_lgb = lgb.LGBMClassifier(
        n_estimators=40,
        max_depth=5,
        learning_rate=0.1,
        random_state=42,
        verbose=-1,
        n_jobs=1
    )
    clf = MultiOutputClassifier(base_lgb)
    clf.fit(X, Y)

    pipeline_data = {
        "vectorizer": vectorizer,
        "model": clf,
        "tech_names": tech_names,
        "cpe_map": {t: tech_sigs[t]["cpe_keyword"] for t in tech_names if "cpe_keyword" in tech_sigs[t]}
    }

    joblib.dump(pipeline_data, MODEL_FILE)
    print(f"[+] Model successfully trained and saved to {MODEL_FILE}")

    global _CACHED_PIPELINE
    _CACHED_PIPELINE = pipeline_data
    return pipeline_data

def get_classifier_pipeline() -> Dict[str, Any]:
    """Retrieve or load cached model pipeline."""
    global _CACHED_PIPELINE
    if _CACHED_PIPELINE is not None:
        return _CACHED_PIPELINE

    if os.path.exists(MODEL_FILE):
        try:
            _CACHED_PIPELINE = joblib.load(MODEL_FILE)
            return _CACHED_PIPELINE
        except Exception as e:
            print(f"[!] Error loading {MODEL_FILE}: {e}, retraining...")

    return train_model()

def predict_technologies(feature_blob: Dict[str, Any], threshold: float = 0.7) -> Dict[str, Any]:
    """
    Fast online inference (<200ms) for technology classification.
    Returns:
      {
        "detected": [{"name": str, "confidence": float, "cpe_keyword": str}, ...],
        "probabilities": {tech_name: float, ...},
        "max_confidence": float
      }
    """
    pipeline = get_classifier_pipeline()
    vectorizer: DictVectorizer = pipeline["vectorizer"]
    clf: MultiOutputClassifier = pipeline["model"]
    tech_names: List[str] = pipeline["tech_names"]
    cpe_map: Dict[str, str] = pipeline["cpe_map"]

    # 1. Vectorize the target's feature blob
    feat_dict = extract_vectorizer_features(feature_blob)
    X = vectorizer.transform([feat_dict])

    # 2. Predict probabilities across all classes
    # predict_proba returns a list of arrays (one per class), shape (1, 2)
    proba_list = clf.predict_proba(X)
    
    probabilities: Dict[str, float] = {}
    detected: List[Dict[str, Any]] = []
    max_conf = 0.0

    for i, tech in enumerate(tech_names):
        # prob of class 1 (technology present)
        prob = float(proba_list[i][0][1])
        probabilities[tech] = round(prob, 4)
        if prob > max_conf:
            max_conf = prob
        if prob >= threshold:
            detected.append({
                "name": tech,
                "confidence": round(prob, 4),
                "cpe_keyword": cpe_map.get(tech, f"{tech.lower()} {tech.lower()}")
            })

    # Sort detected by confidence descending
    detected.sort(key=lambda x: x["confidence"], reverse=True)

    return {
        "detected": detected,
        "probabilities": probabilities,
        "max_confidence": round(max_conf, 4)
    }

if __name__ == "__main__":
    if "--train" in sys.argv or len(sys.argv) == 1:
        train_model()
        print("[+] Test inference run:")
        sample = {
            "headers": {"server": "Apache", "x-powered-by": "PHP/8.0"},
            "cookies": [{"name": "PHPSESSID"}],
            "html_content": "<link rel='stylesheet' href='/wp-content/themes/theme/style.css'>"
        }
        res = predict_technologies(sample, threshold=0.7)
        print(json.dumps(res, indent=2))
