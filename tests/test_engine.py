import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from phishing_engine import fuse, analyze_email

def comp(status,score=None): return {"status":status,"score":score,"evidence":[],"details":{}}

def test_fusion_renormalizes_only_available_components():
    parts={"a":comp("available",.8),"b":comp("not_applicable"),"c":comp("unavailable")}
    result=fuse(parts,{"a":.2,"b":.3,"c":.5})
    assert result["score"]==.8 and result["effective_weights"]=={"a":1.0}

def test_failed_and_missing_features_do_not_add_zero_scores():
    parts={"a":comp("available",.6),"b":comp("error"),"c":comp("unavailable")}
    assert fuse(parts,{"a":.25,"b":.25,"c":.5})["score"]==.6

def test_no_eligible_weight_returns_insufficient_evidence():
    parts={"a":comp("available",1.0),"b":comp("not_applicable")}
    assert fuse(parts,{"a":0.0,"b":1.0})["classification"]=="insufficient_evidence"

def test_email_without_urls_still_uses_other_components():
    result=analyze_email("From: Alice <alice@gmail.com>\nSubject: Hello\nDate: Tue, 01 Jan 2024 10:00:00 +0000\nMessage-ID: <x@example.com>\n\nPlease see the attached report.")
    assert result["components"]["url_analysis"]["status"]=="not_applicable"
    assert result["components"]["website_analysis"]["status"]=="not_applicable"
    assert result["score"] is None or result["eligible_components"]

