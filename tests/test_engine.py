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
    assert fuse(parts,{"a":0.0,"b":1.0})["classification"]=="human_review"

def test_sparse_signal_coverage_does_not_escalate_a_lone_component():
    parts={"temporary_email":comp("available",.8),"other":comp("not_applicable")}
    result=fuse(parts,{"temporary_email":.10,"other":.90},minimum_evidence_coverage=.30)
    assert result["score"] == .8
    assert result["classification"] == "human_review"

def test_email_without_urls_still_uses_other_components():
    result=analyze_email("From: Alice <alice@gmail.com>\nSubject: Hello\nDate: Tue, 01 Jan 2024 10:00:00 +0000\nMessage-ID: <x@example.com>\n\nPlease see the attached report.")
    assert result["components"]["url_analysis"]["status"]=="not_applicable"
    assert result["components"]["website_analysis"]["status"]=="not_applicable"
    assert result["score"] is None or result["eligible_components"]

def test_html_anchor_destination_mismatch_is_scored():
    phase4 = ROOT / "phase 4" / "src"
    sys.path.insert(0, str(phase4))
    from url_analysis import analyze_email_urls
    result = analyze_email_urls("", "", '<a href="https://evil-example.test/login">https://paypal.com</a>')
    item = result["individual_url_scores"][0]
    assert item["anchor_mismatch"]["visible_domain"] == "paypal.com"
    assert item["component_scores"]["D"]["score"] >= 0.85

def test_default_fusion_weights_include_attachment_signal_and_sum_to_one():
    from phishing_engine import DEFAULTS
    assert set(DEFAULTS["weights"]) == {
        "word_pool", "sender_header", "temporary_email", "url_analysis",
        "website_analysis", "attachment_analysis",
    }
    assert sum(DEFAULTS["weights"].values()) == 1.0
    assert DEFAULTS["website_retrieval"]["enabled"] is True   # linked pages are always fetched
    assert DEFAULTS["weights"] == {
        "word_pool": .25, "sender_header": .15, "temporary_email": .10,
        "url_analysis": .20, "website_analysis": .20,
        "attachment_analysis": .10,
    }

def test_attachment_extension_order_and_max_aggregation():
    def email(filename, extra_images=0):
        parts = [f'Content-Type: application/octet-stream\nContent-Disposition: attachment; filename="{filename}"\n\nabc']
        parts.extend(f'Content-Type: image/png\nContent-Disposition: attachment; filename="image{i}.png"\n\nabc' for i in range(extra_images))
        return "From: user@gmail.com\nSubject: Report\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n--x\n" + "\n--x\n".join(parts) + "\n--x--\n"
    bad_order = analyze_email(email("invoice.pdf.exe", 5))
    safe_order = analyze_email(email("report.exe.pdf"))
    assert bad_order["components"]["attachment_analysis"]["score"] == 1.0
    assert safe_order["components"]["attachment_analysis"]["score"] == .65

def test_html_attachment_is_scored_and_inline_images_are_ignored():
    raw = ('From: user@gmail.com\nSubject: X\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n'
           '--x\nContent-Type: text/plain\n\nHello\n'
           '--x\nContent-Type: image/png\nContent-Disposition: inline; filename="logo.png"\n\nabc\n'
           '--x\nContent-Type: text/html\nContent-Disposition: attachment; filename="invoice.html"\n\nabc\n--x--\n')
    result = analyze_email(raw)
    component = result["components"]["attachment_analysis"]
    assert component["score"] == .65
    assert len(component["details"]["attachments"]) == 2

def test_url_analysis_handles_urls_and_avoids_broad_brand_token_matches():
    phase4 = ROOT / "phase 4" / "src"
    sys.path.insert(0, str(phase4))
    from url_analysis import analyze_email_urls
    result = analyze_email_urls("", "Visit https://apple-orchard-farm.com and https://paypal.me.")
    assert result["url_count"] == 2
    assert not result["domain_similarity_findings"]

def test_link_override_is_bounded_and_accepts_general_verify_language():
    raw = ('From: user@gmail.com\nSubject: Verify account\nMIME-Version: 1.0\nContent-Type: text/html\n\n'
           '<a href="https://evil.example/login">https://paypal.com</a> Please verify your account.')
    result = analyze_email(raw, word_pool_model=_DummyModel())
    assert result["strong_signal_override"]["applied"] is True
    assert result["score_adjustments"]["link_mismatch_with_credential_request"] == .15

def test_website_retrieval_toggle_never_calls_fetcher_when_disabled():
    called = []
    def fetcher(*args, **kwargs):
        called.append(args[0])
        raise AssertionError("fetcher must remain unused")
    raw = "From: user@gmail.com\nSubject: Hello\n\nVisit https://example.org"
    result = analyze_email(raw, word_pool_model=_DummyModel(), website_retriever=fetcher,
                           website_retrieval_enabled=False)
    assert not called
    web = result["components"]["website_analysis"]
    assert web["status"] == "available"            # offline domain/brand signals only
    assert web["details"]["fetched_count"] == 0 and web["details"]["retrieval_enabled"] is False
    assert web["details"]["websites"][0]["analysis"]["signals"]["language"] is None

def test_verdict_category_boundaries_match_spec():
    from phishing_engine import classify, DEFAULTS
    lim = DEFAULTS["thresholds"]
    assert lim == {"suspicious": .30, "phishy": .60}
    assert classify(0.0, 1, .3, lim) == "safe" and classify(.2999, 1, .3, lim) == "safe"
    assert classify(.30, 1, .3, lim) == "suspicious" and classify(.5999, 1, .3, lim) == "suspicious"
    assert classify(.60, 1, .3, lim) == "phishy" and classify(1.0, 1, .3, lim) == "phishy"
    assert classify(.9, .1, .3, lim) == "human_review" and classify(None, 0, .3, lim) == "human_review"

def test_intent_consistency_flags_bank_sender_with_car_website():
    sys.path.insert(0, str(ROOT / "phase 6"))
    from consistency_analysis import analyze_consistency
    r = analyze_consistency({"from_display": "HDFC Bank", "from_address": "alerts@hdfcbank.com",
                             "subject": "Your bank statement", "body": "account statement",
                             "urls": ["http://cheapcarsdealer.com/sedan"],
                             "websites": [{"url": "http://cheapcarsdealer.com", "title": "Used Cars Dealership", "text": "buy a sedan"}]})
    assert r["score"] >= .5 and any(f["type"] == "intent_mismatch" for f in r["findings"])
    ok = analyze_consistency({"from_display": "PayPal", "from_address": "service@paypal.com", "subject": "Payment receipt",
                              "body": "Your payment", "urls": ["https://www.paypal.com/activity"]})
    assert ok["score"] == 0.0

def test_thread_analysis_detects_fake_reply_and_domain_change():
    sys.path.insert(0, str(ROOT / "phase 6"))
    from consistency_analysis import analyze_thread
    fake = analyze_thread("From: a@x.com\nSubject: Re: invoice\n\nhi")
    assert any(f["type"] == "fake_reply_subject" for f in fake["findings"])
    first = "From: Ann <ann@acme.com>\nSubject: Q3 invoice\nMessage-ID: <1@acme.com>\n\nlunch"
    later = "From: Ann <ann@acme-corp.com>\nSubject: Re: Q3 invoice\nIn-Reply-To: <1@acme.com>\nMessage-ID: <2@x.com>\n\npay"
    r = analyze_thread(later, [first])
    kinds = {f["type"] for f in r["findings"]}
    assert r["linked_emails"] == 1 and "lookalike_sender_in_thread" in kinds
    assert analyze_thread("From: a@x.com\nSubject: hello\n\nhi")["status"] == "not_applicable"

def test_reply_to_disposable_domain_is_checked():
    raw = "From: Bob <bob@company-example.com>\nReply-To: bob@mailinator.com\nSubject: Hello\n\nhello"
    r = analyze_email(raw, word_pool_model=_DummyModel())
    assert r["components"]["temporary_email"]["details"]["worst_address"] == "reply_to"
    assert r["components"]["temporary_email"]["score"] > .4

def test_header_mismatch_flag_is_binary():
    raw = "From: a@company-example.com\nReply-To: b@other-example.org\nSubject: Hi\n\nhi"
    d = analyze_email(raw, word_pool_model=_DummyModel())["components"]["sender_header"]["details"]
    assert d["component_scores"]["Mismatch"] == 1.0

def test_word_pool_pipeline_reports_stop_words_lemmas_and_pattern_ratio():
    sys.path.insert(0, str(ROOT / "phase 1" / "src"))
    from word_pool.preprocessing import lexical_pipeline
    p = lexical_pipeline("The accounts were SUSPENDED!!! Verify the accounts, now.")
    assert "the" not in p["tokens_without_stop_words"] and "account" in p["lemmas"]
    from phishing_engine import WordPoolModel, WORD_POOL_MODEL_SHA256
    m = WordPoolModel.load(ROOT / "phase 1" / "models" / "word_pool" / "model.joblib", expected_sha256=WORD_POOL_MODEL_SHA256)
    out = m.analyze("Urgent", "Please verify your account immediately or it will be suspended")
    assert 0 <= out["pattern_ratio_F"] <= 1 and out["preprocessing"]["stop_words_removed"] >= 0

def test_rdap_age_and_logo_signals():
    sys.path.insert(0, str(ROOT / "phase 5" / "src"))
    from website_analysis.intelligence import rdap_registration, visual_brand_signals
    doc = '{"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}'
    reg = rdap_registration("example.com", opener=lambda url, t: doc)
    assert reg["registration_age_days"] > 365 and reg["registration"]["source"] == "rdap.org"
    html = '<html><head><title>Sign in</title></head><body><img src="/img/paypal-logo.png" alt="PayPal"></body></html>'
    v = visual_brand_signals(html, "https://secure-pay.example.net/login", [{"name": "PayPal", "domains": ["paypal.com"]}])
    assert v["score"] >= .85
    assert visual_brand_signals(html, "https://www.paypal.com/", [{"name": "PayPal", "domains": ["paypal.com"]}])["score"] == 0.0

def test_website_signals_use_injected_providers_when_enabled():
    page = "<html><title>PayPal Login</title><body><img alt='PayPal logo'><form action='http://evil.example/x'><input type='password' name='p'></form>Verify your account immediately</body></html>"
    def fetcher(url, config=None):
        return {"status": "available", "fetched": True, "html": page, "final_url": url, "original_url": url}
    raw = "From: user@gmail.com\nSubject: Hello\n\nVisit http://secure-login.example.net/x"
    r = analyze_email(raw, word_pool_model=_DummyModel(), website_retriever=fetcher, website_retrieval_enabled=True,
                      registration_provider=lambda d: {"registration_age_days": 3, "registration": {"source": "test", "observed_at": "2026-01-01T00:00:00Z"}})
    sig = r["components"]["website_analysis"]["details"]["websites"][0]["analysis"]["signals"]
    assert all(sig[k] is not None for k in ("domain", "brand", "language", "credentials")) and sig["credentials"] > .5

def test_dataset_input_and_threading(tmp_path):
    from phishing_engine import analyze_dataset
    (tmp_path / "a.eml").write_text("From: Ann <ann@acme.com>\nSubject: Q3 invoice\nMessage-ID: <1@acme.com>\n\nlunch")
    (tmp_path / "b.eml").write_text("From: Ann <ann@acme-corp.com>\nSubject: Re: Q3 invoice\nIn-Reply-To: <1@acme.com>\n\nverify your account")
    out = analyze_dataset(tmp_path, word_pool_model=_DummyModel())
    assert out["total"] == 2 and out["thread_count"] == 1 and out["results"][1]["thread_size"] == 2
    csvf = tmp_path / "d.csv"; csvf.write_text("from,subject,body\nx@gmail.com,hi,lunch\n")
    assert analyze_dataset(csvf, word_pool_model=_DummyModel())["total"] == 1

class _DummyModel:
    def analyze(self, subject, body):
        return {"S_WP": 0.0, "detected_ngrams": [], "detected_collocations": [], "cta_matches": [], "warnings": []}



# ---- Human Review gate and example regression --------------------------------------------
def test_human_review_gate_conditions():
    from phishing_engine import classify, human_review_reasons, DEFAULTS
    lim = DEFAULTS["thresholds"]
    ok = dict(eligible_count=5, minimum_components=4, consistency_status="available")
    assert classify(.9, .9, .6, lim, **ok) == "phishy"
    assert classify(.9, .59, .6, lim, **ok) == "human_review"                       # coverage < 0.6
    assert classify(.9, .9, .6, lim, **{**ok, "eligible_count": 3}) == "human_review"  # fewer than 4 components
    assert classify(.9, .9, .6, lim, **{**ok, "consistency_status": "insufficient_evidence"}) == "human_review"
    assert human_review_reasons(.9, 5, "available") == []
    assert len(human_review_reasons(.5, 3, "insufficient_evidence")) == 3

def test_default_gate_is_sixty_percent_and_four_components():
    from phishing_engine import DEFAULTS
    assert DEFAULTS["minimum_evidence_coverage"] == .60 and DEFAULTS["minimum_eligible_components"] == 4

def test_email_without_urls_goes_to_human_review():
    raw = ("From: notifications@company-internal.net\nSubject: Q3 expense report please review\n\n"
           "Hi team, please find the latest expense summary attached for your review.")
    result = analyze_email(raw)
    assert result["classification"] == "human_review" and result["verdict"] == "Human Review"
    assert result["human_review_reasons"]

EXAMPLES = ROOT / "tests" / "examples"
EXPECTED = {  # example -> verdicts the project design accepts
    1: {"Phishy"}, 2: {"Phishy"}, 3: {"Phishy"}, 4: {"Safe"},
    5: {"Safe", "Suspicious"}, 6: {"Phishy"}, 7: {"Phishy"},
}

def test_design_examples_reach_expected_verdicts():
    for number, accepted in EXPECTED.items():
        raw = (EXAMPLES / f"eg{number}.eml").read_text(encoding="utf-8")
        result = analyze_email(raw, config=ROOT / "configs" / "integrated.yaml", website_retrieval_enabled=False)
        assert result["verdict"] in accepted, (number, result["verdict"], result["score"])

def test_brand_impersonation_helper_catches_lookalikes_not_owned_domains():
    sys.path.insert(0, str(ROOT / "phase 6"))
    from consistency_analysis import impersonated_brand
    for domain in ("paypal-secure.com", "paypa1.com", "microsft-support.com", "chase-bank-security.com"):
        assert impersonated_brand(domain), domain
    for domain in ("paypal.com", "mail.paypal.com", "github.com", "dropbox.com", "apple-orchard-farm.com", "192.168.1.1"):
        assert impersonated_brand(domain) is None, domain

def test_risk_indicator_total_is_capped_and_benign_mail_gets_none():
    result = analyze_email(
        "From: Alice <alice@gmail.com>\nSubject: Hello\nDate: Tue, 01 Jul 2025 10:00:00 +0000\nMessage-ID: <x@gmail.com>\n\nLunch tomorrow?")
    assert result["risk_indicators"]["total"] == 0
    raw = (EXAMPLES / "eg1.eml").read_text(encoding="utf-8")
    assert analyze_email(raw, website_retrieval_enabled=False)["risk_indicators"]["total"] <= .55
