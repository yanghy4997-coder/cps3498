"""
test_batch.py  —  Member B
Test suite for batch_audit.py

Run with:
    pip install pytest
    pytest test_batch.py -v
"""

import pytest
from batch_audit import run_audit, load_passwords, generate_text_report, generate_html_report
import tempfile
import os


# ── Fixtures ─────────────────────────────────────────────────────────────────

WEAK_PASSWORDS = ["password", "123456", "qwerty123"]
STRONG_PASSWORDS = ["X9#kL2$mQr7!vN4p", "Tr@ffic$L1ght99!"]
MIXED_PASSWORDS = WEAK_PASSWORDS + STRONG_PASSWORDS


# ── Basic audit tests ─────────────────────────────────────────────────────────

def test_audit_returns_correct_total():
    """Total count should match number of input passwords."""
    audit = run_audit(MIXED_PASSWORDS)
    assert audit["total"] == len(MIXED_PASSWORDS)


def test_weak_passwords_have_zero_pass_rate():
    """All-weak list should give 0% pass rate."""
    audit = run_audit(WEAK_PASSWORDS)
    assert audit["pass_rate"] == 0.0


def test_strong_passwords_have_high_pass_rate():
    """Strong passwords should score >= 3 and push pass rate above 0."""
    audit = run_audit(STRONG_PASSWORDS)
    assert audit["pass_rate"] > 0.0


def test_pass_rate_is_between_0_and_100():
    """Pass rate must always be a valid percentage."""
    audit = run_audit(MIXED_PASSWORDS)
    assert 0.0 <= audit["pass_rate"] <= 100.0


def test_summary_counts_add_up_to_total():
    """All score-bucket counts should sum to total."""
    audit = run_audit(MIXED_PASSWORDS)
    assert sum(audit["summary"].values()) == audit["total"]


def test_summary_has_all_five_buckets():
    """Summary dict should always have keys 0-4."""
    audit = run_audit(MIXED_PASSWORDS)
    for score in range(5):
        assert score in audit["summary"]


def test_results_contain_password_field():
    """Each result should include the original password string."""
    audit = run_audit(["hunter2", "correcthorsebatterystaple"])
    for r in audit["results"]:
        assert "password" in r
        assert len(r["password"]) > 0


def test_results_contain_required_fields():
    """Each result should have the fields provided by analyzer.py."""
    audit = run_audit(["password123"])
    r = audit["results"][0]
    for field in ["final_score", "score_label", "crack_time", "hibp"]:
        assert field in r, f"Missing field: {field}"


# ── HIBP / breach detection tests ────────────────────────────────────────────

def test_known_breached_password_detected():
    """'password' has been in billions of breaches — must be flagged."""
    audit = run_audit(["password"])
    assert audit["pwned_count"] >= 1


def test_pwned_count_does_not_exceed_total():
    """Can't have more breached passwords than total passwords."""
    audit = run_audit(MIXED_PASSWORDS)
    assert audit["pwned_count"] <= audit["total"]


def test_pwned_count_is_non_negative():
    audit = run_audit(STRONG_PASSWORDS)
    assert audit["pwned_count"] >= 0


# ── Edge case tests ───────────────────────────────────────────────────────────

def test_empty_list_returns_zero_total():
    """Empty input should return zeroed-out audit."""
    audit = run_audit([])
    assert audit["total"] == 0
    assert audit["pass_rate"] == 0.0
    assert audit["pwned_count"] == 0


def test_list_with_blank_lines_ignored():
    """Blank lines in input should be skipped."""
    audit = run_audit(["password123", "", "   ", "hunter2"])
    assert audit["total"] == 2


def test_single_password():
    """Single password should work without errors."""
    audit = run_audit(["onlyone"])
    assert audit["total"] == 1
    assert audit["pass_rate"] in [0.0, 100.0]


def test_generated_at_is_set():
    """generated_at timestamp should be present and non-empty."""
    audit = run_audit(["test"])
    assert "generated_at" in audit
    assert len(audit["generated_at"]) > 0


# ── load_passwords tests ──────────────────────────────────────────────────────

def test_load_passwords_from_file():
    """load_passwords() should read one password per line."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                     delete=False, encoding="utf-8") as f:
        f.write("password123\nhunter2\nletmein\n")
        tmppath = f.name
    try:
        passwords = load_passwords(tmppath)
        assert passwords == ["password123", "hunter2", "letmein"]
    finally:
        os.unlink(tmppath)


def test_load_passwords_skips_blank_lines():
    """load_passwords() should ignore blank lines."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                     delete=False, encoding="utf-8") as f:
        f.write("password123\n\nhunter2\n\n")
        tmppath = f.name
    try:
        passwords = load_passwords(tmppath)
        assert len(passwords) == 2
    finally:
        os.unlink(tmppath)


# ── Report generation tests ───────────────────────────────────────────────────

def test_text_report_contains_total():
    """Text report should mention the total count."""
    audit = run_audit(WEAK_PASSWORDS)
    report = generate_text_report(audit)
    assert str(audit["total"]) in report


def test_text_report_contains_pass_rate():
    """Text report should show the pass rate."""
    audit = run_audit(WEAK_PASSWORDS)
    report = generate_text_report(audit)
    assert str(audit["pass_rate"]) in report


def test_html_report_is_valid_html():
    """HTML report should start with DOCTYPE and contain a table."""
    audit = run_audit(WEAK_PASSWORDS)
    html = generate_html_report(audit)
    assert "<!DOCTYPE html>" in html
    assert "<table>" in html
    assert "</html>" in html


def test_html_report_contains_all_passwords():
    """Every password (truncated to 24 chars) should appear in the HTML."""
    passwords = ["hunter2", "letmein"]
    audit = run_audit(passwords)
    html = generate_html_report(audit)
    for pw in passwords:
        assert pw[:24] in html
