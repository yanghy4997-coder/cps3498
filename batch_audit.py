"""
batch_audit.py  —  Member B
Batch Password Policy Auditor

Usage:
    python batch_audit.py passwords.txt
    python batch_audit.py passwords.txt --output report.html
"""

import argparse
from datetime import datetime

try:
    from analyzer import analyze_password
except ImportError:
    def analyze_password(password):
        return {
            "final_score": 2,
            "score_label": "一般",
            "crack_time":  "3 hours",
            "hibp":        {"pwned": False, "count": 0},
            "feedback":    {"warning": "", "suggestions": []},
            "patterns":    {},
            "password_length": len(password),
        }

SCORE_LABELS = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}
SCORE_LABEL_MAP = {"极弱": "Very Weak", "弱": "Weak", "一般": "Fair", "强": "Strong", "极强": "Very Strong"}
SCORE_COLORS = {0: "#e74c3c", 1: "#e67e22", 2: "#f1c40f", 3: "#2ecc71", 4: "#27ae60"}


def run_audit(passwords):
    results = []
    summary = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    pwned_count = 0

    for pw in passwords:
        pw = pw.strip()
        if not pw:
            continue
        analysis = analyze_password(pw)
        analysis["password"] = pw   # A's dict doesn't include the password — add it here
        results.append(analysis)
        score = analysis.get("final_score", 0)
        summary[score] = summary.get(score, 0) + 1
        if analysis.get("hibp", {}).get("pwned"):
            pwned_count += 1

    total = len(results)
    strong = summary.get(3, 0) + summary.get(4, 0)
    pass_rate = round(strong / total * 100, 1) if total > 0 else 0.0

    return {
        "total":        total,
        "results":      results,
        "summary":      summary,
        "pass_rate":    pass_rate,
        "pwned_count":  pwned_count,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def load_passwords(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def generate_text_report(audit):
    lines = [
        "=" * 60,
        "  PASSWORD POLICY AUDIT REPORT",
        "  Generated: " + audit["generated_at"],
        "=" * 60,
        "",
        "  Total passwords audited : " + str(audit["total"]),
        "  Pass rate (score >= 3)  : " + str(audit["pass_rate"]) + "%",
        "  Breach-exposed (HIBP)   : " + str(audit["pwned_count"]),
        "",
        "  Score distribution:",
    ]
    for score in range(5):
        count = audit["summary"].get(score, 0)
        bar = "#" * count
        lines.append("    " + SCORE_LABELS[score] + " (" + str(score) + ") : " + bar + " " + str(count))

    lines += ["", "  Per-password details:", "-" * 60]
    for r in audit["results"]:
        pwned_flag = "  *** BREACHED ***" if r.get("hibp", {}).get("pwned") else ""
        lines.append(
            "  [" + SCORE_LABEL_MAP.get(r.get("score_label", ""), r.get("score_label", "?")) + "]  crack~" +
            r.get("crack_time", "?")[:20].ljust(20) +
            "  pw=" + r["password"][:20] + pwned_flag
        )
    lines += ["", "=" * 60]
    return "\n".join(lines)


def generate_html_report(audit):
    rows = ""
    for r in audit["results"]:
        score = r.get("final_score", 0)
        color = SCORE_COLORS.get(score, "#999")
        pwned = "YES" if r.get("hibp", {}).get("pwned") else "No"
        pwned_color = "#e74c3c" if r.get("hibp", {}).get("pwned") else "#27ae60"
        pw_display = r["password"][:24] + ("..." if len(r["password"]) > 24 else "")
        rows += (
            "<tr>"
            "<td>" + pw_display + "</td>"
            "<td style='color:" + color + ";font-weight:bold'>" + SCORE_LABEL_MAP.get(r.get("score_label", ""), r.get("score_label", "?")) + "</td>"
            "<td>" + r.get("crack_time", "?") + "</td>"
            "<td style='color:" + pwned_color + "'>" + pwned + "</td>"
            "</tr>\n"
        )

    dist_bars = ""
    for score in range(5):
        count = audit["summary"].get(score, 0)
        pct = round(count / audit["total"] * 100) if audit["total"] else 0
        color = SCORE_COLORS[score]
        dist_bars += (
            "<div style='display:flex;align-items:center;margin:4px 0'>"
            "<span style='width:40px;color:" + color + ";font-weight:bold'>" + SCORE_LABELS[score] + "</span>"
            "<div style='background:" + color + ";width:" + str(pct * 3) + "px;height:18px;border-radius:3px;margin:0 8px'></div>"
            "<span>" + str(count) + " (" + str(pct) + "%)</span></div>"
        )

    pass_color = "#27ae60" if audit["pass_rate"] >= 70 else "#e74c3c"

    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<title>Password Policy Audit Report</title><style>"
        "body{font-family:Arial,sans-serif;max-width:900px;margin:40px auto;color:#333}"
        "h1{color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:8px}"
        ".grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:24px 0}"
        ".card{background:#f8f9fa;border-radius:8px;padding:16px;text-align:center}"
        ".num{font-size:2rem;font-weight:bold;color:#2c3e50}"
        ".lbl{font-size:.85rem;color:#666;margin-top:4px}"
        "table{width:100%;border-collapse:collapse;margin-top:24px}"
        "th{background:#2c3e50;color:#fff;padding:10px;text-align:left}"
        "td{padding:8px 10px;border-bottom:1px solid #eee}"
        "tr:hover td{background:#f0f4ff}"
        ".footer{margin-top:32px;font-size:.8rem;color:#999;text-align:center}"
        "</style></head><body>"
        "<h1>Password Policy Audit Report</h1>"
        "<p style='color:#666'>Generated: " + audit["generated_at"] + "</p>"
        "<div class='grid'>"
        "<div class='card'><div class='num'>" + str(audit["total"]) + "</div><div class='lbl'>Passwords Audited</div></div>"
        "<div class='card'><div class='num' style='color:" + pass_color + "'>" + str(audit["pass_rate"]) + "%</div><div class='lbl'>Pass Rate (score &gt;= 3)</div></div>"
        "<div class='card'><div class='num' style='color:#e74c3c'>" + str(audit["pwned_count"]) + "</div><div class='lbl'>Breach-Exposed (HIBP)</div></div>"
        "</div>"
        "<h2>Score Distribution</h2>" + dist_bars +
        "<h2>Per-Password Details</h2>"
        "<table><thead><tr><th>Password</th><th>Strength</th><th>Est. Crack Time</th><th>Breached?</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table>"
        "<div class='footer'>Password Policy Auditor - " + audit["generated_at"][:10] + "</div>"
        "</body></html>"
    )


def main():
    parser = argparse.ArgumentParser(description="Batch Password Policy Auditor")
    parser.add_argument("input", help="Path to password list file (one per line)")
    parser.add_argument("--output", "-o", help="Save HTML report to this file")
    args = parser.parse_args()

    print("[*] Loading passwords from: " + args.input)
    passwords = load_passwords(args.input)
    print("[*] Analyzing " + str(len(passwords)) + " passwords ...")

    audit = run_audit(passwords)
    print(generate_text_report(audit))

    if args.output:
        html = generate_html_report(audit)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(html)
        print("\n[OK] HTML report saved to: " + args.output)


if __name__ == "__main__":
    main()
