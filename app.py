"""
app.py  —  Module C (Member C: Hanyi Yang)
Flask Web UI for Password Strength Analyzer

Usage:
    pip install -r requirements.txt
    python app.py
    Open http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, jsonify
from analyzer import analyze_password
from batch_audit import run_audit

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    password = request.form.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    result = analyze_password(password)
    return jsonify(result)


@app.route("/batch", methods=["POST"])
def batch():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400
    lines = file.read().decode("utf-8", errors="ignore").splitlines()
    passwords = [line.strip() for line in lines if line.strip()]
    if not passwords:
        return jsonify({"error": "File is empty"}), 400
    audit = run_audit(passwords)
    # remove raw password strings from response for safety
    for r in audit["results"]:
        r["password_masked"] = r["password"][:2] + "*" * (len(r["password"]) - 2)
    return jsonify(audit)


if __name__ == "__main__":
    app.run(debug=True)
