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
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024


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
    # Never return raw passwords to the browser. The analysis pipeline needs the
    # value internally, but the UI only receives a length-preserving mask.
    for result in audit["results"]:
        password = result.pop("password")
        visible = min(2, len(password))
        result["password_masked"] = password[:visible] + "*" * (len(password) - visible)
    return jsonify(audit)


if __name__ == "__main__":
    app.run(debug=True)
