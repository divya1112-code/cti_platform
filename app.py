from flask import Flask, render_template, request, send_file, jsonify, session, redirect, url_for
import requests
import re
import sqlite3
import os
import base64
import time
from datetime import datetime
from report import generate_report
from functools import wraps

app = Flask(__name__)
app.secret_key = "cybershield_secret_2026"

VT_KEY    = "e0086769d559b43f57facb6174f4412fbd0fc502a8eb4be7d71385ade4fd7a4f"
ABUSE_KEY = "244ba6220f712425ab884832cf3c717fca35236878361fdc138d4f54c446e69f385a203c96358445"
OTX_KEY   = "a8d74e2fbd56678ae9c0e91e8f660338091f30313132e130922c451a9f505307"

USERNAME = "admin"
PASSWORD = "cybershield123"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def create_database():
    conn = sqlite3.connect("cti_database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ioc_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc         TEXT NOT NULL,
            ioc_type    TEXT NOT NULL,
            vt_score    INTEGER,
            abuse_score INTEGER,
            otx_score   INTEGER,
            final_score INTEGER,
            verdict     TEXT,
            checked_at  TEXT
        )
    """)
    conn.commit()
    conn.close()

def detect_ioc_type(ioc):
    ioc = ioc.strip()
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, ioc):
        return "ip"
    elif ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    elif len(ioc) in [32, 40, 64] and re.match(r"^[a-fA-F0-9]+$", ioc):
        return "hash"
    else:
        return "domain"

def check_virustotal(ioc, ioc_type):
    try:
        headers = {"x-apikey": VT_KEY}

        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            response = requests.get(url, headers=headers, timeout=15)
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            raise Exception(f"VT Stats = {stats}")
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            score = (malicious * 7) + (suspicious * 3)

            return min(score, 100)

        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            response = requests.get(url, headers=headers, timeout=15)
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            score = (malicious * 7) + (suspicious * 3)
            return min(score, 100)

        elif ioc_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
            response = requests.get(url, headers=headers, timeout=15)
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious",0)
            score = (malicious * 7) + (suspicious * 3)
            return min(score, 100)

        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            check_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(check_url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                score = (malicious * 7) + (suspicious * 3)
                return min(score, 100)
            else:
                submit = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": ioc},
                    timeout=15
                )
                if submit.status_code == 200:
                    analysis_id = submit.json().get("data", {}).get("id", "")
                    time.sleep(5)
                    result = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                        timeout=15
                    )
                    if result.status_code == 200:
                        stats = result.json().get("data", {}).get("attributes", {}).get("stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)

                        score = (malicious * 7) + (suspicious * 3)
                        return min(score, 100)
            return 0
        else:
            return 0
    except Exception as e:
        print(f"VT Error: {e}")
        return 0

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params, timeout=15)
        data = response.json()
        return data.get("data", {}).get("abuseConfidenceScore", 0)
    except Exception as e:
        print(f"Abuse Error: {e}")
        return 0

def check_otx(ioc, ioc_type):
    try:
        if ioc_type == "ip":
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
        elif ioc_type == "domain":
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
        elif ioc_type == "url":
            url = f"https://otx.alienvault.com/api/v1/indicators/url/{ioc}/general"
        elif ioc_type == "hash":
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general"
        else:
            return 0
        headers = {"X-OTX-API-KEY": OTX_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        data = response.json()
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        return min(pulse_count * 2, 100)
    except Exception as e:
        print(f"OTX Error: {e}")
        return 0

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form["username"] == USERNAME and request.form["password"] == PASSWORD:
            session["logged_in"] = True
            session["username"] = request.form["username"]
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/analyze_page")
@login_required
def analyze_page():
    return render_template("analyze.html")

@app.route("/qr_page")
@login_required
def qr_page():
    return render_template("qr.html")

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    ioc = request.form["ioc"].strip()
    ioc_type = detect_ioc_type(ioc)
    vt_score    = check_virustotal(ioc, ioc_type)
    abuse_score = check_abuseipdb(ioc) if ioc_type == "ip" else 0
    otx_score   = check_otx(ioc, ioc_type)
    if ioc_type == "ip":
        final_score = int((vt_score * 0.5) + (abuse_score * 0.3) + (otx_score * 0.2))
    else:
        final_score = int((vt_score * 0.8) + (otx_score * 0.2))
    if final_score >= 71:
        verdict = "HIGH RISK - MALICIOUS"
        color = "danger"
    elif final_score >= 31:
        verdict = "MEDIUM RISK - SUSPICIOUS"
        color = "warning"
    else:
        verdict = "LOW RISK - SAFE"
        color = "success"
    conn = sqlite3.connect("cti_database.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ioc_results
        (ioc, ioc_type, vt_score, abuse_score, otx_score, final_score, verdict, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (ioc, ioc_type, vt_score, abuse_score, otx_score, final_score, verdict,
          datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    print("VT =", vt_score)
    print("Abuse =", abuse_score)
    print("OTX =", otx_score)
    print("Final =", final_score)
    return render_template("result.html",
        ioc=ioc, ioc_type=ioc_type,
        vt_score=vt_score, abuse_score=abuse_score,
        otx_score=otx_score, final_score=final_score,
        verdict=verdict, color=color)

@app.route("/history")
@login_required
def history():
    conn = sqlite3.connect("cti_database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ioc_results ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return render_template("history.html", rows=rows)

@app.route("/download_report", methods=["POST"])
@login_required
def download_report():
    ioc         = request.form["ioc"]
    ioc_type    = request.form["ioc_type"]
    vt_score    = int(request.form["vt_score"])
    abuse_score = int(request.form["abuse_score"])
    otx_score   = int(request.form["otx_score"])
    final_score = int(request.form["final_score"])
    verdict     = request.form["verdict"]
    filename = generate_report(ioc, ioc_type, vt_score, abuse_score,
                               otx_score, final_score, verdict)
    return send_file(filename, as_attachment=True)

@app.route("/scan_qr", methods=["POST"])
@login_required
def scan_qr():
    from qr_scanner import scan_qr_code
    if "qr_image" not in request.files:
        return render_template("qr_result.html", ioc=None, error="No file uploaded")
    file = request.files["qr_image"]
    if file.filename == "":
        return render_template("qr_result.html", ioc=None, error="No file selected")
    os.makedirs("uploads", exist_ok=True)
    filepath = os.path.join("uploads", file.filename)
    file.save(filepath)
    qr_data = scan_qr_code(filepath)
    if qr_data:
        return render_template("qr_result.html", ioc=qr_data, error=None)
    else:
        return render_template("qr_result.html", ioc=None, error="No QR code detected in image")

@app.route("/dashboard_data")
@login_required
def dashboard_data():
    conn = sqlite3.connect("cti_database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ioc_results")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE verdict LIKE '%HIGH%'")
    high = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE verdict LIKE '%MEDIUM%'")
    medium = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE verdict LIKE '%SAFE%'")
    safe = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE ioc_type='ip'")
    ip_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE ioc_type='domain'")
    domain_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE ioc_type='url'")
    url_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE ioc_type='hash'")
    hash_count = cursor.fetchone()[0]
    cursor.execute("""SELECT ioc, ioc_type, final_score, verdict, checked_at
                      FROM ioc_results ORDER BY id DESC LIMIT 5""")
    recent = cursor.fetchall()
    conn.close()
    return jsonify({
        "total": total, "high": high, "medium": medium, "safe": safe,
        "ip_count": ip_count, "domain_count": domain_count,
        "url_count": url_count, "hash_count": hash_count,
        "recent": [{"ioc": r[0], "type": r[1], "score": r[2],
                    "verdict": r[3], "time": r[4]} for r in recent]
    })

@app.route("/stats")
@login_required
def stats():
    conn = sqlite3.connect("cti_database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ioc_results")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE verdict LIKE '%HIGH%'")
    threats = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM ioc_results WHERE verdict LIKE '%SAFE%'")
    safe = cursor.fetchone()[0]
    conn.close()
    return jsonify({"total": total, "threats": threats, "safe": safe})

if __name__ == "__main__":
    create_database()
    app.run(debug=True)
