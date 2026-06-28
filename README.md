# CyberShield — Cyber Threat Intelligence Platform

A professional web-based CTI platform for IOC Analysis built with Python Flask.

## Features
- Analyze IPs, Domains, File Hashes and URLs
- 3 Threat Intelligence APIs integrated
- Weighted Risk Scoring (0-100)
- Beautiful Dashboard with Charts
- QR Code Scanner
- PDF Report Generation
- Scan History Database

## Setup Instructions

### Step 1 — Clone the repository
git clone https://github.com/YOUR_USERNAME/cti-platform.git
cd cti-platform

### Step 2 — Create virtual environment
python3 -m venv venv
source venv/bin/activate

### Step 3 — Install all dependencies
pip install -r requirements.txt

### Step 4 — Get Free API Keys
You need 3 free API keys:
- VirusTotal → https://virustotal.com (Sign up → Profile → API Key)
- AbuseIPDB  → https://abuseipdb.com (Sign up → Account → My API → Keys)
- AlienVault OTX → https://otx.alienvault.com (Sign up → Settings → API Key)

### Step 5 — Add API keys to app.py
Open app.py and replace:
VT_KEY    = "YOUR_VIRUSTOTAL_KEY_HERE"   ← paste VirusTotal key
ABUSE_KEY = "YOUR_ABUSEIPDB_KEY_HERE"   ← paste AbuseIPDB key
OTX_KEY   = "YOUR_OTX_KEY_HERE"         ← paste OTX key

### Step 6 — Run the application
python3 app.py

### Step 7 — Open in browser
http://127.0.0.1:5000

## Developer
- Name: Divya
- University: DAV University
- Program: B.Tech CSE 3rd Year 5th Semester
