import requests
import re

VT_KEY = "e0086769d559b43f57facb6174f4412fbd0fc502a8eb4be7d71385ade4fd7a4f"
ABUSE_KEY= "244ba6220f712425ab884832cf3c717fca35236878361fdc138d4f54c446e69f385a203c96358445"
OTX_KEY = "a8d74e2fbd56678ae9c0e91e8f660338091f30313132e130922c451a9f505307"

def detect_ioc_type(ioc):
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, ioc):
        return "ip"
    elif ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    elif len(ioc) in [32, 40, 64]:
        return "hash"
    else:
        return "domain"

def check_virustotal(ioc, ioc_type):
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        return 0
    headers = {"x-apikey": VT_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 1
    return int((malicious / total) * 100)

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSE_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    return data.get("data", {}).get("abuseConfidenceScore", 0)

def check_otx(ioc, ioc_type):
    if ioc_type == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    elif ioc_type == "domain":
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
    else:
        return 0
    headers = {"X-OTX-API-KEY": OTX_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()
    pulse_info = data.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    return min(pulse_count * 2, 100)

ioc = input("Enter an IP, Domain, Hash or URL: ")
ioc_type = detect_ioc_type(ioc)

print(f"\nIOC Type detected: {ioc_type.upper()}")
print("Querying all APIs...\n")

vt_score = check_virustotal(ioc, ioc_type)
print(f"VirusTotal Score  : {vt_score}/100")

if ioc_type == "ip":
    abuse_score = check_abuseipdb(ioc)
    otx_score = check_otx(ioc, ioc_type)
    print(f"AbuseIPDB Score   : {abuse_score}/100")
    print(f"OTX Score         : {otx_score}/100")
    final_score = int((vt_score * 0.4) + (abuse_score * 0.3) + (otx_score * 0.3))
else:
    otx_score = check_otx(ioc, ioc_type)
    print(f"OTX Score         : {otx_score}/100")
    final_score = int((vt_score * 0.6) + (otx_score * 0.4))

print(f"\nFinal Risk Score  : {final_score}/100")

if final_score >= 71:
    print("Verdict: HIGH RISK - MALICIOUS")
elif final_score >= 31:
    print("Verdict: MEDIUM RISK - SUSPICIOUS")
else:
    print("Verdict: LOW RISK - SAFE")
