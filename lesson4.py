import requests
API_KEY = "244ba6220f712425ab884832cf3c717fca35236878361fdc138d4f54c446e69f385a203c96358445"
ip = input("Enter an IP address: ")
url = "https://api.abuseipdb.com/api/v2/check"
headers = {
    "Key": API_KEY,
    "Accept": "application/json"
}
params = {
    "ipAddress": ip,
    "maxAgeInDays": 90
}
response = requests.get(url, headers=headers, params=params)
data = response.json()
info = data["data"]
print("=== AbuseIPDB Report ===")
print("IP Address    :", info["ipAddress"])
print("Country       :", info["countryCode"])
print("ISP           :", info["isp"])
print("Abuse Score   :", info["abuseConfidenceScore"])
print("Total Reports :", info["totalReports"])
print("last Reported :", info["lastReportedAt"])
score = info["abuseConfidenceScore"]
if score >= 71:
    print("Verdict: HIGH RISK - MALICIOUS")
elif score >= 31:
    print("Verdict: MEDIUM RISK - SUSPICIOUS")
else:
    print("Verdict: LOW RISK - SAFE")
