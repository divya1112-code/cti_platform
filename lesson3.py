import requests
API_KEY = "e0086769d559b43f57facb6174f4412fbd0fc502a8eb4be7d71385ade4fd7a4f"
ioc = input("Enter an IP, Domain, or,  Hash: ")
url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
headers = {
    "x-apikey": API_KEY
}
response = requests.get(url, headers=headers)
data = response.json()
stats = data["data"]["attributes"]["last_analysis_stats"]
malicious = stats["malicious"]
suspicious = stats["suspicious"]
harmless = stats["harmless"]
undetected = stats["undetected"]
print("=== VirusTotal Report ===")
print("IOC       :", ioc)
print("MALICIOUS :", malicious)
print("SUSPICIOUS :", suspicious)
print("HARMLESS  :", harmless)
print("UNDETECTED :", undetected)
total = malicious + suspicious + harmless + undetected
risk_score = int((malicious / total) * 100) if total > 0 else 0
print("Risk Score:", risk_score, "/100")
if risk_score >= 71:
    print("Verdict : HIGH RISK - MALICIOUS")
elif risk_score >= 31:
    print("Verdict : MEDIUM RISk - SUSPICIOUS")
else:
    print("Verdict : LOW RISk - SAFE")
eof
