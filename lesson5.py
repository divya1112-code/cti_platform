import requests
API_KEY = "a8d74e2fbd56678ae9c0e91e8f660338091f30313132e130922c451a9f505307"
ioc = input("Enter an IP address: ")
url = f"https://otx.alienvault.com/api/v1/indicator/IPv4/{ioc}/general"
headers = {
    "X-OTX-API-KEY": API_KEY
}
response = requests.get(url, headers=headers)
data = response.json()
country = data.get("country_name", "Unknown")
pulse_info = data.get("pulse_info", {})
pulse_count = pulse_info.get("count" , 0)
print("AlienVault OTX Report ===")
print("IP address :", ioc)
print("Country    :", country)
print("Pulse Count :", pulse_count)
if pulse_count >= 10:
    print("Verdict: HIGH RISK - MALICIOUS")
elif pulse_count >= 3:
    print("Verdict: MEDIUM RISK - SUSPICIOUS")
else:
    print("Verdict: LOW RISK - SAFE")
