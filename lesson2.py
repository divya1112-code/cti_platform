import requests
ip = input("Enter an IP address: ")
url = f"https://ipinfo.io/{ip}/json"
response = requests.get(url)
data = response.json()
print("=== IP Information ===")
print("Ip Address :", data["ip"])
print("City :", data["city"])
print("country :", data["country"])
print("Organization :", data["org"])
