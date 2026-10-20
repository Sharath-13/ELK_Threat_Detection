import urllib.request
import base64
import json

es_url = "http://127.0.0.1:9200"
auth = base64.b64encode(f"elastic:{password}".encode()).decode("ascii")

# Create a secondary admin account with an easy password without complex symbols
user_payload = json.dumps({
    "password": os.environ["SOCADMIN_PASSWORD"],
    "roles": ["superuser"],
    "full_name": "SOC Admin"
}).encode("utf-8")

req = urllib.request.Request(
    f"{es_url}/_security/user/socadmin",
    data=user_payload,
    headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
)
with urllib.request.urlopen(req) as resp:
    print("Created 'socadmin' superuser with simple password result:", resp.status)

# Verify Kibana login for socadmin
kib_req = urllib.request.Request(
    "http://127.0.0.1:5601/internal/security/login",
    data=json.dumps({
        "providerType": "basic",
        "providerName": "basic",
        "currentURL": "/",
        "params": {"username": "socadmin", "password": os.environ["SOCADMIN_PASSWORD"]}
    }).encode("utf-8"),
    headers={"Content-Type": "application/json", "kbn-xsrf": "true"}
)
with urllib.request.urlopen(kib_req) as resp:
    print(f"Kibana login test for 'socadmin': HTTP {resp.status} (SUCCESS)")
