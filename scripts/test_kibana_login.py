import urllib.request
import json

url = "http://127.0.0.1:5601/internal/security/login"
data = {
    "providerType": "basic",
    "providerName": "basic",
    "currentURL": "/",
    "params": {
        "username": "elastic",
        "password": os.environ["ELASTIC_PASSWORD"]
    }
}
req = urllib.request.Request(
    url,
    data=json.dumps(data).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }
)
try:
    with urllib.request.urlopen(req) as resp:
        print("HTTP Status:", resp.status)
        print("Headers:", resp.headers.get("Set-Cookie", "No cookie"))
        print("Body:", resp.read().decode())
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code, e.read().decode())
