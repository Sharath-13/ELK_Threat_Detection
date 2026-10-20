import urllib.request
import base64
import json
from datetime import datetime, timezone

es_url = "http://127.0.0.1:9200"
auth = base64.b64encode(f"elastic:{password}".encode()).decode("ascii")
headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
today_idx = "elk-threats-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")

# Add 4 successful authentications (Event ID 4624)
success_users = ["analyst_jane", "admin_bob", "service_backup", "finance_mary"]
for u in success_users:
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "log_source_os": "Windows",
        "event_action": "successful_logon",
        "event_category": "authentication",
        "threat_severity": "LOW",
        "threat_user": u,
        "threat_source_ip": "192.168.1.50",
        "is_simulated": True,
        "simulation_label": "Evaluation Safe Baseline Event",
        "winlog": {
            "event_id": 4624,
            "channel": "Security",
            "event_data": {
                "TargetUserName": u,
                "IpAddress": "192.168.1.50"
            }
        }
    }
    req = urllib.request.Request(f"{es_url}/{today_idx}/_doc", data=json.dumps(doc).encode("utf-8"), headers=headers)
    urllib.request.urlopen(req)
    print(f"Indexed baseline successful logon for '{u}'")

# Add 3 safe failed logons (Event ID 4625)
failed_targets = [("oracle_svc", "10.0.0.99", "Bad Password / Invalid Credentials"),
                  ("root", "192.168.1.250", "User Account Does Not Exist"),
                  ("sec_audit", "172.16.5.12", "Account Disabled")]

for u, ip, reason in failed_targets:
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "log_source_os": "Windows",
        "event_action": "failed_logon",
        "event_category": "authentication",
        "threat_detected": "Failed Login / Potential Brute Force",
        "threat_severity": "HIGH",
        "threat_user": u,
        "threat_source_ip": ip,
        "failure_reason": reason,
        "logon_type": "3",
        "is_simulated": True,
        "simulation_label": "Evaluation Safe Demo Event",
        "winlog": {
            "event_id": 4625,
            "channel": "Security",
            "event_data": {
                "TargetUserName": u,
                "IpAddress": ip,
                "SubStatus": "0xC000006A"
            }
        }
    }
    req = urllib.request.Request(f"{es_url}/{today_idx}/_doc", data=json.dumps(doc).encode("utf-8"), headers=headers)
    urllib.request.urlopen(req)
    print(f"Indexed simulated failed logon for '{u}' from {ip}")

# Refresh index
refresh_req = urllib.request.Request(f"{es_url}/{today_idx}/_refresh", data=b"", headers=headers)
urllib.request.urlopen(refresh_req)
print("Index refreshed successfully.")
