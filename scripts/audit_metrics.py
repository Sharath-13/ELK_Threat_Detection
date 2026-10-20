import urllib.request
import base64
import json

es_url = "http://127.0.0.1:9200"
auth = base64.b64encode(f"elastic:{password}".encode()).decode("ascii")
headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}

def search_count(query):
    req = urllib.request.Request(
        f"{es_url}/elk-threats-*/_count",
        data=json.dumps({"query": query}).encode("utf-8"),
        headers=headers
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())["count"]

total_docs = search_count({"match_all": {}})
failed_logons = search_count({"match": {"event_action": "failed_logon"}})
successful_logons = search_count({"match": {"event_action": "successful_logon"}})
system_errors = search_count({"match": {"event_action": "system_error"}})
general_events = search_count({"match": {"event_action": "general_event"}})

windows_events = search_count({"match": {"log_source_os": "Windows"}})
linux_events = search_count({"match": {"log_source_os": "Linux"}})

print("--- ELASTICSEARCH AUDIT METRICS ---")
print(f"Total Documents in elk-threats-*: {total_docs}")
print(f"Total Failed Logons (event_action: failed_logon): {failed_logons}")
print(f"Total Successful Logons (event_action: successful_logon): {successful_logons}")
print(f"Total System Errors (event_action: system_error): {system_errors}")
print(f"Total General Events: {general_events}")
print(f"Windows Events: {windows_events}")
print(f"Linux Events: {linux_events}")

# Check indices
req_indices = urllib.request.Request(f"{es_url}/_cat/indices/elk-threats-*?format=json", headers=headers)
with urllib.request.urlopen(req_indices) as resp:
    indices = json.loads(resp.read().decode())
    print("\n--- INDICES BREAKDOWN ---")
    for idx in indices:
        print(f"Index: {idx['index']} | Docs: {idx['docs.count']} | Size: {idx['store.size']}")
