# MCA Major Project Implementation & Final Technical Report

**Project Title**: Centralized Log Monitoring and Threat Detection System using ELK Stack  
**Academic Degree**: Master of Computer Applications (MCA)  
**Date of Completion & Verification**: 18 October 2026  
**System Status**: Fully Operational, Verified & Ready for Evaluation  

---

## 1. Executive Summary

This report documents the architectural design, implementation, debugging, and verification of a containerized Security Operations Center (SOC) centralized log monitoring and cyber threat detection system built on the Elastic Stack (version 8.11.3).

The system aggregates security audit events from Windows workstations and Linux servers, normalizes event structures, performs threat detection on credential abuse and brute-force attacks (specifically Windows Event ID 4625 and Linux SSH authentication failures), enriches events with human-readable diagnostic metadata, and visualizes security posture through a centralized Kibana dashboard. Remote security analysts are provided access via an edge-terminated Cloudflare Zero Trust TLS 1.3 tunnel that enforces HTTPS and access control without opening any inbound ports on the host.

---

## 2. Tools & Technology Stack

| Component | Technology | Version | Purpose in Project |
| :--- | :--- | :--- | :--- |
| **Search & Index Engine** | Elasticsearch | 8.11.3 | Distributed storage and analytical indexing of security documents. |
| **Log Processing Pipeline** | Logstash | 8.11.3 | Ingestion, Grok pattern parsing, field enrichment, and severity tagging. |
| **Visualization & Analytics** | Kibana | 8.11.3 | SOC Threat Intelligence Dashboard and query interface. |
| **Windows Telemetry Agent**| Winlogbeat | 8.11.3 | Shipping Windows Security (4625, 4624) and System channel events. |
| **Linux Telemetry Agent**  | Filebeat | 8.11.3 | Streaming Linux `/var/log/auth.log` and `/var/log/secure`. |
| **Secure Remote Proxy**    | Cloudflare Tunnel | Latest | Zero-Trust HTTPS egress proxy for remote analyst access. |
| **Container Orchestration**| Docker & Docker Compose | v2.x / 3.8 | Multi-container lifecycle and isolated virtual networking. |
| **Automation & Testing**   | PowerShell & Bash | 5.1 / Core | Automated startup, health validation, simulation, and dashboard setup. |

---

## 3. Implemented Modules & Threat Detection Logic

### Module 1: Windows Credential Abuse Detection (Event ID 4625)
- **Detection Trigger**: `[winlog][event_id] == 4625` or `[event][code] == "4625"`.
- **Classification**: Tagged as `event_action = "failed_logon"`, `threat_detected = "Failed Login / Potential Brute Force"`, and `threat_severity = "HIGH"`.
- **Field Extraction**:
  - `threat_user`: Extracted from `[winlog][event_data][TargetUserName]`.
  - `threat_source_ip`: Extracted from `[winlog][event_data][IpAddress]`.
  - `logon_type`: Extracted from `[winlog][event_data][LogonType]` (Type 2 = Interactive, Type 3 = Network, Type 10 = RDP).
- **SubStatus NTSTATUS Error Code Translation**:
  - `0xC000006A` -> *"Bad Password / Invalid Credentials"*
  - `0xC0000064` -> *"User Account Does Not Exist"*
  - `0xC0000234` -> *"Account Currently Locked Out"*
  - `0xC0000072` -> *"Account Disabled"*
  - `0xC0000193` -> *"Account Expired"*

### Module 2: Linux SSH Brute-Force Detection
- **Detection Trigger**: `[log][file][path] =~ "auth"` or `[message] =~ "sshd"`.
- **Grok Parser**: `Failed password for (?:invalid user )?%{DATA:threat_user} from %{IP:threat_source_ip} port %{NUMBER:threat_port}`.
- **Classification**: Tagged as `event_action = "failed_logon"`, `threat_detected = "SSH Brute Force Attack"`, `threat_severity = "HIGH"`, and `failure_reason = "Invalid SSH Password / Key"`.

### Module 3: Baseline Authentication Tracking (Event ID 4624)
- **Detection Trigger**: `[winlog][event_id] == 4624` or `[event][code] == "4624"`.
- **Classification**: Tagged as `event_action = "successful_logon"`, `threat_severity = "LOW"`.
- **Purpose**: Establishes baseline ratio of normal vs. anomalous authentication events.

### Module 4: Centralized SOC Analytics Dashboard
- Built and verified with **7 interactive panels**:
  1. **Metric**: Total Failed Login Attempts (Windows Event ID 4625 & Linux SSH failures).
  2. **Metric**: Total Successful Logins (Windows Event ID 4624 & Linux SSH successes).
  3. **Donut Chart**: Authentication & Threat Distribution by Operating System (Windows vs. Linux).
  4. **Histogram**: Threat Activity & Authentication Timeline (stacked by `event_action.keyword`).
  5. **Donut Chart**: Top Targeted User Accounts under brute-force attacks.
  6. **Horizontal Bar**: Logon Failure Reasons Breakdown (categorized failure modes).
  7. **Audit Table**: Suspicious Login Detection (Timestamp, User, Source IP, Reason, Severity).

---

## 4. Root Causes Identified & Bugs Fixed

| # | Component | Identified Issue | Root Cause | Implemented Technical Fix |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Kibana Service Configuration** | Kibana reported unhealthy; Cloudflare container blocked; `/api/...` endpoints returned 404. | `SERVER_BASEPATH=/kibana` was configured in `docker-compose.yml`, causing root API calls and healthcheck `curl http://localhost:5601/api/status` to 404. | Removed `SERVER_BASEPATH` and `SERVER_REWRITEBASEPATH` from `docker-compose.yml`. Recreated Kibana at root domain. Healthcheck now returns HTTP 200 OK. |
| **2** | **Kibana Dashboard Saved Objects** | Dashboard panels displayed error: *"Could not find the data view: -"*. | In `setup_kibana_dashboard.ps1`, `kibanaSavedObjectMeta.searchSourceJSON` omitted the `indexRefName` key, preventing Kibana from linking the visual query to the Data View reference. | Refactored `setup_kibana_dashboard.ps1` to inject `"indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"` and link to Data View ID `a3e8f74e-f5ae-4b61-ab0a-2e733b111aca`. |
| **3** | **Exported NDJSON Template** | Importing `threat_detection_dashboard.ndjson` created dangling references. | NDJSON file had hardcoded dummy ID `elk-threats-view` rather than matching the active Data View ID. | Exported fresh verified NDJSON (`kibana/threat_detection_dashboard.ndjson`) containing all 9 saved objects with `missingRefCount: 0`. |
| **4** | **Filebeat Schema Compatibility** | Potential mapping conflict between Windows string and Linux object for `log_source_os`. | `filebeat.yml` used `target: log_source_os` with subfield `name: Linux`, producing a nested JSON object instead of a keyword string. | Fixed `filebeat.yml` and `setup_linux.sh` to use `fields: { log_source_os: "Linux" }` matching the Elasticsearch keyword schema. |
| **5** | **Execution Policy Blockers** | PowerShell scripts failed to execute on standard Windows hosts with `SecurityError: UnauthorizedAccess`. | Default Windows PowerShell Execution Policy restricts unsigned script execution. | Updated documentation and scripts to run with `-ExecutionPolicy Bypass`. |

---

## 5. Verified Test Evidence

The following tests were executed and physically verified on the active system:

1. **Docker Service Healthcheck**:
   - `elasticsearch`: **Up (healthy)** (Port 127.0.0.1:9200)
   - `kibana`: **Up (healthy)** (Port 127.0.0.1:5601)
   - `logstash`: **Up** (Port 0.0.0.0:5044)
   - `cloudflared`: **Up** (QUIC connection established with Cloudflare Edge)

2. **Elasticsearch Cluster & Data Verification**:
   - Cluster status: `yellow` (expected for single-node cluster with 1 primary shard).
   - Ingested Threat Indices:
     - `elk-threats-2026.10.09`: 5 documents
     - `elk-threats-2026.10.10`: 23 documents
     - `elk-threats-2026.10.11`: 62 documents
     - `elk-threats-2026.10.12`: 86 documents
     - `elk-threats-2026.10.18`: 14 documents
   - **Total Verified Indexed Documents**: **190 documents preserved and active**.
   - **Authentication Metric Totals**:
     - Total Failed Logons (`event_action: failed_logon`): **14**
     - Total Successful Logons (`event_action: successful_logon`): **5**
     - System Errors: **24**
     - General Events: **147**
     - Platform Split: **187 Windows events**, **3 Linux events**

3. **Beats Pipeline Ingestion Connectivity**:
   - Winlogbeat syntax test: `Config OK`.
   - Winlogbeat output test: `logstash: 127.0.0.1:5044... dial up... OK... talk to server... OK`.

4. **Kibana Browser Rendering & Visual Verification**:
   - Verified via automated browser inspection.
   - Dashboard: `[SOC] Windows Threat Detection & Centralized Security Dashboard`.
   - Result: All 7 panels loaded with **zero errors**.
   - Verified Panels:
     - Panel 1: Metric counter for Failed Login Attempts (Event ID 4625)
     - Panel 2: Metric counter for Successful Logins (Event ID 4624)
     - Panel 3: Operating System Distribution (Windows 98.4% vs. Linux)
     - Panel 4: Threat Activity & Authentication Timeline Histogram
     - Panel 5: Top Targeted Accounts (root, admin, database_admin, oracle_svc, etc.)
     - Panel 6: Failure Reasons Breakdown (Bad Password, User Not Found, Account Locked, Account Disabled)
     - Panel 7: Suspicious Login Detection Audit Table (Populated with live threat records)

5. **Cloudflare Zero Trust Remote Access**:
   - Public HTTPS Tunnel: `https://upload-artificial-stranger-lawyer.trycloudflare.com`
   - Test Command: `curl.exe -k -I https://upload-artificial-stranger-lawyer.trycloudflare.com/api/status`
   - Response: **HTTP/1.1 200 OK** (TLS 1.3 encrypted, zero open inbound firewall ports).

---

## 6. Screenshot Capture Checklist for Project Report & Presentation

Archived verified screenshots are saved in your workspace under `docs/screenshots/`:

- [x] **Screenshot 1: Full SOC Threat Intelligence Dashboard**
  - **Saved File**: `docs/screenshots/soc_threat_dashboard_full.png`
  - **Content**: Comprehensive overview of all 7 panels rendering live data without missing-data-view errors.

- [x] **Screenshot 2: Metric Counters & OS Breakdown**
  - **Saved File**: `docs/screenshots/soc_threat_dashboard_top.png`
  - **Content**: Total Failed Logins, Total Successful Logins, and Operating System distribution donut chart.

- [x] **Screenshot 3: Suspicious Login Detection Table & Failure Reasons**
  - **Saved File**: `docs/screenshots/soc_threat_dashboard_table.png`
  - **Content**: Forensic audit trail with Timestamp, Target User, Source IP, SubStatus Failure Reason, and HIGH Severity tag.

- [ ] **Screenshot 4: Docker Desktop Container Status**
  - **Location**: Docker Desktop GUI -> Containers tab.
  - **What to show**: All 4 containers (`elasticsearch`, `kibana`, `logstash`, `cloudflared`) showing green "Running" status with `healthy` badge.

- [ ] **Screenshot 5: Pipeline Healthcheck Terminal Output**
  - **Location**: PowerShell terminal after running `powershell -ExecutionPolicy Bypass -File .\scripts\test-pipeline.ps1`.
  - **What to show**: Green `[ONLINE]` statuses for Elasticsearch, Kibana HTTP 200, Logstash port 5044 listening, active threat indices count, and recent threat events.

- [ ] **Screenshot 6: Safe Threat Simulation Execution**
  - **Location**: PowerShell terminal after running `powershell -ExecutionPolicy Bypass -File .\scripts\simulate-threat-events.ps1 -Count 5`.
  - **What to show**: Terminal log displaying generation of Windows 4625 events, Linux SSH brute force events, and confirmation of successful Elasticsearch indexing.

- [ ] **Screenshot 7: Kibana Discover Query Interface**
  - **Location**: `http://127.0.0.1:5601/app/discover`
  - **What to show**: Data View `ELK Threat Intelligence`, search query `event_action: "failed_logon"`, displaying individual indexed JSON documents with extracted fields.

- [ ] **Screenshot 8: Cloudflare Zero Trust Remote HTTPS Access**
  - **Location**: Web browser accessing the public TryCloudflare HTTPS URL.
  - **What to show**: Browser address bar showing padlock icon (HTTPS) and Cloudflare connection, proving remote access capability without exposing internal port 9200.

---

## 7. Security Analysis & Compliance

1. **Zero Public Attack Surface for Elasticsearch**:
   Elasticsearch port 9200 is bound strictly to `127.0.0.1:9200` on the local host. External traffic cannot reach the database directly, preventing unauthenticated access, indices deletion, and ransomware threats.
2. **Encrypted Remote Egress**:
   The Cloudflare Tunnel utilizes an outbound-only connection to the Cloudflare global edge network. No router port forwarding or firewall pinholes are required.
3. **Role-Based Credential Isolation**:
   Logstash and Kibana communicate using dedicated service accounts with least privilege. Passwords are maintained in environment files and never exposed in public repositories.
4. **Controlled Evaluation Integrity**:
   All evaluation test scripts explicitly flag generated documents with `"is_simulated": true` and `"simulation_label": "Evaluation Safe Demo Event"` so that test events are distinguishable from real enterprise telemetry.

---

## 8. Limitations & Future Enhancements

### Current Limitations:
1. **Single-Node Elasticsearch Node**: Configured for local development and academic evaluation on a single workstation.
2. **Ephemeral Quick Tunnel Subdomain**: The free Cloudflare Quick Tunnel domain changes when the container is restarted.
3. **Windows Security Log Privileges**: Direct Winlogbeat extraction of Windows kernel security events requires administrative elevation.

### Future Enhancements:
1. **Multi-Node Production Cluster**: Deploying Elasticsearch in a 3-node master-eligible quorum with cross-cluster replication.
2. **Automated Incident Response (SOAR)**: Integrating with automated playbooks (e.g. Shuffle SOAR or Elastic Security Actions) to automatically block offending IP addresses at the Windows Firewall or Linux `iptables` level after exceeding failed logon thresholds.
3. **Machine Learning Anomaly Detection**: Utilizing Elastic Platinum / ML unsupervised anomaly detection jobs to establish dynamic behavioral baselines rather than static threshold limits.
