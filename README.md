# Centralized Log Monitoring and Threat Detection System using ELK Stack

> **MCA Major Project**  
> **Topic**: Centralized Log Monitoring, Event Enrichment, and Cyber Threat Detection using Elasticsearch, Logstash, Kibana (v8.11.3), and Beats.

---

## 1. Project Overview & Architecture

This project implements an enterprise-grade Security Operations Center (SOC) centralized log monitoring and cyber threat detection pipeline. It ingests, parses, enriches, and visualizes security telemetry from heterogeneous operating systems (Windows workstations and Linux servers) to detect credential-based attacks, brute-force anomalies, and unauthorized access in real time.

```
+-----------------------------------------------------------------------------------------+
|                                    LOG DATA SOURCES                                     |
|                                                                                         |
|   [Windows Host / Workstation]                              [Linux Server / Cloud VM]   |
|   - Windows Security Log (Event 4625, 4624)                 - /var/log/auth.log         |
|   - Windows System Log (Warnings/Errors)                    - /var/log/secure           |
|            |                                                          |                 |
|      [Winlogbeat 8.11]                                          [Filebeat 8.11]         |
+------------|----------------------------------------------------------|-----------------+
             |                                                          |
             +----------------------------+-----------------------------+
                                          | Beats Protocol (Port 5044)
                                          v
+-----------------------------------------------------------------------------------------+
|                                DOCKER CONTAINER NETWORK                                 |
|                                                                                         |
|   [Logstash 8.11.3] (:5044 Ingestion Port)                                              |
|   - Ingestion: Lumberjack/Beats protocol                                                |
|   - Normalization: Event ID 4625 -> Failed Logon, ID 4624 -> Successful Logon           |
|   - Linux Grok Parser: Regex extraction of SSH targets and source IPs                   |
|   - Threat Tagging: HIGH severity assignment, SubStatus error code translation          |
|            |                                                                            |
|            | HTTP REST API (:9200, Basic Authentication)                                |
|            v                                                                            |
|   [Elasticsearch 8.11.3] (:9200 - Bound strictly to 127.0.0.1)                          |
|   - Indices: elk-threats-YYYY.MM.dd                                                     |
|   - Single-Node Cluster, JVM Heap: 1 GB (-Xms1024m -Xmx1024m)                           |
|            |                                                                            |
|            v Internal Bridge Network                                                    |
|   [Kibana 8.11.3] (:5601)                                                               |
|   - Centralized SOC Threat Intelligence Dashboard (7 interactive panels)                |
|   - Data View: "ELK Threat Intelligence" (Pattern: elk-threats-*)                       |
+------------|----------------------------------------------------------------------------+
             | Internal Proxy (:5601)
             v
+-----------------------------------------------------------------------------------------+
|                                SECURE REMOTE ACCESS LAYER                               |
|                                                                                         |
|   [Cloudflare Zero Trust Tunnel (cloudflared container)]                                |
|   - Outbound encrypted TLS 1.3 tunnel to Cloudflare Edge                                |
|   - Public HTTPS Access: https://<assigned-subdomain>.trycloudflare.com                 |
|   - Security Guarantee: ZERO open inbound firewall ports; Port 9200 never exposed       |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Prerequisites

- **Operating System**: Windows 10/11 (64-bit) with WSL2 enabled.
- **Docker Desktop**: Docker Engine and Docker Compose v2.x installed and running.
- **Memory**: Minimum 8 GB RAM (ELK stack is budgeted for ~3.5 GB total container memory).
- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7 (Run as Administrator for full event log access).

---

## 3. Exact Startup and Shutdown Commands

### A. Starting the System
1. Ensure **Docker Desktop** is running.
2. Open PowerShell in the project root directory:
   ```powershell
   cd c:\Users\ASUS\Downloads\ELK_Threat_Detection
   ```
3. Run the automated startup script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\start-elk.ps1
   ```
   *Alternative standard command:*
   ```bash
   docker compose up -d
   ```

### B. Validating System Health
Run the automated end-to-end test script:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test-pipeline.ps1
```
This tests:
- Elasticsearch cluster health (`http://127.0.0.1:9200/_cluster/health`)
- Kibana web interface responsiveness (`http://127.0.0.1:5601/api/status` -> HTTP 200)
- Logstash Beats ingestion port (`127.0.0.1:5044`)
- Document indexing count in `elk-threats-*`

### C. Stopping the System
To stop all containers and release RAM back to Windows:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop-elk.ps1
```
*Alternative standard command:*
```bash
docker compose down
```

---

## 4. Dashboard Access Instructions

### Local Access:
- **URL**: [http://127.0.0.1:5601](http://127.0.0.1:5601)
- **Direct SOC Dashboard**: [http://127.0.0.1:5601/app/dashboards#/view/soc-threat-dashboard](http://127.0.0.1:5601/app/dashboards#/view/soc-threat-dashboard)
- **Verified Credentials** (All tested & working):
 - Primary Superuser: `elastic` / `<YOUR_ELASTIC_PASSWORD>`
- Admin Superuser: `admin` / `<YOUR_ADMIN_PASSWORD>`
- Simple Symbol-Free: `socadmin` / `<YOUR_SOCADMIN_PASSWORD>`

### Public Remote Access (Cloudflare HTTPS Tunnel):
The containerized Cloudflare Tunnel routes traffic directly to Kibana over TLS 1.3 without exposing internal ports.
To inspect the current active tunnel URL, run:
```powershell
docker logs cloudflared 2>&1 | Select-String -Pattern "https://[a-zA-Z0-9-]+\.trycloudflare\.com"
```
*Example verified URL:* `https://upload-artificial-stranger-lawyer.trycloudflare.com`

---

## 5. How to Generate Safe Test Events

### Option A: Complete Multi-Platform Threat Simulation (Recommended for Viva)
Run the project's safe evaluation event generator:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\simulate-threat-events.ps1 -Count 5
```
This safely creates:
1. **Windows Event ID 4625**: Brute-force simulation across targeted accounts (`admin`, `root`, `database_admin`) with varied SubStatus failure reasons (`Bad Password`, `User Account Does Not Exist`, `Account Locked Out`).
2. **Linux SSH Brute Force**: Simulated failed SSH attempts from remote IP addresses parsed with Grok.
3. **Baseline Success (Event ID 4624)**: Legitimate authorized logins to demonstrate ratio metrics.

*All simulated events are explicitly labeled with `"is_simulated": true` and `"simulation_label": "Evaluation Safe Demo Event"`.*

### Option B: Native Windows Security Log Simulation
To generate real Windows Event ID 4625 events into the Windows Event Viewer using LSASS API:
```powershell
powershell -ExecutionPolicy Bypass -File .\winlogbeat\simulate_threats.ps1 -Attempts 5
```

---

## 6. How to Verify Events in Kibana

1. Open `http://127.0.0.1:5601` in your web browser.
2. Log in using `elastic` credentials.
3. In the left navigation menu, click **Discover**:
   - Select Data View: **ELK Threat Intelligence** (`elk-threats-*`).
   - Set the time picker to **Last 30 days** or **Today**.
   - Available fields: `threat_user`, `threat_source_ip`, `threat_severity`, `failure_reason`, `log_source_os`, `event_action`.
4. In the left navigation menu, click **Dashboard**:
   - Open **[SOC] Windows Threat Detection & Centralized Security Dashboard**.
   - Observe all 7 live panels updating dynamically.

---

## 7. SOC Dashboard Panels Reference

| Panel # | Panel Name | Visualization Type | Threat Metric Tracked |
| :---: | :--- | :--- | :--- |
| **1** | Total Failed Login Attempts (Event ID 4625) | Metric Counter | Real-time counter of credential authentication failures. |
| **2** | Total Successful Logins (Event ID 4624) | Metric Counter | Normal baseline comparison counter. |
| **3** | Authentication & Threat Distribution by OS | Donut Chart | Threat origin breakdown (Windows vs. Linux). |
| **4** | Threat Activity & Authentication Timeline | Stacked Histogram | Event frequency over time to identify sudden attack surges. |
| **5** | Top Targeted User Accounts | Donut / Pie Chart | Most frequently attacked usernames under brute force. |
| **6** | Logon Failure Reasons Breakdown | Horizontal Bar | Decoded Windows SubStatus NTSTATUS error codes. |
| **7** | Suspicious Login Detection | Data Audit Table | Detailed table showing Timestamp, User, Source IP, Severity, and Reason. |

---

## 8. Demonstration Procedure for Project Evaluation (Viva Voce)

Follow this 5-minute step-by-step demonstration during your practical exam:

1. **Architecture & Healthcheck (1 min)**:
   - Open PowerShell and run: `powershell -ExecutionPolicy Bypass -File .\scripts\test-pipeline.ps1`
   - Show that Elasticsearch (9200), Kibana (5601), and Logstash (5044) are all healthy.
   - Explain the single-node architecture, JVM memory optimization, and zero-trust port isolation.

2. **Kibana SOC Dashboard Walkthrough (2 mins)**:
   - Open `http://127.0.0.1:5601/app/dashboards#/view/soc-threat-dashboard`.
   - Walk the examiner through the 7 panels.
   - Highlight how SubStatus `0xC000006A` is translated into *"Bad Password / Invalid Credentials"* and `0xC0000064` into *"User Account Does Not Exist"*.

3. **Live Threat Ingestion Demonstration (1.5 mins)**:
   - In PowerShell, run: `powershell -ExecutionPolicy Bypass -File .\scripts\simulate-threat-events.ps1 -Count 5`
   - Switch back to Kibana and click the **Refresh** button (top right).
   - Show the examiner that the metric counter increases immediately, new target usernames appear in the pie chart, and new events populate the audit table.

4. **Zero-Trust Cloudflare Remote Access (30 secs)**:
   - Show the active HTTPS TryCloudflare URL in `docker logs cloudflared`.
   - Explain how remote access is secured without exposing port 9200 to the public internet.

---

## 9. Troubleshooting & Common Fixes

### A. "Could not find the data view: -" Error
- **Cause**: Visualization saved objects lacked an `indexRefName` link to the active data view ID.
- **Fix**: Run `powershell -ExecutionPolicy Bypass -File .\kibana\setup_kibana_dashboard.ps1`. The script dynamically queries the active Data View ID and rebuilds all panels with zero dangling references.

### B. Docker Daemon Not Reachable (`//./pipe/dockerDesktopLinuxEngine`)
- **Cause**: Docker Desktop background process is not running.
- **Fix**: Launch Docker Desktop from the Start menu or execute:
  ```powershell
  Start-Process "C:\Users\ASUS\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe"
  ```
  Wait 20 seconds for the engine to initialize before launching `docker compose`.

### C. Execution Policy Error (`running scripts is disabled on this system`)
- **Cause**: Windows PowerShell default security restriction.
- **Fix**: Always include `-ExecutionPolicy Bypass` when running `.ps1` scripts:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\<script-name>.ps1
  ```

---

## 10. Known Limitations

1. **Single-Node Elasticsearch Deployment**: Configured as a single-node cluster (`discovery.type=single-node`) for evaluation on a single workstation; production deployments use multi-node quorum clusters.
2. **Ephemeral Quick Tunnels**: Free Cloudflare Quick Tunnels (`trycloudflare.com`) generate a new random domain upon container restart. For permanent domain mapping, a named Cloudflare Tunnel with an API token is used.
3. **Beats Execution Context**: Winlogbeat reading the Windows Security event log requires administrative privileges to query kernel-level security audits directly.
