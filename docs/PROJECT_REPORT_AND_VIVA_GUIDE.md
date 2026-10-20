# MCA Major Project Documentation & Viva Voce Defense Guide

## Project Title
**Design and Implementation of a Centralized Log Monitoring and Threat Detection System using ELK Stack**

---

## 1. Project Overview & Abstract

In modern enterprise computing environments, distributed heterogeneous endpoints (Windows workstations, Active Directory domain controllers, and Linux servers) generate enormous volumes of security and system audit logs. Detecting cyber threats such as brute-force authentication attacks, privilege escalations, and unauthorized access in real-time requires centralized log aggregation, structured parsing, and automated alert triggering.

This project delivers a containerized, production-grade Security Operations Center (SOC) telemetry pipeline using the **Elastic (ELK) Stack (v8.11.3)**:
- **Elasticsearch 8.11**: Distributed indexing, document storage, and analytical search engine.
- **Logstash 8.11**: Event enrichment pipeline performing Grok pattern matching, classification of Windows Security Event ID 4625 (Logon Failures) and Linux SSH authentication failures, and metadata tagging.
- **Kibana 8.11**: Interactive visual analytics platform presenting threat metrics, attack timelines, targeted username breakdowns, and brute-force alerting rules.
- **Beats Agents**:
  - **Winlogbeat**: Endpoint agent streaming Windows Security and System channel logs directly to Logstash.
  - **Filebeat**: Linux agent streaming `/var/log/auth.log` and `/var/log/secure`.
- **Cloudflare Zero Trust Tunnel**: Edge-terminated TLS 1.3 reverse proxy providing a secure, public HTTPS URL for remote Kibana access without opening inbound firewall ports or exposing Elasticsearch to the public internet.

---

## 2. Technical Architecture & Data Pipeline

```
+-------------------------------------------------------------------------+
|                           ENDPOINTS / AGENTS                            |
|                                                                         |
|  [Windows Endpoint]                            [Linux Endpoint]         |
|  - Security Log (ID 4625, 4624)                - /var/log/auth.log      |
|  - System Log (Errors)                         - /var/log/secure        |
|          |                                              |               |
|    [Winlogbeat]                                   [Filebeat]            |
+----------|----------------------------------------------|---------------+
           |                                              |
           +--------------------+-------------------------+
                                | Beats Protocol (Port 5044)
                                v
+-------------------------------------------------------------------------+
|                       DOCKER CONTAINER NETWORK                          |
|                                                                         |
|  [Logstash Pipeline] (:5044)                                            |
|  - Ingestion: Beats Input Plugin                                        |
|  - Normalization: Event ID 4625 -> Failed Logon Tagging                 |
|  - Enrichment: Extract TargetUserName, IpAddress, SubStatus             |
|  - Severity: Flag as "HIGH" (Failed Logon) or "INFO" (Success)          |
|          |                                                              |
|          | HTTP REST API (Port 9200, Basic Auth: elastic)               |
|          v                                                              |
|  [Elasticsearch 8.11] (:9200 - Bound strictly to 127.0.0.1)             |
|  - Indices: elk-threats-YYYY.MM.dd                                      |
|  - Single-node Cluster, Memory-locked JVM (1 GB Heap)                   |
|          |                                                              |
|          v Internal Docker Bridge Network                               |
|  [Kibana 8.11] (:5601)                                                  |
|  - Dashboards, Data Views, Security Rules                               |
+----------|--------------------------------------------------------------+
           | Internal HTTP Proxy (:5601)
           v
+-------------------------------------------------------------------------+
|                       SECURE PUBLIC ACCESS LAYER                        |
|                                                                         |
|  [Cloudflare Tunnel (cloudflared container)]                            |
|  - Outbound TLS tunnel to Cloudflare Edge                               |
|  - Encrypted HTTPS URL (https://<subdomain>.trycloudflare.com)          |
|  - Zero inbound firewall ports opened                                   |
|  - Elasticsearch completely hidden from external network                |
+-------------------------------------------------------------------------+
```

---

## 3. Threat Detection Logic: Windows Event ID 4625

### What is Event ID 4625?
Windows Event ID 4625 is generated in the Security log whenever a logon request fails. It records:
- **TargetUserName**: The identity targeted by the actor (e.g., `Administrator`, `root`, `service_account`).
- **IpAddress**: The IPv4/IPv6 source address of the remote machine attempting authentication.
- **LogonType**:
  - `Type 2 (Interactive)`: Physical console or local interactive login.
  - `Type 3 (Network)`: SMB, IPC$, or remote network share connection.
  - `Type 10 (RemoteInteractive)`: Remote Desktop Protocol (RDP).
- **SubStatus**: 32-bit NTSTATUS code detailing the exact failure cause:
  - `0xC000006A`: User name is valid, but the password was incorrect.
  - `0xC0000064`: The user account does not exist.
  - `0xC0000234`: The account is locked out due to exceeding the maximum invalid password threshold.
  - `0xC0000072`: The account is currently disabled.

### Logstash Processing Snippet
```ruby
if [winlog][event_id] == 4625 or [event][code] == "4625" {
  mutate {
    add_field => {
      "event_action"    => "failed_logon"
      "threat_detected" => "Failed Login / Potential Brute Force"
      "threat_severity" => "HIGH"
      "threat_user"     => "%{[winlog][event_data][TargetUserName]}"
      "threat_source_ip"=> "%{[winlog][event_data][IpAddress]}"
    }
  }
}
```

---

## 4. Kibana Dashboards & Threat Analytics

The project includes pre-built Saved Objects (`kibana/threat_detection_dashboard.ndjson`) comprising:
1. **Total Failed Logons Metric**: Instant real-time counter of Event ID 4625 occurrences.
2. **Total Successful Logons Metric**: Counter of Event ID 4624 events for authentication baseline ratio.
3. **Attack Activity Timeline**: Date histogram tracking login velocity to pinpoint brute-force bursts.
4. **Top Targeted User Accounts**: Pie / Donut chart showing the most attacked usernames.
5. **Logon Failure Reasons**: Horizontal bar chart mapping SubStatus error codes (Bad Password vs. Non-existent User).

---

## 5. Repeated Failed-Logon Alerting

### Kibana Index Threshold Alert Rule
In Kibana (`Stack Management` -> `Rules and Alerts`):
- **Rule Type**: Index Threshold Rule.
- **Index Pattern**: `elk-threats-*`
- **When**: Count of documents where `event_action: "failed_logon"` is **GREATER THAN 5**.
- **Window**: Within **5 minutes**.
- **Action**: Generates an incident alert in Kibana Security / Incident Management and writes an alert log.

---

## 6. Security Analysis & Remote Deployment Compliance

| Requirement | Implementation in this Project | Cybersecurity Rationale |
| :--- | :--- | :--- |
| **No Public Elasticsearch** | Port `9200` bound to `127.0.0.1` and internal Docker network | Prevents ransomware attacks, unauthorized index wiping, and zero-day exploits. |
| **Encrypted Transit** | Cloudflare Edge TLS 1.3 Tunnel | Ensures confidentiality and integrity across public internet without self-signed certificate warnings. |
| **Authentication** | Native Elastic Stack Security (`xpack.security.enabled=true`) | Requires valid credentials (`elastic` or RBAC users) to view any log data. |
| **Resource Constraints** | JVM capped to 1 GB ES / 512 MB Logstash | Prevents Denial-of-Service / host lockup on 8 GB RAM machines. |

---

## 7. Viva Voce Defense: Expected Questions & Model Answers

### Q1: Why did you use Logstash instead of shipping directly from Beats to Elasticsearch?
> **Answer**: While Beats can write directly to Elasticsearch via Ingest Node pipelines, Logstash provides an enterprise-grade ETL (Extract, Transform, Load) engine with dedicated buffering, advanced conditional branching, custom Grok parsers for non-standard formats (such as custom Linux auth patterns), and the ability to route alerts to multiple independent destinations (Elasticsearch, Syslog, Webhooks) simultaneously.

### Q2: How does your system differentiate a benign typo from an automated brute-force attack?
> **Answer**: An isolated typo generates a single Event ID 4625 with `SubStatus 0xC000006A` for a known account. An automated brute-force attack exhibits a distinct signature: rapid spikes of Event ID 4625 across multiple non-existent usernames (`0xC0000064`) or repeated failures against high-value accounts (`admin`, `root`) within a narrow timeframe. Our Kibana threshold rule triggers when failed logins exceed 5 occurrences within a 5-minute window.

### Q3: Why is exposing Elasticsearch directly to the public internet dangerous?
> **Answer**: Publicly exposed Elasticsearch clusters are primary targets for automated shodan bots and ransomware. Attackers can execute automated indices deletion (`DELETE /*`), exfiltrate confidential enterprise telemetry, or exploit unauthenticated endpoints. By binding Elasticsearch strictly to `127.0.0.1` and exposing only Kibana through Cloudflare's authenticated TLS tunnel, we enforce zero-trust network isolation.

### Q4: How is memory managed to allow ELK to run on a standard 8 GB RAM laptop?
> **Answer**: By default, Elasticsearch attempts to claim 50% of total host RAM. We explicitly tuned Java Virtual Machine heap options using `ES_JAVA_OPTS="-Xms1024m -Xmx1024m"` for Elasticsearch, `LS_JAVA_OPTS="-Xms512m -Xmx512m"` for Logstash, and limited Kibana's Node.js heap to 512 MB via `--max-old-space-size=512`. This keeps the total container footprint under 3.5 GB, leaving 4.5 GB for the Windows host operating system.
