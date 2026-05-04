# Day 01 – SOC Tier 1 Incident Report: SSH Brute Force Detection (Splunk)

---

## Incident Summary

- **Incident Type:** SSH Brute Force Attack
- **Severity:** High
- **Detection Method:** Splunk SIEM Log Analysis
- **Tools Used:** Splunk Enterprise, Ubuntu Server, Kali Linux (Hydra)
- **Status:** Detected and Analyzed (No Confirmed Compromise)

---

## Executive Summary

>A brute force attack targeting SSH services was detected using Splunk SIEM. The attacker attempted to gain unauthorized access by generating multiple failed login attempts from a single source IP within a short timeframe.

>The activity was identified through log aggregation and pattern analysis of authentication logs ingested into Splunk.

---

## Affected System

- **Target System:** Ubuntu Server (SSH Enabled)
- **Attack Source:** Kali Linux (Simulated Attacker)
- **Log Source:** `/var/log/auth.log`
- **SIEM Platform:** Splunk Enterprise  

---

## Investigation Methodology

---

### 1. Environment Setup

![Setup](./images/01_setup.png)

- Configured SSH service on Ubuntu target system  
- Created user accounts for authentication testing  
- Installed and configured Splunk Enterprise  
- Enabled log forwarding using Splunk Universal Forwarder  

---

### 2. Attack Simulation

![Attack](./images/02_attack.png)

- Performed SSH brute force attack using Hydra  
- Generated multiple failed login attempts  
- Targeted valid and invalid user accounts  

---

### 3. Log Ingestion

![Log Ingestion](./images/03_ingestion.png)

- Ingested `/var/log/auth.log` into Splunk  
- Verified logs using:

```spl id="ingestioncheck"
index=main
````

* Confirmed visibility of authentication events

---

## Detection Analysis

---

### 4. Brute Force Detection Logic

A brute force attack is identified when:

* Multiple failed login attempts occur
* Attempts originate from a single IP
* Activity occurs within a short timeframe

---

### 5. Splunk Detection Query

![Detection](./images/04_detection.png)

```spl id="bruteforcequery"
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| where failed_attempts > 3
| sort - failed_attempts
```

### SOC Observations:

* Extracted source IP addresses from logs
* Aggregated failed login attempts per IP
* Identified top offending IP responsible for attack

---

## Investigation Findings

---

### 6. Event Investigation

![Investigation](./images/05_investigation.png)

* Identified high volume of failed login attempts from a single IP
* Observed rapid sequence of authentication failures
* Checked for successful login attempts after failures
* Confirmed attack behavior consistent with brute force activity

---

## Indicators of Compromise (IOCs)

* High number of failed SSH login attempts
* Repeated authentication attempts from single source IP
* Rapid login attempts within short time interval
* Targeting of valid user accounts

---

## MITRE ATT&CK Mapping

| Behavior                | Technique ID | Description       |
| ----------------------- | ------------ | ----------------- |
| Brute Force Login       | T1110.001    | Password Guessing |
| Remote Service Access   | T1021.004    | SSH               |
| Valid Account Targeting | T1078        | Account Abuse     |

---

## SOC Analyst Findings

* Confirmed SSH brute force attack activity
* Single source IP responsible for repeated login attempts
* No successful compromise detected during attack window
* Attack indicates reconnaissance and credential access attempt

---

## SOC Analyst Response

* Monitor repeated authentication failures in real-time
* Block or blacklist offending IP address
* Enable alerting rules in Splunk for brute force detection
* Enforce account lockout policies
* Review authentication logs for any future successful login attempts

---

## Analyst Insight

> Brute force attacks rely on automation to exploit weak authentication mechanisms. SIEM tools like Splunk enable early detection through log aggregation and pattern recognition, allowing SOC analysts to respond before compromise occurs.

---

## Learning Outcome

This investigation demonstrates the ability to:

* Ingest and analyze logs in Splunk
* Detect brute force attacks using SPL queries
* Identify malicious patterns in authentication logs
* Perform SOC-style investigation and reporting
* Map attack behavior to MITRE ATT&CK framework





## SPL Quick Reference — SOC Analyst Edition

## Core Commands
| Command | Purpose | Example |
|---------|---------|---------|
| search | Filter events | search "Failed password" |
| stats | Aggregate data | stats count by src_ip |
| rex | Extract fields | rex "from (?<ip>\d+\.\d+)" |
| eval | Create fields | eval hour=strftime(_time,"%H") |
| where | Filter results | where count >= 5 |
| sort | Order results | sort -count |
| timechart | Time-based chart | timechart count by status |
| bucket | Group by time | bucket _time span=60s |
| table | Display columns | table src_ip, count, alert |
| dedup | Remove duplicates | dedup src_ip |

## Common SOC SPL Patterns

### Count failed logins by IP
index=main "Failed password"
| stats count by src_ip
| sort -count

### Find brute force in 60s window
index=main "Failed password"
| bucket _time span=60s
| stats count by src_ip, _time
| where count >= 5

### Extract IPs with regex
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"

### Time-based filtering
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18

---




## Repository Structure

```
├── README.md
├── images/
│   ├── 01_setup.png
│   ├── 02_attack.png
│   ├── 03_ingestion.png
│   ├── 04_detection.png
│   ├── 05_investigation.png
│   ├── 06_incident_report.png
├── logs.txt
├── splunk_queries.md
```

---

## Conclusion

This investigation demonstrates how SSH brute force attacks can be effectively detected using Splunk SIEM. By analyzing authentication logs and identifying abnormal login patterns, SOC analysts can detect and respond to credential-based attacks before system compromise occurs.

```
