# 🔐 SSH Brute-Force Detection with Splunk

A SOC detection project built in a home lab using Splunk SIEM.

---

## 📋 Executive Summary

Simulated an SSH brute-force attack and detected it using Splunk SIEM.

**SOC Workflow:** 📥 Ingestion → 🔍 Detection → 🕵️ Investigation → 📝 Reporting

---

## 🎯 Objective

Detect SSH brute-force activity in Splunk and document the investigation the way a real SOC analyst would.

---

## 🏗️ Architecture

![Architecture](architecture_diagram.png)

**Flow:** Attacker (Kali) → Target (Ubuntu SSH) → Splunk SIEM → SOC Analyst

---

## 🛠️ Tools & Environment

- **SIEM:** Splunk Enterprise
- **Target:** Ubuntu Server (SSH)
- **Attacker:** Kali Linux + Hydra
- **Logs:** `/var/log/auth.log`

---

## ⚔️ Attack Scenario

- **Attacker IP:** `192.168.1.105`
- **Target:** Ubuntu SSH server (`root` and other accounts)
- **Action:** Repeated failed SSH login attempts
- **Outcome:** Fully detected in Splunk

---

## 📥 Log Ingestion

SSH authentication logs forwarded into Splunk under `index=main`.

![Log Ingestion](splunk_log_ingestion_preview.png)

---

## 🔍 Detection Rules

### 🚨 Rule 1 — Multiple Failed Logins

```spl
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| where failed_attempts > 3
| sort - failed_attempts
```

📸 ![Rule 1](rule1_failed_attempts.png)

👉 **Insight:** More than 3 failures from one IP = brute-force.

---

### ✅ Rule 2 — Success After Failures

```spl
index=main ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(searchmatch("Failed password"))) as failed,
        count(eval(searchmatch("Accepted password"))) as success
        by src_ip
| where failed > 3 AND success > 0
```

📸 ![Rule 2](rule2_success_after_fail.png)

👉 **Insight:** Failures followed by a success = likely compromise.

---

### 👑 Rule 3 — Root Account Targeting

```spl
index=main "root"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
```

📸 ![Rule 3](rule3_root_attempts.png)

👉 **Insight:** Any attempt on `root` from an unknown IP is suspicious.

---

### 🌐 Rule 4 — Suspicious IP Activity

```spl
index=main "sshd"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort - count
```

📸 ![Rule 4](rule4_ip_activity.png)

👉 **Insight:** One IP hitting SSH repeatedly = attacker behavior.

---

## 🎯 MITRE ATT&CK Mapping

| Behavior | Technique | Description |
|---|---|---|
| Failed SSH password attempts | **T1110.001** — Brute Force: Password Guessing | Attacker guessed passwords repeatedly |
| Targeting the `root` account | **T1078.003** — Valid Accounts: Local | Attempted abuse of a privileged account |
| Successful login after failures | **T1078** — Valid Accounts | Valid credentials used after guessing |
| SSH as entry vector | **T1021.004** — Remote Services: SSH | SSH used to access the target system |

---

## 📌 Key Findings

- **Attacker IP:** `192.168.1.105`
- **Attack Type:** SSH Brute-Force
- **Target Account:** `root`
- **Result:** Detected by all 4 Splunk rules

---

## 📝 Incident Summary

- **Incident Type:** SSH Brute-Force Attack
- **Severity:** 🔴 High
- **Detection Source:** Splunk SIEM (custom SPL rules)
- **Outcome:** Attack fully detected and documented

![Incident Report](incident_report_splunk_soc_investigation.png)

---

## 🛡️ Recommendations

- Disable direct `root` SSH login
- Enforce SSH key-based auth + MFA
- Deploy **Fail2ban** to auto-block brute-force IPs
- Set real-time Splunk alerts for Rule 2 (success after failures)

---

## 🧠 Skills Demonstrated

- Splunk SIEM operations
- SPL query writing
- Log analysis & correlation
- Threat detection engineering
- MITRE ATT&CK mapping
- SOC incident reporting

---

## 🏁 Conclusion

This project shows how a SOC analyst detects SSH brute-force attacks using Splunk — proving hands-on skill in log analysis, detection engineering, and incident reporting. These are the core day-one skills of a Blue Team SOC analyst.
