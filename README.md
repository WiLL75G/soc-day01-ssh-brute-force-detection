# Day 01 – SSH Brute Force Detection (Splunk)

## 🧠 Objective
The goal of this project is to detect SSH brute force attacks by analyzing login failure patterns in log data.

---

## 🔍 What is an SSH Brute Force Attack?
An SSH brute force attack happens when an attacker tries multiple password combinations to gain unauthorized access to a system.

---

## 🛠️ Tools Used
- Splunk (or log analysis tool)
- Sample SSH log data

---

## 📊 What I Did
- Collected SSH login logs
- Filtered failed login attempts
- Identified repeated login failures from same IP
- Flagged suspicious activity

---

## 🚨 Detection Rule (Simple Logic)
If:
- Multiple failed login attempts
- From same IP
- Within short time

Then:
👉 Possible brute force attack

---

## 📌 Findings
- Suspicious IP detected: 192.168.1.10 (example)
- Multiple failed login attempts observed
- Possible brute force behavior identified

---

## 🧾 SOC Analyst Insight
As a SOC analyst, this type of detection helps prevent unauthorized access before attackers succeed.

---

## 📁 Files in this repo
- logs.txt
- findings.md
- README.md
