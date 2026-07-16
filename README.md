# SSH Brute Force Detection with Splunk

Detecting a live SSH brute force attack in Splunk by parsing authentication logs, extracting source IPs, and proving no compromise followed.

## At a Glance

| Field | Detail |
| --- | --- |
| Attack Type | SSH brute force |
| Detection Platform | Splunk Enterprise |
| Log Source | /var/log/auth.log |
| Target | Ubuntu Server, SSH enabled |
| Attack Source | Kali Linux running Hydra |
| Outcome | Attack detected, no successful login observed in the attack window |

## What Happened

An automated password guessing attack was run against the SSH service on the Ubuntu server. Authentication logs were forwarded into Splunk, where the attack was identified by the pattern that defines brute force behaviour: many failed logins, one source IP, a short time window.

The point of the lab was not to prove an attack happened. It was to prove the attack could be seen in the logs, measured, and closed out with evidence either way.

## Environment Setup

![Setup](./images/01_setup.png)

SSH service enabled on the Ubuntu target. Test user accounts created. Splunk Enterprise installed, with the Splunk Universal Forwarder shipping the auth log to the indexer.

## Attack Simulation

![Attack](./images/02_attack.png)

Hydra was run from Kali against the SSH service. It generated repeated failed login attempts against both valid and invalid usernames, so the log data would contain the two cases a real analyst has to tell apart.

## Log Ingestion

![Log Ingestion](./images/03_ingestion.png)

The auth log was ingested and verified before any detection work started. If the data is not there, the query is meaningless.

```spl
index=main
```

Authentication events confirmed visible in the index.

## Detection Logic

Brute force is a pattern, not a single event. The evidence needed is:

Multiple failed authentication attempts.

Originating from one source IP.

Occurring inside a short time window.

A single failed password is a typo. Forty of them in a minute is an attack.

## Detection Query

![Detection](./images/04_detection.png)

```spl
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| where failed_attempts > 3
| sort - failed_attempts
```

The rex command pulls the source IP out of the raw log line. Stats aggregates failures per IP, turning thousands of individual events into a ranked list. The where clause sets the threshold that separates noise from signal.

## Investigation Findings

![Investigation](./images/05_investigation.png)

The query returned one source IP responsible for a high volume of failed logins, delivered in rapid sequence.

The next step was the one that matters. The same log source was checked for successful logins from that IP after the failures. None were found. The attack ran, and it did not land.

That is the difference between "we saw something" and "we know what it did."

## Indicators Observed

High volume of failed SSH authentication events.

Repeated attempts from a single source IP.

Rapid attempt rate inside a short interval.

Valid user accounts targeted alongside invalid ones.

## MITRE ATT&CK Mapping

| Behaviour | Technique ID | Description |
| --- | --- | --- |
| Brute force login | T1110.001 | Password guessing |
| Remote service access | T1021.004 | SSH |
| Valid account targeting | T1078 | Valid accounts |

## Analyst Conclusion

SSH brute force activity confirmed from a single source IP.

No successful authentication from that IP during the attack window.

Behaviour consistent with a credential access attempt, not a completed compromise.

## Recommended Response

Block the offending source IP at the perimeter.

Build a scheduled Splunk alert on the detection query above so this fires without an analyst watching.

Enforce account lockout thresholds.

Continue monitoring the source IP for any later successful authentication.

## What This Lab Demonstrates

Ingesting and validating a log source in Splunk before trusting it.

Writing SPL that extracts fields and aggregates behaviour rather than matching single strings.

Reading authentication logs and separating an attack pattern from normal failure noise.

Closing an investigation on evidence, including the negative finding.

Mapping observed behaviour to MITRE ATT&CK.

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

[![LinkedIn](https://img.shields.io/badge/LinkedIn-WilliamInCyber-blue?style=flat&logo=linkedin)](https://linkedin.com/in/WilliamInCyber)
[![X](https://img.shields.io/badge/X-WilliamInCyber-black?style=flat&logo=x)](https://x.com/WilliamInCyber)
