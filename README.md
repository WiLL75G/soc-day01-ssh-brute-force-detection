# SSH Brute Force Detection with Splunk

Detecting SSH brute force activity in Splunk using Linux authentication logs and investigating whether a successful login followed.

![SSH Brute Force Detection Architecture](./images/00_architecture.png)

The lab follows the activity from Kali Linux to the Ubuntu SSH server. Authentication logs are then sent to Splunk for detection and investigation.

## At a Glance

| Area | Details |
|---|---|
| Attack Type | SSH brute force |
| Detection Platform | Splunk Enterprise |
| Log Source | `/var/log/auth.log` |
| Target | Ubuntu Server with SSH enabled |
| Attack Source | Kali Linux running Hydra |
| Outcome | Attack detected. No successful login from the source was observed during the investigated window |
| MITRE ATT&CK | T1110.001 (Password Guessing) |

## What This Is

This project is a controlled SOC lab that demonstrates how repeated SSH authentication failures can be detected and investigated using Splunk.

The goal was not only to find the failed logins. I also wanted to determine whether the activity was followed by a successful authentication.

## Objective

The investigation focused on three questions.

1. Were repeated SSH authentication failures visible in Splunk?
2. Which source generated the activity?
3. Did a successful login from the same source follow the failures?

## Environment

The lab used an Ubuntu server with SSH enabled as the target.

Kali Linux was used to generate the authentication attempts with Hydra.

Splunk Enterprise was used to search and investigate the Linux authentication events.

![Ubuntu SSH Setup](./images/01_setup.png)

**Verdict:** The Ubuntu server was ready to generate SSH authentication telemetry for the investigation.

## Attack Simulation

Hydra was used from Kali Linux to generate repeated SSH authentication attempts against the Ubuntu server.

This created the failed authentication activity needed for the investigation.

![SSH Attack Simulation](./images/02_attack.png)

**Verdict:** Repeated SSH authentication attempts were generated against the Ubuntu server in the controlled lab.

## Log Ingestion

The Ubuntu authentication log was collected for analysis in Splunk.

The main log source used for the investigation was:

```text
/var/log/auth.log
```

I first confirmed that the authentication events were reaching Splunk.

```spl
index=main
```

![Splunk Log Ingestion](./images/03_ingestion.png)

This validation mattered because detection logic is only useful when the underlying telemetry is available and searchable.

**Verdict:** Linux authentication events were successfully available in Splunk for analysis.

## Detection

I searched the authentication data for failed SSH password events.

```spl
index=main "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| where failed_attempts > 3
| sort - failed_attempts
```

### Why This Search Works

`"Failed password"` isolates failed SSH authentication events.

`rex` extracts the source IP address from the raw event.

`stats` groups the failed attempts by source.

The threshold then keeps sources responsible for more than three failed authentication attempts.

![SSH Brute Force Detection](./images/04_detection.png)

**Verdict:** Splunk identified a source responsible for repeated failed SSH authentication attempts.

## Investigation

Detection was only the beginning of the investigation.

After identifying the repeated failures, I checked the same authentication data for evidence of a successful login from the source.

This helped answer the more important question.

Did the password guessing lead to successful authentication?

![SSH Investigation](./images/05_investigation.png)

The investigation found repeated failed authentication attempts from the source.

No successful authentication from that source was observed during the investigated attack window.

**Verdict:** SSH password guessing was observed, but the available authentication evidence did not show a successful login from the source during the investigated period.

## Indicators and Findings

| Indicator | Finding |
|---|---|
| Source IP | `192.168.64.15` |
| Target Service | SSH |
| Port | TCP 22 |
| Authentication Pattern | Repeated failed password attempts |
| Successful Login | Not observed from the source during the investigated window |
| Analysis Platform | Splunk Enterprise |

## MITRE ATT&CK

### T1110.001 (Password Guessing)

The observed behavior maps to Password Guessing because repeated authentication attempts were made against the SSH service.

The project does not claim successful use of valid credentials because the investigation did not observe a successful authentication from the attacking source during the investigated period.

## Analyst Conclusion

The evidence supports SSH password guessing against the Ubuntu server.

Repeated failed authentication attempts were observed from the source and detected in Splunk.

The investigation then checked whether a successful authentication followed.

No successful authentication from that source was observed during the investigated window.

This means the evidence supports an attempted credential attack, but it does not establish that the source successfully authenticated to the server.

## Incident Report

After completing the investigation, I documented the findings in a short SOC incident report.

The report records the activity, evidence, investigation findings, impact, and recommended response.

[View the full incident report](./ssh_brute_force_incident_report.pdf)

![SSH Brute Force Incident Report](./images/06_incident_report.png)

**Verdict:** The technical investigation was documented in a report that another analyst or security team could review.

## Recommended Response

For similar activity in a real environment, I would:

1. Validate whether the source IP is expected.
2. Review successful authentication events around the same period.
3. Check the targeted accounts for suspicious activity.
4. Block the source if the activity is confirmed as unauthorized.
5. Review whether password authentication should remain enabled.
6. Consider stronger authentication controls.
7. Create and tune a Splunk alert for repeated SSH authentication failures.

## The SOC Angle

A SOC analyst should not stop after finding repeated failed logins.

The next question is whether the activity had an impact.

That means checking what happened before the detection, during the activity, and after it.

In this investigation, the important follow up was checking whether the same source later authenticated successfully.

## Lessons Learned

Detection starts with trustworthy telemetry.

Before building the SPL search, the authentication events had to be visible in Splunk and the source IP had to be available for analysis.

Finding repeated failures confirms password guessing activity, but checking for successful authentication helps determine the outcome.

The main lesson was simple.

Detect the behavior, then investigate its impact.

## What I Would Improve

In the next version, I would make the detection aware of timing instead of only counting failed logins by source.

I would group failures into short time windows and test the threshold against normal SSH activity before turning the search into a Splunk alert.

I would also correlate repeated failures with any later successful authentication from the same source.

This would make the detection more useful during a real investigation.

## What This Demonstrates

This project demonstrates my ability to:

* Validate security telemetry before building a detection
* Investigate Linux authentication activity in Splunk
* Extract useful fields from raw events
* Build simple SPL detection logic
* Identify repeated authentication failures
* Investigate what happened after a detection
* Map observed behavior to MITRE ATT&CK
* Separate observed evidence from assumptions
* Document investigation findings in an incident report
* Communicate a defensible analyst conclusion

## Repository Structure

```text
soc-day01-ssh-brute-force-detection/
├── README.md
├── ssh_brute_force_incident_report.pdf
└── images/
    ├── 00_architecture.png
    ├── 01_setup.png
    ├── 02_attack.png
    ├── 03_ingestion.png
    ├── 04_detection.png
    ├── 05_investigation.png
    └── 06_incident_report.png
```

## Author

William Gokah

SOC Analyst Portfolio

[![LinkedIn](https://img.shields.io/badge/LinkedIn-WilliamInCyber-blue?style=flat&logo=linkedin)](https://linkedin.com/in/WilliamInCyber) [![X](https://img.shields.io/badge/X-WilliamInCyber-black?style=flat&logo=x)](https://x.com/WilliamInCyber)
