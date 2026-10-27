SOC Analyst L1 Home Lab: Windows Log Monitoring & Incident Investigation

1. Project Overview

A practical Security Operations Center (SOC) lab demonstrating Windows security log analysis, SIEM monitoring, detection queries, alert triage, and incident investigation.

2. Objectives

- Analyse Windows Security Event Logs.
- Investigate successful and failed logons.
- Examine process creation and suspicious activity.
- Use Splunk SPL for event searches and correlation.
- Develop basic security detections.
- Produce structured incident investigation reports.

3. Tools and Technologies

- Splunk
- Windows Event Viewer
- Microsoft Sysmon
- Windows Security Logs
- Wireshark
- GitHub

4. Repository Structure

- "01-Windows-Event-Logs/" — Event ID reference and analysis
- "02-Sysmon/" — Sysmon event notes
- "03-Splunk-SPL/" — Search and detection queries
- "04-Investigation-Reports/" — Incident reports
- "05-Screenshots/" — Lab evidence
- "docs/" — Setup guides and learning resources

5. Investigation Scenarios

1. Failed logon investigation — Event ID 4625
2. Successful logon review — Event ID 4624
3. Process creation analysis — Event ID 4688
4. Suspicious PowerShell activity
5. Repeated failed logons followed by a successful login
6. Alert triage and incident documentation

6. Investigation Methodology

1. Identify the alert.
2. Review timestamps, host, account, and source IP when available.
3. Search for related events.
4. Correlate evidence and assess suspicious behaviour.
5. Document findings and possible false positives.
6. Recommend next investigative or containment steps.

7. Learning Outcomes

- Windows event analysis
- SIEM search fundamentals
- Splunk SPL
- Log correlation
- Alert triage
- Incident documentation

8. References

- https://www.splunk.com/en_us/training/free-courses/overview.html
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688

Disclaimer

This project is intended for educational use in an authorised lab environment. All findings and results should be based on actual practice and documented evidence.
