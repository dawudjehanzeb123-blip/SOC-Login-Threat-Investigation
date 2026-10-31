# SOC Login Threat Investigation

## 1. Project Overview

This project uses Python to analyse simulated authentication logs and identify potentially suspicious login activity.

It demonstrates basic Security Operations Centre (SOC) investigation techniques, including authentication monitoring, time-based detection, event correlation and incident reporting.

The project simulates how a SOC analyst might investigate suspicious login patterns and document their findings.

## 2. Tools and Technologies

- Python
- Visual Studio Code
- CSV log files
- Git and GitHub

## 3. Project Objectives

- Read and analyse authentication log files using Python.
- Identify repeated failed login attempts.
- Detect unusual authentication and MFA records.
- Analyse timestamps and event intervals.
- Build a chronological investigation timeline.
- Correlate related security events.
- Automatically generate an incident investigation report.

## 4. Detection Rules

### Rule 1: Repeated Failed Login Attempts

The script identifies repeated failed login attempts associated with the same username and source IP address.

- Detection threshold: 5 or more failed attempts.
- Time window: 5 minutes.
- Alert: Possible brute-force activity.
- Reason: Repeated failed authentication attempts within a short period may indicate password guessing.

### Rule 2: MFA Inconsistency

The script identifies successful login events where the MFA status is recorded as FAILED.

- Alert: MFA inconsistency.
- Reason: The authentication records appear inconsistent and require further investigation.

This finding does not prove that MFA was bypassed.

## 5. Timestamp Analysis and Event Timeline

The script processes timestamps and sorts events chronologically.

It also calculates the time difference between consecutive events.

This helps an analyst understand the sequence and timing of suspicious activity.

## 6. Event Correlation

The investigation compares authentication events and subsequent file activity.

It examines:

- Source IP addresses.
- Usernames.
- Event types.
- Event timestamps.
- The sequence of authentication and file activity.

The available simulated logs do not establish whether the events belong to the same authenticated session. Further investigation would require additional session and device information.

## 7. Investigation Findings

The simulated dataset contains 8 events.

The investigation identified:

**Finding 1: Repeated failed logins**
- Username: j.smith
- Source IP: 192.0.2.10
- Failed attempts: 5
- Time period: 09:00:00–09:01:00
- Detection: Possible brute-force activity.

**Finding 2: MFA inconsistency**
- Username: j.smith
- Source IP: 198.51.100.25
- Event: SUCCESSFUL_LOGIN
- MFA status: FAILED
- Time: 09:02:00
- Detection: Inconsistent authentication records.

The dataset also records file access at 09:03:00 and file download at 09:04:00 from the same source IP as the successful login.

These findings require further investigation and do not confirm a successful attack.

## 8. Automated Incident Report

The Python script automatically generates an `incident_report.md` file.

The report includes:

- Investigation summary.
- Number of events analysed.
- Security findings and alerts.
- Chronological event timeline.
- Time differences between events.
- Recommended investigation steps.
- Event correlation.
- Investigation limitations.
- Conclusion.

## 9. Recommended Investigation Steps

- Verify whether the failed login attempts were legitimate.
- Review account and authentication history.
- Investigate the MFA inconsistency.
- Check which files were accessed and downloaded.
- Review session identifiers and device information.
- Determine whether the recorded activity was authorised.

## 10. Project Limitations

- The project uses simulated authentication logs.
- Detection rules use demonstration thresholds, not universal security standards.
- The script cannot independently confirm malicious activity.
- The dataset does not contain device details, session identifiers or file names.
- Different source IP addresses cannot be assumed to belong to the same person.
- Time differences show event ordering but do not establish causation.

## 11. How to Run the Project

Make sure Python is installed.

Open the project folder in Visual Studio Code and run:

```bash
python scripts/log_analyser.py
```

The script analyses the authentication logs and generates the incident report in the main project folder.

## 12. Conclusion

This project demonstrates basic Python-based security log analysis and SOC investigation techniques.

It explores how repeated authentication failures, unusual MFA records and subsequent file activity can be identified and documented.

The project has helped develop practical skills in Python, security monitoring, timestamp analysis, event correlation and incident reporting.

**Project status:** Initial portfolio project completed. Further improvements and testing are ongoing.