# SOC Login Threat Investigation

## Project Overview

This project uses Python to analyse simulated authentication logs and identify potentially suspicious login activity.

The aim is to demonstrate basic Security Operations Centre (SOC) investigation techniques, including identifying repeated failed login attempts and unusual authentication records.

## Tools and Technologies

- Python
- Visual Studio Code
- CSV log files
- GitHub

## Project Objectives

- Read and analyse authentication logs.
- Identify repeated failed login attempts.
- Flag inconsistent MFA records.
- Generate alerts for further investigation.
- Practise basic security monitoring and incident investigation.

## Detection Rules

### Rule 1: Repeated Failed Login Attempts

The script counts failed login attempts for each username and source IP address.

- Threshold: 5 or more failed attempts.
- Alert: Possible brute-force activity.
- Reason: Repeated failed authentication attempts may indicate password guessing.

### Rule 2: MFA Inconsistency

The script checks for successful login events where the MFA status is recorded as FAILED.

- Alert: MFA inconsistency.
- Reason: The authentication records appear inconsistent and require further investigation.

## Investigation Results

The script identified:

- 5 failed login attempts for user `j.smith` from `192.0.2.10`.
- An MFA inconsistency for user `j.smith` from `198.51.100.25`.

These findings are indicators for investigation, not confirmation of a successful attack.

## Limitations

- The project uses simulated authentication logs.
- The failed login threshold is based on total counts, not a time window.
- The script does not verify whether the activity is malicious.
- Additional information, such as device details and previous login history, would help an analyst investigate further.