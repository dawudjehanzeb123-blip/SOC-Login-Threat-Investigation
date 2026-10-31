# SOC Login Threat Investigation Report

## 1. Investigation Summary

- Total events analysed: 8
- Security findings: 2
- Failed login events: 5

## 2. Security Findings

### MFA INCONSISTENCY
- Time: 2026-10-30 09:02:00
- Details: j.smith from 198.51.100.25

### POSSIBLE BRUTE-FORCE ACTIVITY
- Time: 2026-10-30 09:00:00
- Details: j.smith from 192.0.2.10: 5 failed attempts within five minutes

## 3. Event Timeline

| Time | Username | Source IP | Event | MFA status |
|---|---|---|---|---|
| 09:00:00 | j.smith | 192.0.2.10 | FAILED_LOGIN | NOT_APPLICABLE | First event |
| 09:00:15 | j.smith | 192.0.2.10 | FAILED_LOGIN | NOT_APPLICABLE | 15 seconds |
| 09:00:30 | j.smith | 192.0.2.10 | FAILED_LOGIN | NOT_APPLICABLE | 15 seconds |
| 09:00:45 | j.smith | 192.0.2.10 | FAILED_LOGIN | NOT_APPLICABLE | 15 seconds |
| 09:01:00 | j.smith | 192.0.2.10 | FAILED_LOGIN | NOT_APPLICABLE | 15 seconds |
| 09:02:00 | j.smith | 198.51.100.25 | SUCCESSFUL_LOGIN | FAILED | 60 seconds |
| 09:03:00 | j.smith | 198.51.100.25 | FILE_ACCESS | NOT_APPLICABLE | 60 seconds |
| 09:04:00 | j.smith | 198.51.100.25 | FILE_DOWNLOAD | NOT_APPLICABLE | 60 seconds |

## 4. Recommended Investigation Steps

- Verify whether the failed login attempts were legitimate.
- Review account and authentication history.
- Investigate the MFA inconsistency and authentication logs.
- Check which files were accessed and downloaded.
- Confirm whether the activity belongs to the same user session.

## 5. Limitations

- The dataset contains simulated authentication events.
- The detection rules identify indicators, not confirmed attacks.
- No device, session, file-name or geographic context is available.
- The five-minute threshold is a demonstration rule, not a universal security standard.

## 6. Conclusion

The investigation identified repeated failed login attempts, an MFA inconsistency, and subsequent file activity. Further investigation is required before determining whether any malicious activity occurred.