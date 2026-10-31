
import csv
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ==========================================
# SOC LOGIN THREAT INVESTIGATION
# ==========================================

project_folder = Path(__file__).resolve().parent.parent
log_file = project_folder / "authentication_logs.csv"
report_file = project_folder / "incident_report.md"

events = []
failed_logins = defaultdict(list)
alerts = []

print("Starting SOC investigation...")

# ==========================================
# 1. READ AND PROCESS LOGS
# ==========================================

with open(log_file, "r", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        timestamp = datetime.strptime(
            row["timestamp"], "%Y-%m-%d %H:%M:%S"
        )

        event = {
            "timestamp": timestamp,
            "username": row["username"],
            "source_ip": row["source_ip"],
            "event_type": row["event_type"],
            "mfa_status": row["mfa_status"]
        }

        events.append(event)

        if event["event_type"] == "FAILED_LOGIN":
            key = (event["username"], event["source_ip"])
            failed_logins[key].append(timestamp)

        # MFA inconsistency detection
        if (
            event["event_type"] == "SUCCESSFUL_LOGIN"
            and event["mfa_status"] == "FAILED"
        ):
            alerts.append({
                "time": timestamp,
                "type": "MFA INCONSISTENCY",
                "details": (
                    f"{event['username']} from {event['source_ip']}"
                )
            })

# Sort all events chronologically
events.sort(key=lambda event: event["timestamp"])

# ==========================================
# 2. DETECT REPEATED FAILED LOGINS
# ==========================================

for (username, ip), timestamps in failed_logins.items():

    timestamps.sort()

    for start_index, start_time in enumerate(timestamps):
        end_time = start_time + timedelta(minutes=5)

        attempts = [
            time for time in timestamps
            if start_time <= time <= end_time
        ]

        if len(attempts) >= 5:
            alerts.append({
                "time": start_time,
                "type": "POSSIBLE BRUTE-FORCE ACTIVITY",
                "details": (
                    f"{username} from {ip}: "
                    f"{len(attempts)} failed attempts "
                    f"within five minutes"
                )
            })
            break


# ==========================================
# 3. BUILD INVESTIGATION TIMELINE
# ==========================================

timeline = []
previous_time = None

for event in events:

    current_time = event["timestamp"]

    if previous_time is None:
        time_difference = "First event"
    else:
        difference = current_time - previous_time
        time_difference = f"{difference.total_seconds():.0f} seconds"

    timeline.append(
        f"| {current_time.strftime('%H:%M:%S')} "
        f"| {event['username']} "
        f"| {event['source_ip']} "
        f"| {event['event_type']} "
        f"| {event['mfa_status']} "
        f"| {time_difference} |"
    )

    previous_time = current_time


# ==========================================
# 4. GENERATE INCIDENT REPORT
# ==========================================

report = [
    "# SOC Login Threat Investigation Report",
    "",
    "## 1. Investigation Summary",
    "",
    f"- Total events analysed: {len(events)}",
    f"- Security findings: {len(alerts)}",
    f"- Failed login events: {sum(len(v) for v in failed_logins.values())}",
    "",
    "## 2. Security Findings",
    ""
]

if alerts:
    for alert in alerts:
        report.extend([
            f"### {alert['type']}",
            f"- Time: {alert['time']}",
            f"- Details: {alert['details']}",
            ""
        ])
else:
    report.append("No detection rules were triggered.")

report.extend([
    "## 3. Event Timeline",
    "",
    "| Time | Username | Source IP | Event | MFA status |",
    "|---|---|---|---|---|",
    *timeline,
    "",
    "## 4. Recommended Investigation Steps",
    "",
    "- Verify whether the failed login attempts were legitimate.",
    "- Review account and authentication history.",
    "- Investigate the MFA inconsistency and authentication logs.",
    "- Check which files were accessed and downloaded.",
    "- Confirm whether the activity belongs to the same user session.",
    "",
    "## 5. Limitations",
    "",
    "- The dataset contains simulated authentication events.",
    "- The detection rules identify indicators, not confirmed attacks.",
    "- No device, session, file-name or geographic context is available.",
    "- The five-minute threshold is a demonstration rule, not a universal security standard.",
    "",
    "## 6. Conclusion",
    "",
    "The investigation identified repeated failed login attempts, "
    "an MFA inconsistency, and subsequent file activity. "
    "Further investigation is required before determining whether "
    "any malicious activity occurred."
])

report_file.write_text("\n".join(report), encoding="utf-8")

# ==========================================
# 5. DISPLAY RESULTS
# ==========================================

print("\n===== INVESTIGATION RESULTS =====")

for alert in alerts:
    print(f"[ALERT] {alert['type']}")
    print(f"Time: {alert['time']}")
    print(f"Details: {alert['details']}\n")

print(f"Events analysed: {len(events)}")
print(f"Report generated: {report_file.name}")
print("\n===== INVESTIGATION COMPLETE =====")
