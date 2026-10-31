
import csv
from pathlib import Path
from collections import Counter

# ==================================
# SOC LOGIN THREAT INVESTIGATION
# ==================================

# Locate the project directory
project_folder = Path(__file__).resolve().parent.parent
log_file = project_folder / "authentication_logs.csv"

# Store investigation results
failed_logins = Counter()
suspicious_events = []

print("Starting SOC investigation...")

# Read authentication logs
with open(log_file, "r", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:

        username = row["username"]
        source_ip = row["source_ip"]
        event_type = row["event_type"]
        mfa_status = row["mfa_status"]

        # Detection rule 1: Failed logins
        if event_type == "FAILED_LOGIN":
            failed_logins[(username, source_ip)] += 1

        # Detection rule 2: MFA inconsistency
        if (
            event_type == "SUCCESSFUL_LOGIN"
            and mfa_status == "FAILED"
        ):
            suspicious_events.append(
                f"MFA inconsistency: {username} from {source_ip}"
            )

# ==================================
# DISPLAY INVESTIGATION RESULTS
# ==================================

print("\n===== SOC INVESTIGATION RESULTS =====")

for (username, ip), count in failed_logins.items():

    print(f"\nUsername: {username}")
    print(f"Source IP: {ip}")
    print(f"Failed login attempts: {count}")

    if count >= 5:
        print("[ALERT] Possible brute-force activity!")

print("\n===== SUSPICIOUS EVENTS =====")

for event in suspicious_events:
    print("[ALERT]", event)

print("\n===== INVESTIGATION COMPLETE =====")
