
import csv
from collections import Counter, defaultdict

LOG_FILE = "sample_security_logs.csv"
FAILED_LOGIN_EVENT_ID = "4625"
ALERT_THRESHOLD = 5


def analyze_logs():
    failed_attempts = Counter()
    users_by_ip = defaultdict(set)

    try:
        with open(LOG_FILE, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            for row in reader:
                event_id = row.get("EventID", "").strip()
                username = row.get("Username", "Unknown").strip()
                source_ip = row.get("SourceIP", "Unknown").strip()

                if event_id == FAILED_LOGIN_EVENT_ID:
                    failed_attempts[source_ip] += 1
                    users_by_ip[source_ip].add(username)

        print("=== SOC L1: Failed Login Analysis ===")

        if not failed_attempts:
            print("No failed logins found.")
            return

        for source_ip, count in failed_attempts.most_common():
            status = (
                "POTENTIAL ALERT"
                if count >= ALERT_THRESHOLD
                else "Review"
            )

            print(f"\nSource IP: {source_ip}")
            print(f"Failed attempts: {count}")
            print(f"Usernames targeted: {', '.join(sorted(users_by_ip[source_ip]))}")
            print(f"Status: {status}")

        print("\nNote: Repeated failures are suspicious indicators,")
        print("not proof of an attack. Correlate with other events.")

    except FileNotFoundError:
        print(f"Log file not found: {LOG_FILE}")
        print("Create sample_security_logs.csv in the same folder.")


if __name__ == "__main__":
    analyze_logs()
  
