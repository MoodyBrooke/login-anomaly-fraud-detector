import csv
from datetime import datetime

# -----------------------------
# Simple configuration / rules
# -----------------------------

# How many failed logins in a row before we consider it suspicious
MAX_FAILED_ATTEMPTS = 3

# We consider these hours "weird" or unusual (2 AM - 4 AM)
UNUSUAL_HOUR_START = 2   # 2 AM
UNUSUAL_HOUR_END = 4     # 4 AM

# "Impossible travel" threshold in hours
IMPOSSIBLE_TRAVEL_HOURS = 4


def parse_timestamp(ts_str):
    """
    Convert a timestamp string like '2025-01-01 09:15:00'
    into a Python datetime object.
    """
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def is_unusual_hour(dt):
    """
    Return True if the login time is within the unusual hour window.
    """
    hour = dt.hour
    return UNUSUAL_HOUR_START <= hour < UNUSUAL_HOUR_END


def load_logins(csv_path):
    """
    Load login events from a CSV file.
    Returns a list of dicts, one per row.
    """
    events = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse timestamp once and store as datetime
            row["timestamp_dt"] = parse_timestamp(row["timestamp"])
            events.append(row)
    return events


def detect_anomalies(events):
    """
    Given a list of login events, return a list of suspicious events
    with reasons why they were flagged.
    """

    suspicious = []

    # Track last known country per user
    last_country_by_user = {}

    # Track last login time per user
    last_timestamp_by_user = {}

    # Track consecutive failures per user
    consecutive_failures_by_user = {}

    # We will sort events by time just in case
    events_sorted = sorted(events, key=lambda e: e["timestamp_dt"])

    for event in events_sorted:
        user = event["user_id"]
        country = event["country"]
        result = event["login_result"]
        dt = event["timestamp_dt"]

        reasons = []

        # 1) Check failed logins in a row
        if result == "fail":
            consecutive_failures_by_user[user] = (
                consecutive_failures_by_user.get(user, 0) + 1
            )
        else:
            # reset on success
            consecutive_failures_by_user[user] = 0

        if consecutive_failures_by_user.get(user, 0) >= MAX_FAILED_ATTEMPTS:
            reasons.append(
                f"{consecutive_failures_by_user[user]} failed logins in a row"
            )

        # 2) Check for new country and impossible travel
        previous_country = last_country_by_user.get(user)
        previous_time = last_timestamp_by_user.get(user)

        if previous_country is None:
            # First time we've ever seen this user
            last_country_by_user[user] = country
            last_timestamp_by_user[user] = dt
        else:
            if country != previous_country:
                # New country is always interesting
                reasons.append(
                    f"New country for this user: {country} (previous: {previous_country})"
                )

                # Check for impossible travel based on time difference
                if previous_time is not None:
                    time_diff = dt - previous_time
                    hours = time_diff.total_seconds() / 3600.0

                    if hours < IMPOSSIBLE_TRAVEL_HOURS:
                        reasons.append(
                            f"Possible impossible travel: {previous_country} -> {country} in {hours:.2f} hours"
                        )

                # Update to latest country and time
                last_country_by_user[user] = country
                last_timestamp_by_user[user] = dt
            else:
                # Same country, just update last time seen
                last_timestamp_by_user[user] = dt

        # 3) Check unusual login hours
        if is_unusual_hour(dt):
            reasons.append(f"Login at unusual hour: {dt.strftime('%H:%M:%S')}")

        # If we have any reasons, mark this event as suspicious
        if reasons:
            suspicious.append(
                {
                    "login_id": event["login_id"],
                    "user_id": user,
                    "country": country,
                    "timestamp": event["timestamp"],
                    "reasons": reasons,
                }
            )

    return suspicious


def print_report(suspicious_events):
    """
    Print a simple report of suspicious events.
    """
    if not suspicious_events:
        print("No suspicious login events detected.")
        return

    print("Suspicious Login Events Report")
    print("-" * 40)

    for event in suspicious_events:
        print(f"Login ID: {event['login_id']}")
        print(f"User ID : {event['user_id']}")
        print(f"Country : {event['country']}")
        print(f"Time    : {event['timestamp']}")
        print("Reasons :")
        for r in event["reasons"]:
            print(f"  - {r}")
        print("-" * 40)


def main():
    # Path to the CSV file (relative to project root)
    csv_path = "data/sample_logins.csv"

    print(f"Loading login events from {csv_path} ...")
    events = load_logins(csv_path)
    print(f"Loaded {len(events)} events.")

    print("Detecting suspicious activity...")
    suspicious = detect_anomalies(events)

    print_report(suspicious)


if __name__ == "__main__":
    main()
