import re
import sqlite3

# List of dangerous security keywords to watch for in URLs
MALICIOUS_KEYWORDS = ["UNION", "SELECT", "'--", "etc/passwd", "wp-login"]


def initialize_threat_db():
    """Creates a local security database if it doesn't exist."""
    conn = sqlite3.connect("siem_alerts.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            timestamp TEXT,
            request_uri TEXT,
            status_code INTEGER,
            threat_type TEXT
        )
    """
    )
    conn.commit()
    return conn


def parse_and_analyze():
    # Connect to database
    conn = initialize_threat_db()
    cursor = conn.cursor()

    # Regular expression to extract IP, Timestamp, Request, and Status Code
    log_regex = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[(.*?)\] "(GET|POST) (.*?) HTTP/1.1" (\d{3})'

    alert_count = 0

    print("[*] Parsing logs for malicious indicators...")

    # Read the log file line by line
    with open("web_access.log", "r") as file:
        for line in file:
            match = re.search(log_regex, line)
            if match:
                ip, timestamp, method, uri, status = match.groups()
                status = int(status)
                threat_type = None

                # Rule 1: Flag high-risk status codes (Brute force / failed entry)
                if status == 401:
                    threat_type = "Suspicious Failed Login (Brute Force)"

                # Rule 2: Flag dangerous string patterns (SQLi / Exploit attempts)
                elif any(keyword in uri for keyword in MALICIOUS_KEYWORDS):
                    threat_type = "Web Application Attack Attempt (SQLi/LFI)"

                # If an alert is triggered, write it to our SQL threat table
                if threat_type:
                    cursor.execute(
                        """
                        INSERT INTO security_alerts (ip_address, timestamp, request_uri, status_code, threat_type)
                        VALUES (?, ?, ?, ?, ?)
                    """,
                        (ip, timestamp, uri, status, threat_type),
                    )
                    alert_count += 1

    conn.commit()
    print(f"[+] Parsing complete. Saved {alert_count} threat alerts to SQL.")

    # Show top findings directly in terminal
    print("\n--- Summary of Log Highlights ---")
    cursor.execute(
        "SELECT ip_address, COUNT(*) FROM security_alerts GROUP BY ip_address"
    )
    for row in cursor.fetchall():
        print(f"Malicious Attacker IP: {row[0]} | Triggered Alerts: {row[1]}")

    conn.close()


if __name__ == "__main__":
    parse_and_analyze()
