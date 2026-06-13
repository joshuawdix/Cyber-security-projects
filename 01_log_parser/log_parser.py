import re
import sqlite3

# 1. Initialize the SQLite database
conn = sqlite3.connect("threat_intelligence.db")
cursor = conn.cursor()

#Create a table to store suspicisous security logs
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        timestamp TEXT,
        request_method TEXT,
        status_code INTEGER
        )
    """
)
conn.commit()

# 2. Simulate a raw server log line (e.g., a suspicious failed login attempt)
mock_log_line = '192.168.1.45 - - [12/Jun/2026:14:32:01 +0000] "POST /login HTTP/1.1" 401 2340'

# 3. Parse the line using Regex
#This regex extracts: IP, Timestamp, HTTP Method, and Status Code
log_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[(.*?)\] "(\A|GET|POST|PUT|DELETE) .*?" (\d{3})'
match = re.search(log_pattern, mock_log_line)

if match:
    ip, timestamp, method, status = match.groups()
    
    #4. Insert parsed data into SQL if the ststus code indicates an error (like 401 Unauthorized)
    if int(status) == 401:
        cursor.execute(
            "INSERT INTO security_logs (ip_address, timestamp, request_method, status_code) VALUES (?, ?, ?, ?)",
            (ip, timestamp, method, int(status)),
        )
        conn.commit()
        print(f"[!] Log Parsed & Saved: Flagged malicious activity from IP {ip}")

# 5. Query the database to verify it worked
cursor.execute("SELECT * FROM security_logs")
print("Database Entriees:", cursor.fetchall())
conn.close()