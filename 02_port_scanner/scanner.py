import socket
import sqlite3
import time

# Define common ports and their typical network services
TARGET_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted)",
    25: "SMTP (Email)",
    80: "HTTP (Web Server)",
    110: "POP3 (Email)",
    443: "HTTPS (Secure Web)",
    3306: "MySQL (Database)"
}

TARGET_HOST = "127.0.0.1"  # Localhost (completely safe to scan)

def initialize_asset_db():
    """Creates a database table to keep an inventory of network assets and open ports."""
    conn = sqlite3.connect("network_inventory.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT,
            ip_address TEXT,
            port_number INTEGER,
            service_name TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    return conn

def run_port_scan():
    conn = initialize_asset_db()
    cursor = conn.cursor()
    
    scan_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[*] Starting network inventory scan on {TARGET_HOST} at {scan_timestamp}...")
    
    open_ports_found = 0

    for port, service in TARGET_PORTS.items():
        # AF_INET specifies IPv4; SOCK_STREAM specifies TCP connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a fast 1-second timeout so the script doesn't freeze on closed ports
        s.settimeout(1.0)
        
        # connect_ex returns an error code instead of throwing an unhandled exception
        result = s.connect_ex((TARGET_HOST, port))
        
        # Result code '0' means the connection was successful (Port is OPEN)
        if result == 0:
            status = "OPEN"
            open_ports_found += 1
            print(f"[!] ALERT: Port {port} ({service}) is OPEN!")
        else:
            status = "CLOSED"

        # Log EVERY port status into our SQL Asset Inventory Database
        cursor.execute('''
            INSERT INTO port_scan_results (scan_time, ip_address, port_number, service_name, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (scan_timestamp, TARGET_HOST, port, service, status))
        
        s.close()

    conn.commit()
    print(f"[+] Scan finished. Saved results to 'network_inventory.db'. Found {open_ports_found} open ports.")
    
    # Run an SQL report showing historical open ports
    print("\n--- Current SQL Network Asset Report ---")
    cursor.execute("SELECT port_number, service_name FROM port_scan_results WHERE status = 'OPEN'")
    open_assets = cursor.fetchall()
    
    if not open_assets:
        print("No exposure found. All scanned ports are currently closed.")
    else:
        for row in open_assets:
            print(f"Active Exposure -> Port: {row[0]} | Running Service: {row[1]}")
            
    conn.close()

if __name__ == "__main__":
    run_port_scan()
