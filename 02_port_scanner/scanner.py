import socket

# Target local host safely (never scan networks you do not own)
target_host = "127.0.0.1"
# Common ports to check: 22 (SSH), 80 (HTTP), 443 (HTTPS)
ports_to_scan = [22, 80, 443]

print(f"Starting security port scan on host: {target_host}")

for port in ports_to_scan:
    # AF_INET specifies IPv4, SOCK_STREAM specifies TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a rapid timeout so the scanner doesn't hang indefinitely
    s.settimeout(1.0)

    # Attempt to connect to the IP and Port
    result = s.connect_ex((target_host, port))

    if result == 0:
        print(f"[+] Port {port}: OPEN (Potential Security Exposure)")
    else:
        print(f"[-] Port {port}: Closed")

    # Always close the socket connection
    s.close()
