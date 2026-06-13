import random
import time

# Mock IP addresses
good_ips = ["192.168.1.50", "10.0.0.12", "172.16.5.4"]
attacker_ips = ["185.220.101.5", "45.134.26.11"]  # Known malicious IPs

# Simulation templates
normal_pages = ["/home", "/about", "/products", "/contact"]
attack_payloads = [
    "/login?user=admin'--",  # SQL Injection bypass
    "/admin.php?id=1 UNION SELECT null, username, password FROM users--",  # SQLi data exfiltration
    "/wp-login.php",  # Brute force targeting admin portal
    "/etc/passwd",  # Local File Inclusion (LFI) attempt
]


def generate_mock_logs():
    print("[*] Generating simulated attack log file...")
    with open("web_access.log", "w") as f:
        # 1. Generate 50 lines of normal user traffic
        for _ in range(50):
            ip = random.choice(good_ips)
            page = random.choice(normal_pages)
            # Normal user traffic returns 200 OK
            f.write(
                f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {page} HTTP/1.1" 200 3450\n'
            )

        # 2. Simulate a Brute Force attack (many rapid 401 Unauthorized errors)
        for _ in range(15):
            f.write(
                f'{attacker_ips[0]} - - [{time.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "POST /login HTTP/1.1" 401 230\n'
            )

        # 3. Simulate web application vulnerability exploits (SQL Injection)
        for payload in attack_payloads:
            # Attacks often trigger 500 Internal Server Errors or 403 Forbidden
            status = random.choice([403, 500])
            f.write(
                f'{attacker_ips[1]} - - [{time.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {payload} HTTP/1.1" {status} 120\n'
            )

    print("[+] Created 'web_access.log' with 69 security events.")


if __name__ == "__main__":
    generate_mock_logs()
