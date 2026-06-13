import hashlib
import requests

print("--- Testing Requests Library ---")
try:
    response = requests.get("https://httpbin.org", timeout=5)
    print(f"Connection Successful! Status Code: {response.status_code}")
except Exception as e:
    print(f"Connection Failed: {e}")

print("\n--- Testing Cryptography Hashing ---")
secret_password = "SecurePassword123"
hashed_password = hashlib.sha256(secret_password.encode()).hexdigest()
print(f"Original: {secret_password}")
print(f"SHA-256 Hash: {hashed_password}")
