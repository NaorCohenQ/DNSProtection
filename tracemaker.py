import random
from collections import defaultdict, deque
import pandas as pd
import re

class DNSProtectionLayer:
    def __init__(self, threshold, window_size):
        self.threshold = threshold  # Max number of NXDOMAIN requests allowed
        self.window_size = window_size  # Size of the sliding window
        self.request_log = {}  # Logs recent requests per IP
        self.blocked_ips = set()  # Set of blocked IPs

    def is_nxd_attack(self, ip):
        # Simulate DNS resolution, returns True if the domain is non-existent
        nxdomain = random.choice([True, False])  # Replace with real DNS resolution check
        return nxdomain

    def process_request(self, ip):
        if ip in self.blocked_ips:
            return "Blocked"

        nxdomain = self.is_nxd_attack(ip)
        if nxdomain:
            self.request_log[ip]
            if len(self.request_log[ip]) > self.window_size:
                self.request_log[ip].popleft()

            if len(self.request_log[ip]) >= self.threshold:
                self.blocked_ips.add(ip)
                return "Blocked"

        return "Allowed"

    def get_statistics(self):
        return len(self.blocked_ips), len(self.request_log)

def loadData():
    # Load the CSV file from your local directory
    file_path = 'traces1.csv'  # Replace with your actual file path
    data = pd.read_csv(file_path)

    # Extract the timestamp and q_src columns
    extracted_data = data[['timestamp', 'q_src']]

    # Filter rows where q_src is a valid IPv4 address
    extracted_data = extracted_data[extracted_data['q_src'].apply(is_valid_ipv4)]

    return extracted_data

def is_valid_ipv4(ip):
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if pattern.match(ip):
        # Further check to ensure each octet is between 0 and 255
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

def generate_attack_traffic(subnets, num_requests, start_timestamp):
    attack_traffic = []
    timestamp = start_timestamp
    for _ in range(num_requests):
        subnet = random.choice(subnets)
        ip = f"{subnet}.{random.randint(1, 254)}"
        domain = f"nonexistent{random.randint(1, 10000)}.com"
        attack_traffic.append((timestamp, ip, domain))
        timestamp += random.randint(1, 10)  # Increment timestamp by a small random amount
    return attack_traffic

# Example attacker simulation
subnets = ['192.168.1', '10.0.0', '172.16.0']
csvData = loadData()
last_timestamp = csvData['timestamp'].max()  # Get the last timestamp from the original data

attack_traffic = generate_attack_traffic(subnets, num_requests=100, start_timestamp=last_timestamp + 1)

# Combine real traffic with attack traffic
real_traffic = list(csvData.itertuples(index=False, name=None))
combined_traffic = real_traffic + attack_traffic
random.shuffle(combined_traffic)

# Process the combined traffic with the DNSProtectionLayer
protection_layer = DNSProtectionLayer(threshold=10, window_size=20)
blocked_count = 0
total_requests = len(combined_traffic)
legitimate_requests = sum(1 for _, ip, domain in combined_traffic if protection_layer.is_nxd_attack(ip, domain))

for timestamp, ip, domain in combined_traffic:
    result = protection_layer.process_request(ip, domain)
    if result == "Blocked":
        blocked_count += 1

print(f"Blocked Requests: {blocked_count}")
print(f"Total Requests: {total_requests}")
print(f"Legitimate Requests: {legitimate_requests}")
print(f"Percentage of Legitimate Traffic Blocked: {blocked_count/legitimate_requests * 100:.2f}%")
