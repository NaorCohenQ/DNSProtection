import random
from collections import defaultdict
import pandas as pd
import re

class SpaceSaving:
    def __init__(self, epsilon):
        self.epsilon = epsilon
        self.capacity = int(1 / epsilon)
        self.counters = defaultdict(int)

    def increment(self, item):
        if item in self.counters:
            self.counters[item] += 1
        elif len(self.counters) < self.capacity:
            self.counters[item] += 1
        else:
            min_item = min(self.counters, key=self.counters.get)
            self.counters.pop(min_item)
            self.counters[item] = 1

    def get_frequency(self, item):
        return self.counters.get(item, 0)

    def get_heavy_hitters(self, threshold):
        return {item for item, count in self.counters.items() if count >= threshold}

class RHHH:
    def __init__(self, hierarchy_levels, epsilon, delta):
        self.H = hierarchy_levels  # Number of levels in the hierarchy
        self.epsilon = epsilon  # Error tolerance
        self.delta = delta  # Confidence level
        self.counters = [SpaceSaving(epsilon) for _ in range(self.H)]  # Initialize counters for each level

    def update(self, ip_address):
        # Randomly select a level in the hierarchy
        level = random.randint(0, self.H - 1)
        prefix = self.get_prefix(ip_address, level)
        self.counters[level].increment(prefix)

    def get_prefix(self, ip_address, level):
        # Split IP address into octets
        octets = ip_address.split(".")
        # Build prefix based on the level
        if level == 0:
            return octets[0]  # /8
        elif level == 1:
            return ".".join(octets[:2])  # /16
        elif level == 2:
            return ".".join(octets[:3])  # /24
        else:
            return ip_address  # /32 (full IP address)

    def output_hhh(self, threshold):
        hhh_candidates = set()
        for level in range(self.H - 1, -1, -1):
            for prefix in self.counters[level].get_heavy_hitters(threshold):
                conditioned_freq = self.calculate_conditioned_frequency(prefix, hhh_candidates, level)
                if conditioned_freq >= threshold:
                    hhh_candidates.add(prefix)
        return hhh_candidates

    def calculate_conditioned_frequency(self, prefix, hhh_candidates, level):
        conditioned_freq = self.counters[level].get_frequency(prefix)
        for parent_prefix in self.get_parents(prefix, hhh_candidates):
            conditioned_freq -= self.counters[level - 1].get_frequency(parent_prefix)
        return conditioned_freq

    def get_parents(self, prefix, hhh_candidates):
        # Get parent prefixes in the hierarchy
        parents = []
        for candidate in hhh_candidates:
            if candidate.startswith(prefix) and len(candidate) > len(prefix):
                parents.append(candidate)
        return parents

    def detect_ddos_sources(self, threshold):
        hhh_candidates = self.output_hhh(threshold)
        return self.map_sources(hhh_candidates)

    def map_sources(self, hhh_candidates):
        # Map the heavy hitter prefixes to their corresponding networks
        attack_sources = {}
        for prefix in hhh_candidates:
            network = self.prefix_to_network(prefix)
            attack_sources[network] = attack_sources.get(network, 0) + 1
        return attack_sources

    def prefix_to_network(self, prefix):
        # Convert prefix to network identifier
        parts = prefix.split(".")
        if len(parts) == 1:
            return f"{prefix}.0.0.0/8"
        elif len(parts) == 2:
            return f"{prefix}.0.0/16"
        elif len(parts) == 3:
            return f"{prefix}.0/24"
        else:
            return f"{prefix}/32"

def is_valid_ipv4(ip):
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if pattern.match(ip):
        # Further check to ensure each octet is between 0 and 255
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

def loadData():
    # Load the CSV file from your local directory
    file_path = 'traces1.csv'  # Replace with your actual file path
    data = pd.read_csv(file_path)

    # Extract the timestamp and q_src columns
    extracted_data = data[['timestamp', 'q_src']]

    # Filter rows where q_src is a valid IPv4 address
    extracted_data = extracted_data[extracted_data['q_src'].apply(is_valid_ipv4)]

    return extracted_data

# Parameters for RHHH
hierarchy_levels = 4  # Supporting /8, /16, /24, /32
epsilon = 0.01
delta = 0.01
threshold = 2

# Create an instance of RHHH
rhhh = RHHH(hierarchy_levels, epsilon, delta)

# Simulate packet stream
csvData = loadData()



# Update RHHH with each packet's source IP
for packet in csvData['q_src']:
    rhhh.update(packet)

# Detect DDoS sources
ddos_sources = rhhh.detect_ddos_sources(threshold)

# Output detected DDoS sources
print("Detected DDoS Sources:")
for network,count in ddos_sources.items():
    print(f"Network: {network}")

#
#
# # Read packet trace from a pcap file
# packets = rdpcap('path_to_trace.pcap')
#
# # Initialize RHHH
# hierarchy_levels = 4  # Supporting /8, /16, /24, /32
# epsilon = 0.01
# delta = 0.01
# threshold = 2
# rhhh = RHHH(hierarchy_levels, epsilon, delta)
#
# # Process each packet in the trace
# for packet in packets:
#     if packet.haslayer('IP'):
#         src_ip = packet['IP'].src
#         rhhh.update(src_ip)
#
# # Detect heavy hitters
# ddos_sources = rhhh.detect_ddos_sources(threshold)
#
# # Output detected DDoS sources
# print("Detected DDoS Sources:")
# for network, count in ddos_sources.items():
#     print(f"Network: {network}, Count: {count}")
