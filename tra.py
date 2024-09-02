import time
import ipaddress
import random
from collections import defaultdict

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
        #Simply convert the heavy hitter prefixes to their network identifiers without counting
        return {self.prefix_to_network(prefix) for prefix in hhh_candidates}

    # def map_sources(self, hhh_candidates):
    #     # Map the heavy hitter prefixes to their corresponding networks
    #     attack_sources = {}
    #     for prefix in hhh_candidates:
    #         network = self.prefix_to_network(prefix)
    #         attack_sources[network] = attack_sources.get(network, 0) + 1
    #     return attack_sources

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

# Example usage
def simulate_ipv4_packet_stream():
    # Simulated packet stream for testing
    packets = [
        "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4",
        "192.168.2.1", "192.168.2.2", "192.168.3.1", "192.168.3.2",
        "172.16.1.1", "172.16.1.2", "172.16.2.1", "172.16.2.2",
        "10.0.0.1", "10.0.0.2", "10.0.1.1", "10.0.1.2",
        "101.0.0.1", "101.0.0.2", "101.0.1.1", "101.0.1.2"
    ]
    return packets

# Parameters for RHHH
hierarchy_levels = 4  # Supporting /8, /16, /24, /32
epsilon = 0.01
delta = 0.01
threshold = 2

# Create an instance of RHHH
rhhh = RHHH(hierarchy_levels, epsilon, delta)

# Simulate packet stream
packet_stream = simulate_ipv4_packet_stream()

# Update RHHH with each packet's source IP
for packet in packet_stream:
    rhhh.update(packet)

# Detect DDoS sources
ddos_sources = rhhh.detect_ddos_sources(threshold)

# Output detected DDoS sources
print("Detected DDoS Sources:")
for network, count in ddos_sources.items():
    print(f"Network: {network}, Count: {count}")



# Reusing the RHHH and SpaceSaving classes from the earlier implementation
# (Make sure to include the RHHH and SpaceSaving classes from the previous code here)
#
# # Function to simulate the generation of IPv4 addresses
def generate_ipv4_address():
     return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
#
# # Simulating different hierarchical structures
def simulate_hierarchy(rhhh, packet_count, hierarchy_type):
     packet_stream = []
     if hierarchy_type == "1D Byte-Level":
         # Generating packets with varying byte-level prefixes
         for _ in range(packet_count):
             ip = generate_ipv4_address()
             packet_stream.append(ip)

     elif hierarchy_type == "1D Bit-Level":
         # Generating packets with varying bit-level prefixes (simulate finer granularity)
         for _ in range(packet_count):
             ip = generate_ipv4_address()
             ip_bits = ''.join(f"{int(octet):08b}" for octet in ip.split('.'))
             packet_stream.append(ip_bits)

     elif hierarchy_type == "2D Byte-Level":
         # Generating packets considering both source and destination (simulate 2D hierarchy)
        for _ in range(packet_count):
             src_ip = generate_ipv4_address()
             dst_ip = generate_ipv4_address()
             packet_stream.append((src_ip, dst_ip))

     # Feeding the packet stream into the RHHH algorithm
     start_time = time.time()
     for packet in packet_stream:
         if hierarchy_type == "2D Byte-Level":
             rhhh.update(packet[0])  # Only considering source IP for simplicity
         else:
             rhhh.update(packet)
     end_time = time.time()

     execution_time = end_time - start_time
     heavy_hitters = rhhh.detect_ddos_sources(threshold=100)  # Threshold set to 100 for this simulation
#
     return execution_time, heavy_hitters
#
# Running the simulation
def run_simulation():
    packet_count = 1000000  # Simulating 1 million packets
    epsilon = 0.01
    delta = 0.01
    hierarchy_levels = 4  # Corresponding to /8, /16, /24, /32

    # Initializing RHHH for each hierarchy type
    rhhh_1d_byte = RHHH(hierarchy_levels, epsilon, delta)
    rhhh_1d_bit = RHHH(hierarchy_levels, epsilon, delta)
    rhhh_2d_byte = RHHH(hierarchy_levels, epsilon, delta)

    # Simulate 1D Byte-Level Hierarchy
    time_1d_byte, heavy_hitters_1d_byte = simulate_hierarchy(rhhh_1d_byte, packet_count, "1D Byte-Level")

    # Simulate 1D Bit-Level Hierarchy
    time_1d_bit, heavy_hitters_1d_bit = simulate_hierarchy(rhhh_1d_bit, packet_count, "1D Bit-Level")

    # Simulate 2D Byte-Level Hierarchy
    time_2d_byte, heavy_hitters_2d_byte = simulate_hierarchy(rhhh_2d_byte, packet_count, "2D Byte-Level")

    # Results
    print("Simulation Results:")
    print(f"1D Byte-Level Hierarchy: Time = {time_1d_byte:.4f}s, Heavy Hitters = {len(heavy_hitters_1d_byte)}")
    print(f"1D Bit-Level Hierarchy: Time = {time_1d_bit:.4f}s, Heavy Hitters = {len(heavy_hitters_1d_bit)}")
    print(f"2D Byte-Level Hierarchy: Time = {time_2d_byte:.4f}s, Heavy Hitters = {len(heavy_hitters_2d_byte)}")

    # Example of printing some of the heavy hitters
    print("\nExample Heavy Hitters:")
    for hierarchy, hitters in [("1D Byte-Level", heavy_hitters_1d_byte), ("1D Bit-Level", heavy_hitters_1d_bit), ("2D Byte-Level", heavy_hitters_2d_byte)]:
        print(f"\n{hierarchy}:")
        for network, count in list(hitters.items())[:10]:  # Display first 10 heavy hitters
            print(f"Network: {network}, Count: {count}")

run_simulation()
