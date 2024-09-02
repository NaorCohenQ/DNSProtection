import random
from collections import defaultdict
import pandas as pd
import re

time_stamp = 0
q_src = 1
is_orig = 2

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

    def getAmount(self,ip):
        return self.counters[3].counters[ip]

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


class DNSProtectionLayer:
    def __init__(self, threshold,rhhh):
        self.threshold = threshold  # Max number of NXDOMAIN requests allowed
        # self.request_log = {}  # Logs recent requests per IP
        self.denied = {}
        self.blocked_ips = set()  # Set of blocked IPs
        self.rhhh = rhhh

    def is_nxd_attack(self, val):
        # Simulate DNS resolution, returns True if the domain is non-existent
        return val == 0
        # nxdomain = random.choice([True, False])  # Replace with real DNS resolution check
        # return nxdomain

    def process_request(self, packet):
        ip = packet[1]
        if ip in self.blocked_ips:
            return "Blocked"

        nxdomain = self.is_nxd_attack(packet[2])
        if not nxdomain:
            self.rhhh.update(ip)

        if nxdomain:
            if not self.denied.__contains__(ip):
                self.denied[ip] = 0

            self.denied[ip] +=1
            # use RHH for props, block IP if necessary.
            if self.denied[ip]>self.rhhh.getAmount(ip)-self.threshold:
                # Possible instead : Relations between amount of legitmate vs unlegitmate attacks of the same ip.
                self.blocked_ips.add(ip)
                #return "Blocked"



            # self.request_log[ip]
            # if len(self.request_log[ip]) > self.window_size:
            #     self.request_log[ip].popleft()
            #
            # if len(self.request_log[ip]) >= self.threshold:
            #     self.blocked_ips.add(ip)
            #     return "Blocked"

        return "Allowed"

    def get_statistics(self):
        return len(self.blocked_ips)

class Simulator:
    def __init__(self):
        self.csvData = self.loadData()
        self.blocked_count = 0
        self.total_requests = 0
        self.legitimate_requests = 0
        self.legit_blocked = 0


    def is_valid_ipv4(self,ip):
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if pattern.match(ip):
            # Further check to ensure each octet is between 0 and 255
            return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
        return False


    def loadData(self):
        # Load the CSV file from your local directory
        file_path = 'traces1.csv'  # Replace with your actual file path
        data = pd.read_csv(file_path)

        # Extract the timestamp and q_src columns
        extracted_data = data[['timestamp', 'q_src']]

        # Filter rows where q_src is a valid IPv4 address
        extracted_data = extracted_data[extracted_data['q_src'].apply(self.is_valid_ipv4)]

        return extracted_data

    def generate_attack_traffic(self,subnets, num_requests, start_timestamp):
        attack_traffic = []
        timestamp = start_timestamp
        for _ in range(num_requests):
            subnet = random.choice(subnets)
            #ip = f"{subnet}.{random.randint(1, 254)}"
            attack_traffic.append((timestamp, subnet,0))
            timestamp += random.randint(1, 10)  # Increment timestamp by a small random amount
        return attack_traffic

    def simulate_attack(self,attack_perc,subs_perc):
        # Parameters for RHHH
        hierarchy_levels = 4  # Supporting /8, /16, /24, /32
        epsilon = 0.01
        delta = 0.01
        threshold = 2

        # Create an instance of RHHH
        rhhh = RHHH(hierarchy_levels, epsilon, delta)

        # Simulate packet stream
        csvData = self.loadData()
        csvData = csvData[:50000]
        csvData['isOrig'] = 1
        protLayer = DNSProtectionLayer(10,rhhh)

        # Example attacker simulation
        #subnets = ['192.168.1', '10.0.0', '172.16.0']
        subnets = [ip for ip in csvData['q_src']]
        subnets=subnets[:10]
        #csvData = loadData()
        first_timestamp = csvData['timestamp'].min()
        last_timestamp = csvData['timestamp'].max()  # Get the last timestamp from the original data
        real_traffic = list(csvData.itertuples(index=False, name=None))

        num_requests = (int)(len(real_traffic)*(attack_perc/100))
        # real_traffic = [packet for packet in csvData['q_src']]
        
        attack_traffic = self.generate_attack_traffic(subnets, num_requests, start_timestamp=first_timestamp)

        # Combine real traffic with attack traffic
        combined_traffic = real_traffic + attack_traffic
        random.shuffle(combined_traffic)

        # Process the combined traffic with the DNSProtectionLayer
        #protection_layer = DNSProtectionLayer(threshold=10, window_size=20)
        self.total_requests = len(combined_traffic)
        self.legitimate_requests = len(real_traffic)

        # Update RHHH with each packet's source IP
        for packet in combined_traffic:
           result = protLayer.process_request(packet)
           if result == "Blocked":
                self.blocked_count += 1
                self.legit_blocked = self.legit_blocked + packet[is_orig]

    def blocked_stats(self):
        return self.blocked_count

    def total_req_stats(self):
        return self.total_requests

    def legit_req_stats(self):
        return self.legitimate_requests

    def legit_block_stats(self):
        return self.legit_blocked


    def printStats(self):
        print(f"Blocked Requests: {self.blocked_count}")
        print(f"Total Requests: {self.total_requests}")
        print(f"Legitimate Requests: {self.legitimate_requests}")
        print(f"Legitimate Requests Blocked: {self.legit_blocked}")
        print(f"Attack Requests Blocked: {self.blocked_count-self.legit_blocked}")
        #print(f"Percentage of Legitimate Traffic Blocked: {self.blocked_count/self.legitimate_requests * 100:.2f}%")


# smltr = Simulator()
# smltr.simulate_attack(50,-1)
# smltr.printStats()
