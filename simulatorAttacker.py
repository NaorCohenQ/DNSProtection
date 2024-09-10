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
        self.H = hierarchy_levels  # ber of levels in the hierarchy
        self.epsilon = epsilon  # Error tolerance
        self.delta = delta  # Confidence level
        self.counters = [SpaceSaving(epsilon) for _ in range(self.H)]  # Initialize counters for each level

    def getAmo(self,ip,level):
        res = 0
        for i in range(level,4):
            pref = self.get_prefix(ip,i)
            if pref in self.counters[level].counters:
                res += self.counters[level].counters[pref]
        return res
    def getAmount(self,ip,level):
        if level == -1:
            level = random.choice([0,1,2,3])
        res = 0
        #for i in range(0,level):
        #for i in range(level,4):
        # pref = self.get_prefix(ip,3)
        # if pref in self.counters[3].counters:
        #        res += self.counters[3].counters[pref]
        for i in range(level,4):
            pref = self.get_prefix(ip,i)
            res += self.counters[level].counters[pref]
        # # print(res)
        # #return self.counters[3].counters[pref]
        # #return self.counters[3].counters[pref]
        return res
        #return self.counters[level].counters[ip]

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
    def __init__(self, threshold,rhhh,ticks,rls_perc,pref_size):
        self.threshold = threshold  # Max number of NXDOMAIN requests allowed
        # self.request_log = {}  # Logs recent requests per IP
        self.denied = {}
        #self.blocked_ips = set()  # Set of blocked IPs
        self.blocked_ips = {}
        self.rhhh = rhhh
        self.rhhh2 = RHHH(4,0.01,0.01)
        self.ticks = ticks
        self.rls_factor = self.ticks * rls_perc
        self.pref_size = pref_size
        self.cost = 0
    def is_nxd_attack(self, val):
        # Simulate DNS resolution, returns True if the domain is non-existent
        return val == 0
        # nxdomain = random.choice([True, False])  # Replace with real DNS resolution check
        # return nxdomain
    def should_released(self,tick,ip):
        if self.rls_factor+self.blocked_ips[ip]<= tick:
            self.blocked_ips.pop(ip)
            self.denied[ip] = 1
            return True
        return False

#172.63.94.18
    def process_request3(self,packet):
        tick = packet[0]
        ip = packet[1]
        #self.should_released(tick,ip)

        if ip in self.blocked_ips.keys():
            res = self.should_released(tick,ip)
            if res == False:
                return "Blocked"
            if res == True:
                self.rhhh.update(ip)
                return "Allowed"

        nxdomain = self.is_nxd_attack(packet[2])
        self.cost+=1
        if not nxdomain:
            self.rhhh.update(ip)

        if nxdomain:
            if not self.denied.__contains__(ip):
                self.denied[ip] = 0

            self.denied[ip] +=1
            # use RHH for props, block IP if necessary.
            if self.rhhh.getAmo(ip,self.pref_size)>= self.denied[ip]-self.threshold:
                self.blocked_ips[ip] = tick

            return "Allowed"



    def process_request2(self,packet):
        tick = packet[0]
        ip = packet[1]
        if ip in self.blocked_ips.keys() and not self.should_released(tick,ip):
            return "Blocked"

        nxdomain = self.is_nxd_attack(packet[2])
        self.cost +=1
        if not nxdomain:
            self.rhhh.update(ip)

        if nxdomain:
            self.rhhh2.update(ip)
            if self.rhhh2.counters[self.pref_size].counters[self.rhhh2.get_prefix(ip,self.pref_size)]>=self.rhhh.getAmount(ip,self.pref_size)+self.threshold:
            #if self.rhhh2.getAmount(ip,self.pref_size)>=self.rhhh.getAmount(ip,self.pref_size)+self.threshold:
                self.blocked_ips[ip] = tick
                #return "Blocked"
                return "Blocked"
        #172.64.183.9

        return "Allowed"



    def process_request(self, packet):
        tick = packet[0]
        ip = packet[1]
        #self.should_released(tick,ip)

        if ip in self.blocked_ips.keys() and not self.should_released(tick,ip):
            return "Blocked"

        if ip in self.blocked_ips.keys() and self.should_released(tick,ip):
            return "Allowed"

        nxdomain = self.is_nxd_attack(packet[2])
        self.cost+=1
        if not nxdomain:
            self.rhhh.update(ip)

        if nxdomain:
            if not self.denied.__contains__(ip):
                self.denied[ip] = 0

            self.denied[ip] +=1
            # use RHH for props, block IP if necessary.
            if self.denied[ip]>=self.rhhh.getAmount(ip,self.pref_size)-self.threshold:
                # Possible instead : Relations between amount of legitmate vs unlegitmate attacks of the same ip.
                self.blocked_ips[ip] = tick
                #return "Blocked"

#72.164.89


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
        self.att_req = 0
        self.legit_blocked = 0
        self.end_tstmp = 0
        self.loadC = 0
        self.legit_passed = {}
        self.att_passed = {}
        self.real_traff = {}
        self.reduced_subs = ()
        self.prefi_size = 0


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


    def randomized_subnets(self,subnets,pref_size):
        new_list = []
        for subnet in subnets:
            # Split the subnet into its octets
            octets = subnet.split('.')

            if pref_size == -1:
                # Randomly choose a prefix length (8, 16, 24, or 32)
                prefix_length = random.choice([8, 16, 24, 32])
            else:
                prefix_length = pref_size*8
            # Build the prefix based on the chosen prefix length
            if prefix_length == 8:
                new_subnet = f"{octets[0]}"
            elif prefix_length == 16:
                new_subnet = f"{octets[0]}.{octets[1]}"
            elif prefix_length == 24:
                new_subnet = f"{octets[0]}.{octets[1]}.{octets[2]}"
            else:  # prefix_length == 32
                new_subnet = subnet

            new_list.append(new_subnet)

        return new_list

    def generate_ips_for_subnets(self,subnets, X):
        generated_ips = []

        for subnet in subnets:
            # Determine the number of octets already in the subnet
            octets = subnet.split('.')
            num_existing_octets = len(octets)

            for _ in range(X):
                # Generate the remaining octets to complete the IP address
                while len(octets) < 4:
                    octets.append(str(random.randint(0, 255)))

                # Join the octets to form a full IP address
                ip_address = '.'.join(octets)
                generated_ips.append(ip_address)

                # Reset the octets to the original subnet for the next iteration
                octets = subnet.split('.')
        return generated_ips
    def generate_attack_traces(self, subnets, num_requests, first_timestamp,pref_size):
        attack_traff = []
        #timestamp = first_timestamp
        timestamp = random.choice(first_timestamp)
        max_t=timestamp
        size = int(num_requests/len(subnets))
        splus = num_requests%len(subnets)
        subs = self.randomized_subnets(subnets,pref_size)
        all_ips = self.generate_ips_for_subnets(subs,size)
        random.shuffle(all_ips)
        for ip in all_ips:
            attack_traff.append((timestamp, ip,0))
            timestamp = random.choice(first_timestamp)
            max_t =max(timestamp,max_t)
        for i in range(0,splus):
             attack_traff.append((timestamp, all_ips[0],0))
             timestamp = random.choice(first_timestamp)
             max_t =max(timestamp,max_t)
             #timestamp += random.randint(0, 1)  # Increment timestamp by a small random amount
        self.end_tstmp = max_t
        return attack_traff


    # def generate_attack_traces(self, subnets, num_requests, first_timestamp,pref_size):
    #     attack_traff = []
    #     timestamp = first_timestamp
    #     size = int(num_requests/len(subnets))
    #     splus = num_requests%len(subnets)
    #     subs = self.randomized_subnets(subnets,pref_size)
    #     all_ips = self.generate_ips_for_subnets(subs,size)
    #     random.shuffle(all_ips)
    #     for ip in all_ips:
    #         attack_traff.append((timestamp, ip,0))
    #         timestamp += random.randint(0, 1)  # Increment timestamp by a small random amount
    #     for i in range(0,splus):
    #          attack_traff.append((timestamp, all_ips[0],0))
    #          timestamp += random.randint(0, 1)  # Increment timestamp by a small random amount
    #     self.end_tstmp = timestamp
    #     return attack_traff

    def simulate_attack(self,attack_perc,subs_perc,start_perc,pref_size,numOfPackets,revive):
        self.prefi_size = pref_size
        # Parameters for RHHH
        hierarchy_levels = 4  # Supporting /8, /16, /24, /32
        epsilon = 0.01
        delta = 0.01
        threshold = 2

        # Create an instance of RHHH
        rhhh = RHHH(hierarchy_levels, epsilon, delta)

        # Simulate packet stream
        #csvData = self.loadData()
        #amount_of_data = len(self.csvData)
        csvData = self.csvData[:numOfPackets]

        #Normalized the timestamp column.
        K = csvData['timestamp'].iloc[0]
        csvData['timestamp'] = csvData['timestamp'] - K
        times = set(csvData['timestamp'])
        times = list(times)
        csvData['isOrig'] = 1

        # Example attacker simulation
        #subnets = ['192.168.1', '10.0.0', '172.16.0']
        subnets = [ip for ip in csvData['q_src']]
        subs = set(subnets)
        subs_amount = (int)(len(subs)*(subs_perc/100))
        print(subs_amount)
        subs = list(subs)
        total_ips = len(subs)
        # print("Subs:",subnets)
        subnets=subnets[:subs_amount]
        #contains both the reduced subs and the amount of all the IP's
        self.reduced_subs = (subnets,total_ips)
        # print("Reduced Subs:",subnets)
        #csvData = loadData()


        first_timestamp = csvData['timestamp'].min()
        last_timestamp = csvData['timestamp'].max()  # Get the last timestamp from the original data
        if start_perc == 0:
            start_tstmp = first_timestamp
        else:
            gap = last_timestamp-first_timestamp
            start_tstmp = int(gap *(start_perc/100))

        real_traffic = list(csvData.itertuples(index=False, name=None))
        self.real_traff = real_traffic


        timesX =[t for t in times if t>=start_tstmp]
        num_requests = (int)(len(real_traffic)*(attack_perc/100))
        # real_traffic = [packet for packet in csvData['q_src']]
        self.att_req = num_requests
        #attack_traffic = self.gen_now(subnets,num_requests,start_tstmp,pref_size)
        #attack_traffic = self.generate_attack_traces(subnets,num_requests,start_tstmp,pref_size)
        attack_traffic = self.generate_attack_traces(subnets,num_requests,timesX,pref_size)
        #attack_traffic = self.generate_attack_traffic(subnets, num_requests, start_tstmp)
        #attack_traffic=attack_traff
        # Combine real traffic with attack traffic

        combined_traffic = real_traffic + attack_traffic
        combined_traffic = sorted(combined_traffic,key= lambda x : x[0])
        #random.shuffle(combined_traffic)

        #total_ticks = self.end_tstmp - start_tstmp
        # Process the combined traffic with the DNSProtectionLayer
        #protection_layer = DNSProtectionLayer(threshold=10, window_size=20)
        self.total_requests = len(combined_traffic)
        self.legitimate_requests = len(real_traffic)

        calc_load = {}
        curr =0
        curr_ts = 0
        protLayer = DNSProtectionLayer(10,rhhh,self.end_tstmp,revive,pref_size-1)
        # Update RHHH with each packet's source IP
        self.combined = combined_traffic
        for packet in combined_traffic:
           if packet[0] != curr_ts:
                curr+=1
                curr_ts = packet[0]
           # if packet[2] == 0:
           #      x=9
           if curr not in calc_load:
                calc_load[curr] = 0
                self.att_passed[curr] = 0
                self.legit_passed[curr] = 0
           calc_load[curr]+=1
           result = protLayer.process_request2(packet)
           if result == "Blocked":
                self.blocked_count += 1
                self.legit_blocked = self.legit_blocked + packet[is_orig]
           elif result == "Allowed":
               if packet[is_orig] == 0:
                 self.att_passed[curr]+=1
               else:
                 self.legit_passed[curr]+=1
        self.loadC = calc_load
        #print(attack_traffic[-1])
        print(calc_load)
        # print(self.att_passed)
        # print(self.legit_passed)
        print("Cost:",protLayer.cost)

    def get_subnets(self):
        red_sub = self.reduced_subs[0]
        if len(red_sub)>=20:
            red_sub = self.reduced_subs[:20]
        res = [self.get_prefix(x,self.prefi_size-1) for x in red_sub]
        res = set(res)
        return list(res)

    def get_total_subs(self):
        return self.reduced_subs[1]

    def get_legit_c(self):
        real_c = {}
        for p in self.real_traff:
            if p[0] not in real_c.keys():
                real_c[p[0]] = 0
            else:
                real_c[p[0]]+=1
        return real_c
    def get_att_c(self):
        real_c = self.get_legit_c()
        result_dict = {key: self.loadC.get(key, 0) - real_c.get(key, 0) for key in self.loadC.keys()}
        return result_dict
    def get_legit_passed(self):
        return self.legit_passed
    def get_att_passed(self):
        return self.att_passed
    def get_load(self):
        return self.loadC
    def blocked_stats(self):
        return self.blocked_count

    def total_req_stats(self):
        return self.total_requests

    def legit_req_stats(self):
        return self.legitimate_requests

    def legit_block_stats(self):
        return self.legit_blocked

    def attack_block_stats(self):
        return self.blocked_count-self.legit_blocked
    def attack_req_stats(self):
        return self.att_req

    def printStats(self):
        print(f"Total Requests: {self.total_requests}")
        print(f"Blocked Requests: {self.blocked_count}")
        print(f"Legitimate Requests: {self.legitimate_requests}")
        print(f"Attack Requests: {self.total_requests-self.legitimate_requests}")
        print(f"Legitimate Requests Blocked: {self.legit_blocked}")
        print(f"Attack Requests Blocked: {self.blocked_count-self.legit_blocked}")
        print(f"Percentage of Attacked Traffic Blocked: {(self.blocked_count-self.legit_blocked)/self.att_req * 100:.2f}%")
        print(f"Percentage of Legitimate Traffic Blocked: {self.legit_blocked/self.legitimate_requests * 100:.2f}%")

    def get_prefix(self, ip_address, level):
        # Split IP address into octets
        octets = ip_address.split(".")
        # Build prefix based on the level
        if level == 0:
            return octets[0]+".0.0.0"  # /8
        elif level == 1:
            return ".".join(octets[:2])+".0.0"  # /16
        elif level == 2:
            return ".".join(octets[:3])+".0"  # /24
        else:
            return ip_address  # /32 (full IP address)

    def gen_now(self, subnets, num_requests, start_tstmp, pref_size):
        attack_traff = []
        timestamp = start_tstmp
        size = int(num_requests/len(subnets))
        splus = num_requests%len(subnets)
        subs = self.randomized_subnets(subnets,pref_size)
        all_ips = self.generate_ips_for_subnets(subs,size)
        random.shuffle(all_ips)
        for ip in all_ips:
            attack_traff.append((timestamp, ip,0))
            timestamp += random.randint(0, 1)  # Increment timestamp by a small random amount
        for i in range(0,splus):
             attack_traff.append((timestamp, all_ips[0],0))
             timestamp += random.randint(0, 1)  # Increment timestamp by a small random amount
        self.end_tstmp = timestamp
        return attack_traff


smltr = Simulator()
smltr.simulate_attack(300,4,0,2,10000,0.01)
smltr.printStats()
print(smltr.get_subnets())
# print("-----------------------------------------------")
# smltr.simulate_attack(300,3,0,2)
# smltr.printStats()

#A value is trying to be set on a copy of a slice from a DataFrame.
#Try using .loc[row_indexer,col_indexer] = value instead
