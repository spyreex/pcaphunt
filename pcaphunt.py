from collections import Counter, defaultdict                               
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS

filename = "capture3.pcap"
packets = rdpcap(filename)
print(f"Loaded {len(packets)} packets from {filename}")         
# Stage 1: first 10 packets
for number, packet in enumerate(packets[:10], start=1):          
    print(f"#{number}: {packet.summary()}")                      

# Stage 2: count protocols and talkers
protocol_counts = Counter()
talkers = Counter()

for packet in packets:
    if DNS in packet:
        protocol_counts["DNS"] += 1
    elif TCP in packet:
        protocol_counts["TCP"] += 1
    elif UDP in packet:
        protocol_counts["UDP"] += 1
    elif ICMP in packet:                                         
        protocol_counts["ICMP"] += 1
    elif ARP in packet:
        protocol_counts["ARP"] += 1
    else:
        protocol_counts["OTHER"] += 1

    if IP in packet:
        talkers[packet[IP].src] += 1                              

# Printing section (new): shows the results
print()
print("Protocols:")
for protocol, count in protocol_counts.items():
    print(f"  {protocol}: {count}")

print()
print("Top 5 talkers (source IP):")
for ip, count in talkers.most_common(5):
    print(f"  {ip}: {count} packets")

SCAN_THRESHOLD=20
syn_ports=defaultdict(set)

for packet in packets:
    if IP in packet and TCP in packet:
        if packet[TCP].flags=="S":
            source= packet[IP].src
            target= packet[IP].dst
            port= packet[TCP].dport
            syn_ports[(source,target)].add(port)
print()
print("Port scan check:")
found=False
for(source,target), ports in syn_ports.items():
    if len(ports)>SCAN_THRESHOLD:
        print(f"[ALERT] possible port scan : {source} -> {target} ({len(ports)} ports) ")
        found=True
if not found:
    print("No port scans detected")