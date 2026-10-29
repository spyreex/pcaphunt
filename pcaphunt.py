from collections import Counter, defaultdict                               
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Raw

filename = "capture3.pcap"
packets = rdpcap(filename)
print(f"Loaded {len(packets)} packets from {filename}")         

for number, packet in enumerate(packets[:10], start=1):          
    print(f"#{number}: {packet.summary()}")                      

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
ip_to_macs=defaultdict(set)
for packet in packets:
    if ARP in packet and packet[ARP].op==2:
        ip=packet[ARP].psrc
        mac=packet[ARP].hwsrc
        ip_to_macs[ip].add(mac)
print()
print("ARP spoofing check:")
found=0
for ip,macs in ip_to_macs.items():
    if len(macs)>1:
        print(f"[ALERT] Possible ARP spoofing: {ip} claimed by {len(macs)} MACs:{macs}")
        found +=1
if not found:
    print("no ARP spoofing detected")


CLEARTEXT_PORTS = (21, 23, 80)
KEYWORDS = ["user", "pass", "login", "authorization: basic"]

print()
print("Cleartext credentials check:")
found = 0
for packet in packets:
    if IP in packet and TCP in packet and Raw in packet:
        if packet[TCP].dport in CLEARTEXT_PORTS:
            text = packet[Raw].load.decode(errors="ignore").lower()
            for keyword in KEYWORDS:
                if keyword in text:
                    print(f"[ALERT] Cleartext login data: {packet[IP].src} -> {packet[IP].dst}:{packet[TCP].dport} | {text[:80]}")
                    found += 1
                    break

if not found:
    print("No cleartext credentials detected.")