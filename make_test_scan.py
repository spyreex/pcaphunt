from scapy.all import IP, TCP, wrpcap

ATTACKER = "10.0.0.66"
VICTIM = "10.0.0.1"

packets = []
for port in range(1, 201):                       # ports 1 to 200
    syn = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000, dport=port, flags="S")
    packets.append(syn)

wrpcap("test_scan.pcap", packets)
print(f"Wrote {len(packets)} SYN packets to test_scan.pcap")
