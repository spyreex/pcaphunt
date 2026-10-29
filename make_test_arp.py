from scapy.all import Ether, ARP, wrpcap

ROUTER_IP = "192.168.1.1"
REAL_MAC = "48:12:58:d7:7e:5a"
FAKE_MAC = "de:ad:be:ef:00:01"

packets = [
    Ether() / ARP(op=2, psrc=ROUTER_IP, hwsrc=REAL_MAC),   # real router reply
    Ether() / ARP(op=2, psrc=ROUTER_IP, hwsrc=FAKE_MAC),   # attacker's fake reply
    Ether() / ARP(op=2, psrc=ROUTER_IP, hwsrc=REAL_MAC),   # real router again
]

wrpcap("test_arp.pcap", packets)
print("Wrote test_arp.pcap")