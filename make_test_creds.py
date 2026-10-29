from scapy.all import IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.20"
SERVER = "10.0.0.10"

packets = [
    # FTP login: should alert twice (USER and PASS)
    IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=21) / Raw(load=b"USER karim\r\n"),
    IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=21) / Raw(load=b"PASS secret123\r\n"),
    # HTTP login form: should alert
    IP(src=CLIENT, dst=SERVER) / TCP(sport=50001, dport=80) / Raw(load=b"POST /login HTTP/1.1\r\nHost: test\r\n\r\nusername=admin&password=1234"),
    # Normal HTTP page request: should NOT alert
    IP(src=CLIENT, dst=SERVER) / TCP(sport=50002, dport=80) / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: test\r\n\r\n"),
]

wrpcap("test_creds.pcap", packets)
print("Wrote test_creds.pcap")