"""
pcaphunt - suspicious traffic detector

Reads a .pcap capture file and looks for signs of attacks:
port scans, ARP spoofing, cleartext credentials and suspicious DNS queries.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
from scapy.error import Scapy_Exception


# Detection settings
SCAN_THRESHOLD = 20                 # different ports from one source to one target
CLEARTEXT_PORTS = (21, 23, 80)      # FTP, Telnet, HTTP
KEYWORDS = ["user", "pass", "login", "authorization: basic"]
MAX_NAME_LENGTH = 60                # whole DNS name
MAX_LABEL_LENGTH = 30               # one part between the dots


def load_packets(filename):
    """Read a capture file. Stops the script with a clear message if it can't."""
    try:
        return rdpcap(filename)
    except FileNotFoundError:
        print(f"Error: file not found: {filename}")
        sys.exit(1)
    except Scapy_Exception:
        print(f"Error: {filename} is not a valid capture file (empty, or not pcap format)")
        sys.exit(1)


def count_protocols(packets):
    """Count packets per protocol. DNS is checked before UDP because DNS runs on top of UDP."""
    counts = Counter()
    for packet in packets:
        if DNS in packet:
            counts["DNS"] += 1
        elif TCP in packet:
            counts["TCP"] += 1
        elif UDP in packet:
            counts["UDP"] += 1
        elif ICMP in packet:
            counts["ICMP"] += 1
        elif ARP in packet:
            counts["ARP"] += 1
        else:
            counts["OTHER"] += 1
    return counts


def count_talkers(packets):
    """Count packets per source IPv4 address."""
    talkers = Counter()
    for packet in packets:
        if IP in packet:
            talkers[packet[IP].src] += 1
    return talkers


def detect_port_scans(packets):
    """Find sources that send SYNs to many different ports of one target."""
    syn_ports = defaultdict(set)
    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[TCP].flags == "S":
                source = packet[IP].src
                target = packet[IP].dst
                syn_ports[(source, target)].add(packet[TCP].dport)

    findings = []
    for (source, target), ports in syn_ports.items():
        if len(ports) > SCAN_THRESHOLD:
            findings.append({
                "type": "Port scan",
                "detail": f"{source} -> {target} ({len(ports)} ports)",
            })
    return findings


def detect_arp_spoofing(packets):
    """Find IPs claimed by more than one MAC address in ARP replies."""
    ip_to_macs = defaultdict(set)
    for packet in packets:
        if ARP in packet and packet[ARP].op == 2:
            ip_to_macs[packet[ARP].psrc].add(packet[ARP].hwsrc)

    findings = []
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            findings.append({
                "type": "ARP spoofing",
                "detail": f"{ip} claimed by {len(macs)} MACs: {', '.join(sorted(macs))}",
            })
    return findings


def mask_secrets(text):
    """Hide password values so the report never shows real credentials."""
    text = re.sub(r"(pass(?:word)?\s*[=:\s]\s*)[^&\s]+", r"\1****", text)
    text = re.sub(r"(authorization:\s*basic\s+)\S+", r"\1****", text)
    return text


def detect_cleartext_credentials(packets):
    """Find login data sent without encryption (FTP, Telnet, HTTP)."""
    findings = []
    for packet in packets:
        if IP in packet and TCP in packet and Raw in packet:
            if packet[TCP].dport in CLEARTEXT_PORTS:
                text = packet[Raw].load.decode(errors="ignore").lower()
                for keyword in KEYWORDS:
                    if keyword in text:
                        one_line = " ".join(text.split())     # remove line breaks and extra spaces
                        findings.append({
                            "type": "Cleartext credentials",
                            "detail": f"{packet[IP].src} -> {packet[IP].dst}:{packet[TCP].dport} | {mask_secrets(one_line)[:80]}",
                        })
                        break
    return findings


def detect_suspicious_dns(packets):
    """Find DNS queries with very long names or very long parts (tunneling, random domains)."""
    findings = []
    reported = set()
    for packet in packets:
        if DNSQR in packet:
            name = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            if name in reported:
                continue

            longest_label = 0
            for label in name.split("."):
                if len(label) > longest_label:
                    longest_label = len(label)

            if len(name) > MAX_NAME_LENGTH or longest_label > MAX_LABEL_LENGTH:
                findings.append({
                    "type": "Suspicious DNS",
                    "detail": f"{name} (length {len(name)}, longest part {longest_label})",
                })
                reported.add(name)
    return findings


def print_report(filename, packets, protocols, talkers, findings):
    """Print the full analysis to the screen."""
    print("=" * 60)
    print(f"pcaphunt report: {filename} ({len(packets)} packets)")
    print("=" * 60)

    print("\nProtocols:")
    for protocol, count in protocols.most_common():
        print(f"  {protocol}: {count}")

    print("\nTop 5 talkers (source IP):")
    for ip, count in talkers.most_common(5):
        print(f"  {ip}: {count} packets")

    print(f"\nFindings ({len(findings)}):")
    if not findings:
        print("  No suspicious activity detected.")
    for finding in findings:
        print(f"  [ALERT] {finding['type']}: {finding['detail']}")
    print("=" * 60)


def save_json(filename, packets, protocols, talkers, findings, output_file):
    """Save the results as a JSON report."""
    report = {
        "file": filename,
        "packets": len(packets),
        "protocols": dict(protocols),
        "top_talkers": dict(talkers.most_common(5)),
        "findings": findings,
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)
    print(f"Report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Detect suspicious activity in a pcap capture file.")
    parser.add_argument("pcap", help="capture file to analyze (.pcap)")
    parser.add_argument("--json", metavar="FILE", help="also save the results to a JSON file")
    args = parser.parse_args()

    packets = load_packets(args.pcap)
    protocols = count_protocols(packets)
    talkers = count_talkers(packets)

    findings = []
    findings += detect_port_scans(packets)
    findings += detect_arp_spoofing(packets)
    findings += detect_cleartext_credentials(packets)
    findings += detect_suspicious_dns(packets)

    print_report(args.pcap, packets, protocols, talkers, findings)

    if args.json:
        save_json(args.pcap, packets, protocols, talkers, findings, args.json)


if __name__ == "__main__":
    main()