from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        size = len(packet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto_name = "ICMP"
            sport = "-"
            dport = "-"
        else:
            proto_name = str(proto)
            sport = "-"
            dport = "-"

        log_line = f"[{timestamp}] [{proto_name}] {ip_src}:{sport} --> {ip_dst}:{dport} | Size: {size} bytes"
        print(log_line)

        # 
        with open("log.txt", "a") as f:
            f.write(log_line + "\n")

print("🔍 Starting Network Sniffer with Logging... (Ctrl+C to stop)\n")
sniff(prn=packet_callback, store=False)
