import logging
from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import re
import time

# 🔹 Configure Logging
logging.basicConfig(
    filename="suspicious_activity.log",  # Log file name
    level=logging.INFO,                  # Set logging level to INFO
    format="%(asctime)s - %(message)s",  # Log format with timestamps
    datefmt="%Y-%m-%d %H:%M:%S"          # Timestamp format
)

# 🔹 Track packet counts per IP
packet_counts = defaultdict(lambda: {"count": 0, "ports": set(), "timestamp": time.time()})

# 🔹 Suspicious Payload Patterns (Basic SQL Injection, XSS)
suspicious_patterns = [
    r"(?i)union.*select",  # SQL Injection
    r"(?i)<script>.*</script>",  # XSS Attack
    r"(?i)or\s+\d=\d",  # SQL Injection Bypass
    r"(?i)drop\s+table",  # Database Manipulation Attempt
    r"(?i)1=1"  # Simple SQL Injection Test
]

# 🔹 Malicious Activity Scanner
def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Track Packet Count
        packet_counts[src_ip]["count"] += 1
        packet_counts[src_ip]["timestamp"] = time.time()

        #  Detect Port Scanning
        if TCP in packet or UDP in packet:
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
            packet_counts[src_ip]["ports"].add(sport)
            
            if len(packet_counts[src_ip]["ports"]) > 10:
                alert = f"🚨 Potential Port Scan Detected from {src_ip}"
                print(alert)
                logging.info(alert)

        #  Detect DoS/DDoS Attacks
        if packet_counts[src_ip]["count"] > 100:
            alert = f"🚨 Potential DoS Attack Detected from {src_ip}"
            print(alert)
            logging.info(alert)

        #  Detect Suspicious HTTP Payloads
        if Raw in packet and (TCP in packet and packet[TCP].dport == 80):
            payload = packet[Raw].load.decode(errors="ignore")

            for pattern in suspicious_patterns:
                if re.search(pattern, payload):
                    alert = f" Suspicious HTTP Request from {src_ip} → {dst_ip}: {payload}"
                    print(alert)
                    logging.info(alert)
                    break  # Avoid multiple alerts per packet

        # Print a summary of captured packets
        print(f"Packet: {src_ip} → {dst_ip} | {packet.summary()}")

# 🔹 Start Sniffing (Requires Admin Privileges)
sniff(prn=packet_handler, store=False)
