from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict

THRESHOLD = 20 # Number of unique ports scanned
ALERT_FILE = "logs/alerts.log"

port_scan_attempts = defaultdict(set)

def detect_port_scan(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_scan_attempts[src_ip].add(dst_port)
        
def detect_port_scan_signatures(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # NULL Scan (no flags set)
        if flags == 0:
            alert_msg = f"[SIGNATURE ALERT - Port Scan] NULL Scan from {src_ip} on port {dst_port}\n"
            print(alert_msg)
            with open(ALERT_FILE, "a") as log:
                log.write(alert_msg)

        # FIN Scan (only FIN flag)
        elif flags == "F":
            alert_msg = f"[SIGNATURE ALERT - Port Scan] FIN Scan from {src_ip} on port {dst_port}\n"
            print(alert_msg)
            with open(ALERT_FILE, "a") as log:
                log.write(alert_msg)

        # Xmas Scan (FIN, PSH, URG)
        elif flags == "FPU":
            alert_msg = f"[SIGNATURE ALERT - Port Scan] Xmas Scan from {src_ip} on port {dst_port}\n"
            print(alert_msg)
            with open(ALERT_FILE, "a") as log:
                log.write(alert_msg)

def check_port_scan():
    global port_scan_attempts
    for ip, ports in port_scan_attempts.items():
        if len(ports) > THRESHOLD:
            alert_msg = f" Port Scan Detected! IP: {ip} scanned {len(ports)} ports.\n"
            print(alert_msg)
            with open(ALERT_FILE, "a") as alert_log:
                alert_log.write(alert_msg)
    port_scan_attempts.clear()  # Reset tracking every cycle

# Run sniffing in the background
sniff(filter="tcp", prn=lambda pkt: (detect_port_scan(pkt), detect_port_scan_signatures(pkt)), store=False, timeout=5)

while True:
    check_port_scan()
    time.sleep(5)