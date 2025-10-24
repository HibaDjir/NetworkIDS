from scapy.all import sniff, IP, TCP, Raw
import time
from collections import defaultdict

THRESHOLD = 500  # Packets per 5 seconds
ALERT_FILE = "logs/alerts.log"

packet_count = defaultdict(int)

#  Abnormal Behavior Detection
MY_IP = "192.168.43.37"

def detect_dos(packet):
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip == MY_IP:
            return  # Skip your own IP
        packet_count[src_ip] += 1

def detect_dos_signatures(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        if src_ip == MY_IP:
            return  # Skip your own IP
        flags = packet[TCP].flags

        # Detect SYN Flood (SYN only)
        if flags == 0x02:
            alert_msg = f"[SIGNATURE ALERT - DoS] SYN Flood pattern from {src_ip}\n"
            print(alert_msg)
            with open(ALERT_FILE, "a") as log:
                log.write(alert_msg)

        # Detect Hping tool pattern
        if Raw in packet and b"Hping" in packet[Raw].load:
            alert_msg = f"[SIGNATURE ALERT - DoS] Hping tool detected from {src_ip}\n"
            print(alert_msg)
            with open(ALERT_FILE, "a") as log:
                log.write(alert_msg)


#  Check abnormal behavior threshold
def check_dos():
    global packet_count
    for ip, count in packet_count.items():
        if count > THRESHOLD:
            alert_msg = f"[ANOMALY ALERT - DoS] IP: {ip} sent {count} packets in 5 seconds\n"
            print(alert_msg)
            with open(ALERT_FILE, "a") as alert_log:
                alert_log.write(alert_msg)
    packet_count.clear()  # Reset counts every 5 seconds

#  Packet Sniffing Loop
def main():
    while True:
        sniff(filter="ip", prn=lambda pkt: (detect_dos(pkt), detect_dos_signatures(pkt)), store=False, timeout=5)
        check_dos()
        time.sleep(1)  # Optional buffer delay

if __name__ == "__main__":
    main()