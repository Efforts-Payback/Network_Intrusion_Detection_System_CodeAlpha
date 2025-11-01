from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
from collections import defaultdict
import sys, os, threading

# --- Fix encoding issues for Windows ---
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# --- CSV setup ---
filename = f"intrusion_log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
with open(filename, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Alert Type", "Source IP", "Destination IP", "Details"])

# --- Global counters ---
total_packets = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0
alert_count = 0
lock = threading.Lock()

# --- Packet tracking for detection logic ---
packet_count = defaultdict(int)

print("🚀 Starting Python-Based Intrusion Detection System (IDS)...")
print("📊 Press Ctrl+C or stop execution to end scan.\n")

def analyze_packet(packet):
    """Analyze each captured packet and detect suspicious behavior."""
    global total_packets, tcp_count, udp_count, icmp_count, other_count, alert_count

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "OTHER"

        # Update counters
        with lock:
            total_packets += 1
            if proto == "TCP":
                tcp_count += 1
            elif proto == "UDP":
                udp_count += 1
            elif proto == "ICMP":
                icmp_count += 1
            else:
                other_count += 1

        # Track source packet frequency
        packet_count[src] += 1
        alert = None

        # --- Detection rules ---
        if packet_count[src] > 5:
            alert = f"[!] Possible DoS attack from {src}"
        elif packet.haslayer(ICMP):
            alert = f"[ICMP] Ping detected from {src}"
        elif packet.haslayer(TCP) and packet[TCP].dport == 21:
            alert = f"[FTP] Possible FTP login attempt from {src}"
        elif packet.haslayer(TCP) and packet[TCP].dport == 8080:
            alert = f"[HTTP] Suspicious HTTP traffic on port 8080 from {src}"

        # Show counters
        print(
            f"\rPackets: {total_packets} | TCP: {tcp_count} | UDP: {udp_count} | ICMP: {icmp_count} | Alerts: {alert_count}",
            end="" "\n")

        # --- If any alert detected ---
        if alert:
            alert_count += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[{timestamp}] {alert} -> {dst}")
            with open(filename, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, alert, src, dst, f"Protocol: {proto}"])

def print_summary():
    """Display summary when scan stops."""
    print("\n\n🧾 Intrusion Detection Summary:")
    print(f"Total Packets: {total_packets}")
    print(f"TCP: {tcp_count}")
    print(f"UDP: {udp_count}")
    print(f"ICMP: {icmp_count}")
    print(f"Other: {other_count}")
    print(f"Alerts Detected: {alert_count}")
    print(f"\nLogs saved to: {filename}")

# --- Main execution ---
try:
    sniff(prn=analyze_packet, store=False)
except KeyboardInterrupt:
    pass
finally:
    # No matter how it stops, print summary
    print_summary()
