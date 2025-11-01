### 🧠 Network Intrusion Detection System (IDS)

This project was developed as part of my internship at CodeAlpha.
It’s a Python-based Intrusion Detection System (IDS) that monitors live network traffic, detects suspicious behavior, and logs alerts in real time.

## 🚀 Features

📡 Captures live network packets using Scapy
🔍 Detects potential threats such as:

ICMP ping activity
FTP login attempts
Suspicious HTTP traffic

DoS-like repeated requests from the same IP
🧾 Automatically saves all alerts to a CSV file
📊 Displays live traffic counters and a full summary when the scan stops
✅ Works on Windows (requires Admin privileges)

## 🧩 Tools & Technologies

Language: Python
Library: Scapy
IDE: PyCharm
Platform: Windows 10 / 11

## ⚙️ Installation & Setup

# Clone this repository:
git clone https://github.com/Efforts-Payback/Network_Intrusion_Detection_System_CodeAlpha/edit/main/


# Navigate into the folder:
cd CodeAlpha_Network_Intrusion_Detection_System


# Install required library:
pip install scapy


# Run the script (as Administrator):
python python_ids_final_autosummary.py


## 🧠 How It Works
--> The system starts sniffing live network traffic.
--> Each packet is analyzed for suspicious activity.
--> Alerts are printed in real-time.
--> A summary is automatically displayed when scanning stops.
--> All detected alerts are logged into a .csv report file.

# 📂 Output Example

🚀 Starting Python-Based Intrusion Detection System (IDS)...
📊 Press Ctrl+C or stop execution to end scan.

Packets: 250 | TCP: 120 | UDP: 80 | ICMP: 50 | Alerts: 3
[2025-11-01 15:10:45] [ICMP] Ping detected from 192.168.0.12 -> 8.8.8.8
[2025-11-01 15:10:50] [!] Possible DoS attack from 192.168.0.15 -> 192.168.0.1

🧾 Intrusion Detection Summary:
Total Packets: 255
TCP: 122
UDP: 81
ICMP: 52
Alerts Detected: 3

Logs saved to: intrusion_log_2025-11-01_15-10-44.csv

## 🎯 Learning Outcomes

--> Understood the basics of network traffic analysis
--> Explored rule-based detection using Python
--> Learned how to automate alert generation and logging
--> Strengthened concepts in cybersecurity and networking
