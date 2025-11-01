# 🧠 Network Intrusion Detection System (IDS)

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

### ⚙️ Installation & Setup

### Clone this repository:
git clone https://github.com/Efforts-Payback/Network_Intrusion_Detection_System_CodeAlpha/edit/main/


### Navigate into the folder:
cd CodeAlpha_Network_Intrusion_Detection_System


### Install required library:
pip install scapy


### Run the script (as Administrator):
python python_ids_final_autosummary.py


## 🧠 How It Works
--> The system starts sniffing live network traffic. <br>
--> Each packet is analyzed for suspicious activity. <br>
--> Alerts are printed in real-time. <br>
--> A summary is automatically displayed when scanning stops. <br>
--> All detected alerts are logged into a .csv report file. <br>

## 📂 Output Example

🚀 Starting Python-Based Intrusion Detection System (IDS)... <br>
📊 Press Ctrl+C or stop execution to end scan. <br>
<br>
Packets: 250 | TCP: 120 | UDP: 80 | ICMP: 50 | Alerts: 3 <br>
[2025-11-01 15:10:45] [ICMP] Ping detected from 192.168.0.12 -> 8.8.8.8 <br>
[2025-11-01 15:10:50] [!] Possible DoS attack from 192.168.0.15 -> 192.168.0.1 <br>
<br>
🧾 Intrusion Detection Summary: <br>
Total Packets: 255 <br>
TCP: 122 <br>
UDP: 81 <br>
ICMP: 52 <br>
Alerts Detected: 3 <br>
<br>
Logs saved to: intrusion_log_2025-11-01_15-10-44.csv <br>

## 🎯 Learning Outcomes

--> Understood the basics of network traffic analysis <br>
--> Explored rule-based detection using Python <br>
--> Learned how to automate alert generation and logging <br>
--> Strengthened concepts in cybersecurity and networking <br>
