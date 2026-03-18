from scapy.all import sniff, TCP, IP
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import time
import netifaces as ni
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Track SYN packet timestamps per source IP
syn_timestamps = defaultdict(list)
blocked_ips = set()

# Threshold configuration
SYN_THRESHOLD = 50
TIME_WINDOW = timedelta(seconds=10)

# Initialize pandas DataFrame for logging attacks
attack_log = pd.DataFrame(columns=["Time", "Source IP", "SYN Count"])

# Function to send an email notification (Alert) when an attack is detected
def send_email(subject, body):
    sender_email = "vesq3hrmeow@gmail.com"
    receiver_email = "ibrargoraya477@gmail.com"
    password = "your_password_here"

    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print(f"Email sent to {receiver_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to process SYN packets and detect potential flood
def detect_syn(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        source_ip = packet[IP].src
        current_time = datetime.now()

        if source_ip in blocked_ips:
            rate_limit_ip(source_ip)
            return

        syn_timestamps[source_ip].append(current_time)
        syn_timestamps[source_ip] = [
            timestamp for timestamp in syn_timestamps[source_ip] if timestamp > current_time - TIME_WINDOW
        ]

        syn_count = len(syn_timestamps[source_ip])
        print(f"SYN packet detected from {source_ip}: {syn_count} times")

        if syn_count > SYN_THRESHOLD:
            print(f"Potential SYN flood attack detected from {source_ip}!")
            log_attack(source_ip, syn_count)
            send_email("SYN Flood Attack Detected", f"A SYN flood attack was detected from IP: {source_ip}. SYN Count: {syn_count}")
            block_ip(source_ip)

def rate_limit_ip(ip):
    if ip in blocked_ips:
        print(f"Rate limiting IP {ip}. Delaying request...")
        time.sleep(1)

def block_ip(ip):
    if ip not in blocked_ips:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=Block_" + ip, "dir=in", "action=block", "remoteip=" + ip])
        blocked_ips.add(ip)
        print(f"IP {ip} is now blocked due to exceeding SYN packet threshold!")
        log_block(ip)

def log_attack(ip, count):
    timestamp = datetime.now()
    attack_log.loc[len(attack_log)] = [timestamp, ip, count]
    attack_log.to_csv("attack_log.csv", index=False)
    print(f"Logged attack from {ip}: {count} packets.")

def log_block(ip):
    with open("blocked_ips_log.txt", "a") as log_file:
        log_file.write(f"IP {ip} blocked due to exceeding SYN threshold.\n")

def plot_attack_patterns():
    if not attack_log.empty:
        ip_counts = attack_log.groupby("Source IP")["SYN Count"].sum().reset_index()
        ip_counts.plot(kind="bar", x="Source IP", y="SYN Count", title="SYN Packet Distribution by IP", legend=False)
        plt.xlabel("Source IP")
        plt.ylabel("SYN Packet Count")
        plt.show()

def get_network_interface():
    interfaces = ni.interfaces()
    valid_interfaces = []
    for iface in interfaces:
        try:
            addrs = ni.ifaddresses(iface)
            if ni.AF_INET in addrs:  # Check if the interface has an IPv4 address
                valid_interfaces.append(iface)
        except ValueError:
            continue

    if not valid_interfaces:
        raise Exception("No valid network interface found!")
    
    print("Valid interfaces:", valid_interfaces)
    return valid_interfaces[0]

def detect_ddos():
    global syn_timestamps
    for ip, timestamps in syn_timestamps.items():
        if len(timestamps) > 100:
            print(f"DDoS attack detected from IP {ip}!")
            block_ip(ip)

iface = get_network_interface()
print(f"Sniffing on interface: {iface}")
sniff(iface=iface, filter="tcp[tcpflags] & tcp-syn != 0", prn=detect_syn)
