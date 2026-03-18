from scapy.all import sniff, TCP, IP, get_if_list
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess

# Threshold configuration
SYN_THRESHOLD = int(input("Enter SYN packet threshold: "))
TIME_WINDOW = timedelta(seconds=int(input("Enter time window in seconds: ")))

# Initialize packet counters
normal_syn_packet_counts = []
malicious_syn_packet_counts = []
syn_timestamps = defaultdict(list)
blocked_ips = set()
attack_log = pd.DataFrame(columns=["Time", "Source IP", "SYN Count", "Additional Info"])

# Thread-safe lock for data synchronization
data_lock = threading.Lock()

# Email Configuration
EMAIL_RATE_LIMIT = timedelta(minutes=1)
last_email_time = defaultdict(lambda: datetime.min)

def send_email(subject, body):
    sender_email = "vesq3hrmeow@gmail.com"
    receiver_email = "ibrargoraya477@gmail.com"
    password = "johs sqov rfty xhtl"  # Replace with your email password
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

def log_attack(ip, count, packet):
    timestamp = datetime.now()
    additional_info = f"Packet details: {packet.summary()}"
    attack_log.loc[len(attack_log)] = [timestamp, ip, count, additional_info]
    attack_log.to_csv("attack_log.csv", index=False)
    print(f"Logged attack from {ip}: {count} packets.")

def block_ip(ip):
    if ip not in blocked_ips:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=Block_" + ip, "dir=in", "action=block", "remoteip=" + ip])
        blocked_ips.add(ip)
        print(f"IP {ip} is now blocked due to exceeding SYN packet threshold!")
        with open("blocked_ips_log.txt", "a") as log_file:
            log_file.write(f"{datetime.now()}: IP {ip} blocked.\n")

def detect_syn(packet):
    """
    Detects and categorizes SYN packets as normal or malicious.
    """
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        source_ip = packet[IP].src
        current_time = datetime.now()

        with data_lock:
            # Update SYN timestamps for the source IP
            syn_timestamps[source_ip].append(current_time)
            syn_timestamps[source_ip] = [
                timestamp for timestamp in syn_timestamps[source_ip]
                if timestamp > current_time - TIME_WINDOW
            ]

            syn_count = len(syn_timestamps[source_ip])
            print(f"SYN packet detected from {source_ip}: {syn_count} times")

            if syn_count > SYN_THRESHOLD:
                # Malicious packet
                print(f"Potential SYN flood attack detected from {source_ip}!")
                malicious_syn_packet_counts.append((current_time, len(malicious_syn_packet_counts) + 1))
                log_attack(source_ip, syn_count, packet)
                
                # Send email alert (rate-limited)
                global last_email_time
                if datetime.now() - last_email_time[source_ip] > EMAIL_RATE_LIMIT:
                    send_email("SYN Flood Attack Detected", f"Attack from {source_ip} with {syn_count} SYN packets.")
                    last_email_time[source_ip] = datetime.now()

                # Block IP
                block_ip(source_ip)
            else:
                # Normal packet
                normal_syn_packet_counts.append((current_time, len(normal_syn_packet_counts) + 1))

def get_network_interface():
    """
    Prompts the user to select a network interface for sniffing.
    """
    scapy_interfaces = get_if_list()
    print("Available interfaces:", scapy_interfaces)

    for i, iface in enumerate(scapy_interfaces):
        print(f"{i + 1}. {iface}")
    choice = int(input("Select the interface number to sniff on: ")) - 1

    if choice < 0 or choice >= len(scapy_interfaces):
        raise ValueError("Invalid choice for network interface!")
    return scapy_interfaces[choice]

def start_sniffing():
    """
    Starts sniffing SYN packets on the selected network interface.
    """
    iface = get_network_interface()
    print(f"Sniffing on interface: {iface}")
    sniff(iface=iface, filter="tcp[tcpflags] & tcp-syn != 0", prn=detect_syn)

def update_plot():
    """
    Updates the real-time plot for normal and malicious SYN packets.
    """
    plt.ion()
    fig, ax = plt.subplots(figsize=(12, 6))

    while True:
        with data_lock:
            # Extract times and counts for normal and malicious packets
            normal_times, normal_counts = zip(*normal_syn_packet_counts) if normal_syn_packet_counts else ([], [])
            malicious_times, malicious_counts = zip(*malicious_syn_packet_counts) if malicious_syn_packet_counts else ([], [])

        ax.clear()
        ax.plot(normal_times, normal_counts, label="Normal SYN Packets", color="blue")
        ax.plot(malicious_times, malicious_counts, label="Malicious SYN Packets", color="red")

        ax.set_title("Real-Time SYN Packet Analysis")
        ax.set_xlabel("Time")
        ax.set_ylabel("SYN Packet Count")
        ax.legend()
        ax.grid(True)
        plt.pause(1)  # Update every second

    plt.ioff()

# Start sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

# Update the plot in the main thread
update_plot()

sniff_thread.join()
