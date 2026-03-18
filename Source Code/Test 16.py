from scapy.all import sniff, TCP, IP, get_if_list
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess
import pandas as pd
import matplotlib
matplotlib.use('TkAgg')  # Use TkAgg backend for GUI environments
import matplotlib.pyplot as plt
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading

# Track SYN packet timestamps per source IP
syn_timestamps = defaultdict(list)
blocked_ips = set()
attack_count = defaultdict(int)

# Threshold configuration via user input
SYN_THRESHOLD = int(input("Enter SYN packet threshold: "))
TIME_WINDOW = timedelta(seconds=int(input("Enter time window in seconds: ")))

# Initialize pandas DataFrame for logging attacks
attack_log = pd.DataFrame(columns=["Time", "Source IP", "SYN Count", "Additional Info"])

# Rate Limiting Email Alerts
last_email_time = defaultdict(lambda: datetime.min)
EMAIL_RATE_LIMIT = timedelta(minutes=1)  # Rate limit emails to once per minute per IP

def send_email(subject, body):
    sender_email = "vesq3hrmeow@gmail.com"
    receiver_email = "ibrargoraya477@gmail.com"
    password = "johs sqov rfty xhtl"  # replace with your actual email password
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
            log_attack(source_ip, syn_count, packet)
            send_email_alert(source_ip, syn_count)
            block_ip(source_ip)

            # Real-time alert for attack detection
            real_time_alert(f"Potential SYN flood attack detected from {source_ip} with {syn_count} SYN packets.")

def rate_limit_ip(ip):
    if ip in blocked_ips:
        print(f"Rate limiting IP {ip}. Delaying request...")
        time.sleep(1)

def block_ip(ip):
    attack_count[ip] += 1  # Increment the attack count for the source IP
    if attack_count[ip] >= 3:  # Block after 3 attacks
        if ip not in blocked_ips:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=Block_" + ip, "dir=in", "action=block", "remoteip=" + ip])
            blocked_ips.add(ip)
            print(f"IP {ip} is now blocked due to exceeding SYN packet threshold!")
            log_block(ip)

def send_email_alert(source_ip, syn_count):
    # Prevent excessive email sending by rate limiting
    global last_email_time
    if datetime.now() - last_email_time[source_ip] > EMAIL_RATE_LIMIT:
        subject = "SYN Flood Attack Detected"
        body = f"A SYN flood attack was detected from IP: {source_ip}. SYN Count: {syn_count}"
        send_email(subject, body)
        last_email_time[source_ip] = datetime.now()  # Update last email sent time

def log_attack(ip, count, packet):
    timestamp = datetime.now()
    additional_info = f"Packet details: {packet.summary()}"
    attack_log.loc[len(attack_log)] = [timestamp, ip, count, additional_info]
    attack_log.to_csv("attack_log.csv", index=False)
    print(f"Logged attack from {ip}: {count} packets.")

def log_block(ip):
    with open("blocked_ips_log.txt", "a") as log_file:
        log_file.write(f"IP {ip} blocked due to exceeding SYN threshold.\n")

# Real-Time Alerts (Dashboard)
def real_time_alert(message):
    print(f"[ALERT]: {message}")

# Function to get the network interface
def get_network_interface():
    scapy_interfaces = get_if_list()
    print("Available interfaces:", scapy_interfaces)

    # Let the user pick a valid interface if multiple are found
    for i, iface in enumerate(scapy_interfaces):
        print(f"{i + 1}. {iface}")
    choice = int(input("Select the interface number to sniff on: ")) - 1

    if choice < 0 or choice >= len(scapy_interfaces):
        raise ValueError("Invalid choice for network interface!")

    return scapy_interfaces[choice]

# Start sniffing
def start_sniffing():
    iface = get_network_interface()
    print(f"Sniffing on interface: {iface}")
    sniff(iface=iface, filter="tcp[tcpflags] & tcp-syn != 0", prn=detect_syn)

# Initialize plot with larger figure size
fig, ax = plt.subplots(figsize=(50, 36))  # Larger figure size for better visibility

def plot_attack_patterns():
    """Plot attack patterns based on the attack log."""
    if not attack_log.empty:
        ip_counts = attack_log.groupby("Source IP")["SYN Count"].sum().reset_index()
        ax.clear()  # Clear the previous plot
        ip_counts.plot(kind="bar", x="Source IP", y="SYN Count", ax=ax, title="SYN Packet Distribution by IP", legend=False)
        ax.set_xlabel("Source IP")
        ax.set_ylabel("SYN Packet Count")

        # Update the plot window
        plt.draw()
        plt.pause(0.01)  # Pause to allow the plot to refresh

def update_plot():
    """Continuously update the plot in real-time."""
    while sniff_thread.is_alive():  # Keep updating while sniffing
        plot_attack_patterns()
        time.sleep(2)  # Update every 2 seconds

# Start the real-time plot update in a separate thread
plot_thread = threading.Thread(target=update_plot)

# Start sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)

sniff_thread.start()
plot_thread.start()

# Wait for sniffing to finish and then join threads
sniff_thread.join()
plot_thread.join()

# Save the plot as an image
fig.savefig("syn_flood_attack_plot.png", dpi=150, bbox_inches="tight")

plt.show()  # Keep the plot window open
