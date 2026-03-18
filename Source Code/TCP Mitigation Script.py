from scapy.all import sniff, TCP, IP, get_if_list # TCP, IP are classes and the others are functions
from datetime import datetime, timedelta # timedelta -> represents the difference between two dates or times
from collections import defaultdict # A specialized dictionary that returns a default value (an empty list) for missing keys.
import pandas as pd
import matplotlib.pyplot as plt
import threading
import smtplib # Module for sending emails 
from email.mime.text import MIMEText # Used for formatting and structuring the email message
from email.mime.multipart import MIMEMultipart # Used for formatting and structuring the email message
import subprocess # Allows you to run system commands
import os # Access to os level functionality

# Threshold configuration
SYN_THRESHOLD = int(input("Enter SYN packet threshold: ")) 
TIME_WINDOW = timedelta(seconds=int(input("Enter time window in seconds: "))) 

# Initialize packet counters
normal_syn_packet_counts = []
malicious_syn_packet_counts = []
syn_timestamps = defaultdict(list)
attack_counts = defaultdict(int)
blocked_ips = set()
attack_log = pd.DataFrame(columns=["Time", "Source IP", "SYN Count", "Additional Info"])

# Thread-safe lock for data synchronization
data_lock = threading.Lock()

# Email Configuration
EMAIL_RATE_LIMIT = timedelta(minutes=1)
last_email_time = defaultdict(lambda: datetime.min)

# Rate-limiting for SYN Flood Detection
last_detection_time = defaultdict(lambda: datetime.min)
RATE_LIMIT_TIME_WINDOW = timedelta(seconds=1) 

# Define the target port
TARGET_PORT = 9999

def send_email_alert(subject, body, ip, last_email_time, email_rate_limit=timedelta(minutes=1)):
    """
    Sends a rate-limited email alert for SYN flood attack.
    """
    current_time = datetime.now()

    # Check if the email should be sent (rate-limited)
    if current_time - last_email_time.get(ip, datetime.min) > email_rate_limit:
        # Retrieve credentials from environment variables
        sender_email = os.getenv("SENDER_EMAIL")
        receiver_email = os.getenv("RECEIVER_EMAIL")
        password = os.getenv("EMAIL_PASSWORD")
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        if not sender_email or not receiver_email or not password:
            print("Error: Email credentials not set in environment variables.")
            return

        # Log which email addresses are used (mask sensitive info for security)
        print(f"Fetched credentials: SENDER_EMAIL={sender_email}, RECEIVER_EMAIL={receiver_email}")

        msg = MIMEMultipart() # creates multipart email
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain')) # formats body as plain text

        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()  # Start TLS encryption
            server.login(sender_email, password)  # Login with sender's email credentials
            server.sendmail(sender_email, receiver_email, msg.as_string())  # Send the email
            server.quit()  # Close the SMTP connection
            print(f"Email sent to {receiver_email}")
            # Update last email sent time
            last_email_time[ip] = current_time
        except Exception as e:
            print(f"Failed to send email: {e}")
    else:
        print(f"Email rate-limited for {ip}, try again later.")

# $env:SENDER_EMAIL="your_email@gmail.com"
# $env:RECEIVER_EMAIL="receiver_email@gmail.com"
# $env:EMAIL_PASSWORD="your_password"

def log_attack(ip, count, packet):
    timestamp = datetime.now()
    additional_info = f"Packet details: {packet.summary()}"
    attack_log.loc[len(attack_log)] = [timestamp, ip, count, additional_info]
    
    # Append to the file if it exists, else create it
    attack_log.to_csv("attack_log.csv", mode='a', header=not os.path.exists('attack_log.csv'), index=False) # tells pandas to not write index column
    print(f"Logged attack from {ip}: {count} packets.")


def is_rule_exists(rule_name):
    """Check if the firewall rule already exists."""
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=" + rule_name],
            check=True, capture_output=True, text=True # capture_output=True -> ensures that i/o is captures & text=True -> ensures its is retured as a string
        )
        # If the rule exists, return True, else False
        return rule_name in result.stdout
    except subprocess.CalledProcessError:
        return False  # Rule does not exist

def block_ip(ip):
    """
    Blocks the given IP using Windows firewall after detecting multiple attacks.
    Ensures that the rules are only added if they don't already exist.
    Requires administrative privileges to run the `netsh` command.
    """
    try:
        # Block inbound traffic
        inbound_rule_name = f"Block_In_{ip}"
        if not is_rule_exists(inbound_rule_name):
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + inbound_rule_name,
                     "dir=in", "action=block", "remoteip=" + ip],
                    check=True, capture_output=True, text=True
                )
                print(f"Inbound traffic from IP {ip} is now blocked.")
            except subprocess.CalledProcessError as e:
                raise Exception(f"Error occurred while blocking inbound IP {ip}: {e}")

        # Block outbound traffic
        outbound_rule_name = f"Block_Out_{ip}"
        if not is_rule_exists(outbound_rule_name):
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + outbound_rule_name,
                     "dir=out", "action=block", "remoteip=" + ip],
                    check=True, capture_output=True, text=True
                )
                print(f"Outbound traffic to IP {ip} is now blocked.")
            except subprocess.CalledProcessError as e:
                raise Exception(f"Error occurred while blocking outbound IP {ip}: {e}")

        # Log the IP block to a file only if it's not already logged
        if ip not in blocked_ips:
            blocked_ips.add(ip)
            with open("blocked_ips_log.txt", "a") as log_file:
                log_file.write(f"{datetime.now()}: IP {ip} blocked (both inbound and outbound).\n")
            print(f"IP {ip} logged as blocked.")

    except Exception as ex:
        print(f"Unexpected error occurred: {ex}")

def kill_connections(ip, port):
    """Kill active connections from the specified IP and port."""
    # Run netstat to find connections to the specific IP and port
    netstat_output = os.popen(f'netstat -ano | findstr "{ip}:{port}"').read()
    
    # If there are connections matching the IP and port, kill the corresponding processes
    if netstat_output:
        for line in netstat_output.splitlines():# This splits the output into individual lines, where each line represents a separate network connection.
            pid = line.split()[-1]  # Extract the PID, split -> line into a string & [-1] -> last item in the line = PID
            print(f"Killing process with PID: {pid}")
            os.system(f"taskkill /PID {pid} /F")
    else:
        print(f"No connections found for IP {ip} on port {port}")


def rate_limit_ip(ip):
    """Rate-limiting function to prevent detecting the same IP too frequently."""
    current_time = datetime.now()
    if current_time - last_detection_time[ip] < RATE_LIMIT_TIME_WINDOW:
        print(f"Rate limiting IP {ip}, skipping redundant detection.")
        return True
    last_detection_time[ip] = current_time
    return False # Allows detection if rate limiting isn't met

def detect_syn(packet):
    """
    Detects and categorizes SYN packets as normal or malicious for a specific port (TARGET_PORT).
    """
    if packet.haslayer(TCP) and packet[TCP].flags == "S" and packet[TCP].dport == TARGET_PORT:
        source_ip = packet[IP].src
        current_time = datetime.now()

        # Rate limit IP detections to avoid redundant checks
        if rate_limit_ip(source_ip):
            return

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

                # Send detailed email alert (rate-limited)
                email_subject = f"SYN Flood Attack Detected from {source_ip}"
                email_body = (f"Attack Details:\n"
                              f"Source IP: {source_ip}\n"
                              f"SYN Packet Count: {syn_count}\n"
                              f"Timestamp: {current_time}\n"
                              f"Packet Summary: {packet.summary()}")
                send_email_alert(email_subject, email_body, source_ip, last_email_time)

                # Increment attack count
                attack_counts[source_ip] += 1
                if attack_counts[source_ip] >= 3:
                    # Block the IP after 3 attacks (not immediately)
                    block_ip(source_ip)
                    kill_connections(source_ip, TARGET_PORT) # Immediately kill malicious connections
            else:
                # Normal packet
                normal_syn_packet_counts.append((current_time, len(normal_syn_packet_counts) + 1))

def get_network_interface():
    """
    Prompts the user to select a network interface for sniffing.
    """
    scapy_interfaces = get_if_list() # Retrieves a kist of interfaces
    print("Available interfaces:", scapy_interfaces)

    for i, iface in enumerate(scapy_interfaces): # enumerate generates both the index (i) and the value (iface)
        print(f"{i + 1}. {iface}")
    choice = int(input("Select the interface number to sniff on: ")) - 1

    if choice < 0 or choice >= len(scapy_interfaces):
        raise ValueError("Invalid choice for network interface!")
    return scapy_interfaces[choice]

def start_sniffing():
    """
    Starts sniffing SYN packets on the selected network interface for the target port.
    """
    iface = get_network_interface() # Gets the iface from user
    print(f"Sniffing on interface: {iface}")
    sniff(iface=iface, filter=f"tcp port {TARGET_PORT} and tcp[tcpflags] & tcp-syn != 0", prn=detect_syn)

# def mock_sniffing():
#     for i in range(100):
#         time.sleep(0.5)
#         with data_lock:
#             normal_syn_packet_counts.append((i, i % 10))
#             malicious_syn_packet_counts.append((i, (i * 2) % 10))

def update_plot():
    """
    Updates the real-time plot for normal and malicious SYN packets.
    """
    plt.ion()  # Enable interactive mode -> allows dynamic updates without blocking the rest of the code
    fig, ax = plt.subplots(figsize=(12, 6))  # Create figure and axes
    max_updates = 500  # Limit updates for testing
    
    for _ in range(max_updates):
        with data_lock:
            # Extract times and counts for normal and malicious packets
            normal_times, normal_counts = zip(*normal_syn_packet_counts) if normal_syn_packet_counts else ([], []) # Extract timestamps & counts
                                                                                                        # If the lists are empty,assigns empty lists to the variables
            malicious_times, malicious_counts = zip(*malicious_syn_packet_counts) if malicious_syn_packet_counts else ([], [])
        
        ax.clear()  # Clear the axes for new data
        ax.plot(normal_times, normal_counts, label="Normal SYN Packets", color="blue")
        ax.plot(malicious_times, malicious_counts, label="Malicious SYN Packets", color="red")
        
        ax.set_title("Real-Time SYN Packet Analysis")
        ax.set_xlabel("Time")
        ax.set_ylabel("SYN Packet Count")
        ax.legend()
        ax.grid(True) # Grid is added for better visualization
        
        plt.pause(1)  # Pause for a second to allow real-time updates
    
    plt.ioff()  # Disable interactive mode
    plt.close(fig)  # Explicitly close the figure to free resources
    

# # Start mock sniffing in a separate thread
# sniff_thread = threading.Thread(target=mock_sniffing)
# sniff_thread.start()

# # Update the plot in the main thread
# update_plot()

# sniff_thread.join()


# Start sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

# Update the plot in the main thread
update_plot()

sniff_thread.join()
