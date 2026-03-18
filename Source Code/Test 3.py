from scapy.all import sniff, TCP, IP
from datetime import datetime, timedelta  # timedelta is used to define a "Time Window"
from collections import defaultdict  # A special dictionary that returns a default value when a key is accessed that does not exist. 
                                    # It is used to store lists of timestamps for each source IP address.
import subprocess  # To run the system commands for blocking the IP

# Track SYN packet timestamps per source IP
syn_timestamps = defaultdict(list)  # This creates a dictionary that will store a list of timestamps(values) for each source IP(keys).

# Track blocked IPs (for simplicity in this case, we'll just use a list)
blocked_ips = set()  # We use a set to store blocked IPs (unique values)

# Threshold configuration
SYN_THRESHOLD = 50  # Max SYN packets we expect from a Source IP
TIME_WINDOW = timedelta(seconds=10)  # Time window to monitor SYN packets

# Function to process SYN packets and detect potential flood
def detect_syn(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # The layer function refers to a specific protocol.
                                            # TCP flags are special control bits in a TCP header.
                                            # S is part of the TCP three-way handshake (SYN, SYN-ACK, ACK)
        source_ip = packet[IP].src  # This extracts the source IP address from the IP layer of the packet.
        current_time = datetime.now()  # This records the current timestamp when the SYN packet is detected.

        # Skip processing for blocked IPs
        if source_ip in blocked_ips:
            return

        # Updating the current timestamp to the list of timestamps for this "Source IP"
        syn_timestamps[source_ip].append(current_time)

        # This part filters out any timestamps that are older than 10 seconds compared to the current time.
        syn_timestamps[source_ip] = [
            timestamp for timestamp in syn_timestamps[source_ip] if timestamp > current_time - TIME_WINDOW
                # Removes timestamps older than 10 seconds
        ]

        # Count the number of SYN packets within the time window
        syn_count = len(syn_timestamps[source_ip])

        print(f"SYN packet detected from {source_ip}: {syn_count} times")

        # If the number of SYN packets exceeds the threshold, it could be a SYN flood
        if syn_count > SYN_THRESHOLD:
            print(f"Potential SYN flood attack detected from {source_ip}!")
            log_attack(source_ip, syn_count)  # Function to log the details of the attack

            # Block the IP for future packets
            block_ip(source_ip)

# Function to block the IP using Windows Firewall (netsh command)
def block_ip(ip):
    if ip not in blocked_ips:
        # Run the netsh command to block the IP
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=Block_" + ip, "dir=in", "action=block", "remoteip=" + ip])
        blocked_ips.add(ip)
        print(f"IP {ip} is now blocked due to exceeding SYN packet threshold!")
        log_block(ip)  # Log this block action

# Function to log attack details to a file
def log_attack(ip, count):  # Append mode ("a") means that new data will be added to the end of the file, rather than overwriting.
    with open("syn_flood_log.txt", "a") as log_file:  # The details are written in a file named: syn_flood_log.txt
        log_file.write(f"Potential SYN flood from {ip}: {count} packets within {TIME_WINDOW.seconds} seconds\n")

# Function to log blocked IP details to a file
def log_block(ip):
    with open("blocked_ips_log.txt", "a") as log_file:  # Log file for blocked IPs
        log_file.write(f"IP {ip} blocked due to exceeding SYN threshold.\n")

# Start sniffing for SYN packets on the network interface (Computer's N/W Interface Card)
sniff(
    iface="\\Device\\NPF_{48FF4755-81B3-46DE-A13F-BCE7FFF0177D}",  # iface parameter specifies the network interface to monitor.
    filter="tcp[tcpflags] & tcp-syn != 0",  # This is a BPF (Berkeley Packet Filter) to only capture TCP SYN packets.
    prn=detect_syn,  # The prn parameter specifies a callback function.
                     # Whenever Scapy captures a packet from the network, it will pass the packet to the detect_syn function to analyze it.
)
