from scapy.all import sniff, TCP, IP, get_if_list
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import threading
import time

# Threshold configuration
SYN_THRESHOLD = int(input("Enter SYN packet threshold: "))
TIME_WINDOW = timedelta(seconds=int(input("Enter time window in seconds: ")))

# Initialize packet counters
normal_syn_packet_counts = []
malicious_syn_packet_counts = []
syn_timestamps = defaultdict(list)

# Thread-safe lock for data synchronization
data_lock = threading.Lock()

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

            # Categorize packets as normal or malicious
            if syn_count > SYN_THRESHOLD:
                print(f"Potential SYN flood attack detected from {source_ip}!")
                malicious_syn_packet_counts.append((current_time, len(malicious_syn_packet_counts) + 1))
            else:
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

# Start sniffing and plotting in parallel
sniff_thread = threading.Thread(target=start_sniffing)
plot_thread = threading.Thread(target=update_plot)

sniff_thread.start()
plot_thread.start()

sniff_thread.join()
plot_thread.join()
