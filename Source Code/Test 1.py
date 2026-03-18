from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

# Sniff 10 packets on interface 'eth0'
sniff(count=10, prn=process_packet)

from scapy.all import sniff, TCP

def detect_syn(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        print(f"SYN packet detected: {packet.summary()}") # packet.summary() is a method in Scapy that returns a brief summary of the packet's details.

# Use the specified interface
sniff(iface="\\Device\\NPF_{48FF4755-81B3-46DE-A13F-BCE7FFF0177D}", prn=detect_syn)
