import subprocess
from datetime import datetime

# Initialize a set to track blocked IPs
blocked_ips = set()

def block_ip(ip):
    """
    Blocks the given IP using Windows firewall after detecting multiple attacks.
    Ensures that the rules are only added if they don't already exist.
    Requires administrative privileges to run the `netsh` command.
    """
    try:
        # Check if the inbound block rule exists for the IP
        inbound_rule_name = f"Block_In_{ip}"
        inbound_result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=" + inbound_rule_name],
            capture_output=True,
            text=True
        )
        if "No rules match" in inbound_result.stdout or not inbound_result.stdout:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + inbound_rule_name,
                 "dir=in", "action=block", "remoteip=" + ip],
                check=True
            )
            print(f"Inbound traffic from IP {ip} is now blocked.")
        else:
            print(f"Inbound block rule for IP {ip} already exists.")

        # Check if the outbound block rule exists for the IP
        outbound_rule_name = f"Block_Out_{ip}"
        outbound_result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=" + outbound_rule_name],
            capture_output=True,
            text=True
        )
        if "No rules match" in outbound_result.stdout or not outbound_result.stdout:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + outbound_rule_name,
                 "dir=out", "action=block", "remoteip=" + ip],
                check=True
            )
            print(f"Outbound traffic to IP {ip} is now blocked.")
        else:
            print(f"Outbound block rule for IP {ip} already exists.")

        # Log the IP block to a file
        blocked_ips.add(ip)
        with open("blocked_ips_log.txt", "a") as log_file:
            log_file.write(f"{datetime.now()}: IP {ip} blocked (both inbound and outbound).\n")

    except subprocess.CalledProcessError as e:
        print(f"Error occurred while blocking IP {ip}: {e}")

# Example usage
block_ip("192.168.43.117")
