import os

if os.path.exists("blocked_ips_log.txt"):
    print("[INFO] blocked_ips_log.txt exists in the current directory.")
else:
    print("[ERROR] blocked_ips_log.txt does NOT exist in the current directory.")
