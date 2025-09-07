#!/usr/bin/env python3
import subprocess
import time
from collections import defaultdict
import re

# ---------------- Configuration ----------------
THRESHOLD = 5       # Number of failed attempts to trigger alert
WINDOW = 60         # Time window in seconds
AUTO_BLOCK = False  # Set True to block IPs via iptables
# ------------------------------------------------

attempts = defaultdict(list)  # Track failed attempts per IP
blocked_ips = set()

# Regex to detect failed SSH logins
FAILED_PATTERN = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")

def block_ip(ip):
    """Block IP using iptables (optional)."""
    if AUTO_BLOCK and ip not in blocked_ips:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            blocked_ips.add(ip)
            print(f"[BLOCKED] IP {ip} has been blocked via iptables")
        except Exception as e:
            print(f"[ERROR] Could not block IP {ip}: {e}")

def check_attempt(ip):
    """Check if an IP exceeds threshold in the time window."""
    now = time.time()
    # Remove old timestamps outside the time window
    attempts[ip] = [t for t in attempts[ip] if now - t <= WINDOW]
    
    if len(attempts[ip]) >= THRESHOLD:
        print(f"[ALERT] Possible brute-force attack from {ip}")
        block_ip(ip)
        # Clear attempts after alert
        attempts[ip] = []

def monitor_ssh_logs():
    """Monitor SSH logs in real-time using journalctl."""
    print("Monitoring SSH logs in real-time for brute-force attacks...")
    proc = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-o", "cat"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )

    for line in proc.stdout:
        line = line.decode()
        match = FAILED_PATTERN.search(line)
        if match:
            ip = match.group(1)
            attempts[ip].append(time.time())
            check_attempt(ip)


def banner():
    print("""
   __________ __  ___      __    __
  / ___/ ___// / / (_)__  / /___/ /
   \__ \\__ \/ /_/ / / _ \/ / __  / 
 ___/ /__/ / __  / /  __/ / /_/ /  
/____/____/_/ /_/_/\___/_/\__,_/  

        SSH Brute-force Detection Tool
        by Aliakbar 
 """)



if __name__ == "__main__":
    banner()
    monitor_ssh_logs()
