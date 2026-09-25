import hashlib
import os
import re
import subprocess
import threading
import time
from typing import Optional
from dotenv import load_dotenv
import psutil
import requests

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

if not DISCORD_WEBHOOK_URL:
    raise ValueError("Missing DISCORD_WEBHOOK_URL! Please define it in your .env file.")

# ==========================================
# 1. SSH MONITOR & IPS CONFIGURATION
# ==========================================
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?:invalid user )?(.*?) from (.*?) port")
SUCCESS_LOGIN_PATTERN = re.compile(r"Accepted (?:password|publickey) for (.*?) from (.*?) port")

CANARY_ACCOUNTS = {"honeyadmin", "backup_service", "dbadmin"}
ALERT_COOLDOWN = 60  # Rate limit cooldown in seconds
MAX_FAILURES = 3     # Maximum failed attempts before UFW ban

last_alert_times = {}
failed_attempts = {}

# ==========================================
# 2. SYSTEM HEALTH CONFIGURATION
# ==========================================
CPU_THRESHOLD = 85.0
RAM_THRESHOLD = 85.0
RESOURCE_CHECK_INTERVAL = 10
resource_alert_state = {"cpu": False, "ram": False}

# ==========================================
# 3. FILE INTEGRITY MONITORING (FIM) CONFIG
# ==========================================
MONITORED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
]
FIM_CHECK_INTERVAL = 15  # Seconds between file integrity audits
file_baselines = {}


# ==========================================
# ALERTING UTILITIES
# ==========================================
def get_geolocation(ip: str) -> str:
    """Queries a free API to get the geographical location of an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
    except requests.exceptions.RequestException:
        pass
    return "Local/Unknown Network"


def send_discord_alert(user: str, ip: str, location: str, alert_type: str) -> None:
    """Dispatches formatted security and access alerts to Discord."""
    if alert_type == "failure":
        title = "🚨 **SSH Alert: Failed Login** 🚨"
        color_block = "```diff\n- Access Denied\n```"
    elif alert_type == "success":
        title = "⚠️ **CRITICAL: Root SSH Login** ⚠️" if user == "root" else "✅ **SSH Alert: Successful Login** ✅"
        color_block = "```yaml\nAccess Granted\n```"
    elif alert_type == "banned":
        title = "🛑 **IPS ACTION: IP Banned** 🛑"
        color_block = f"```diff\n- UFW Block Applied: {ip}\n- Strike Limit Exceeded ({MAX_FAILURES})\n```"
    elif alert_type == "canary":
        title = "🪤 **DECEPTION ALERT: Canary Trap Tripped** 🪤"
        color_block = (
            f"```diff\n"
            f"- ZERO-TOLERANCE INSTANT BAN\n"
            f"- Honeypot Account Targeted: {user}\n"
            f"- Immediate UFW Perimeter Lockout\n"
            f"```"
        )
    else:
        title = "ℹ️ **Security Notification**"
        color_block = ""

    message = {
        "content": (
            f"{title}\n"
            f"**Target:** `{user}`\n"
            f"**IP:** `{ip}`\n"
            f"**Location:** 🌍 `{location}`\n"
            f"{color_block}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to dispatch Discord alert: {e}")


def send_health_alert(metric: str, usage: float) -> None:
    """Dispatches formatted hardware metrics to Discord."""
    title = f"🔥 **SYSTEM HEALTH ALERT: {metric.upper()} SPIKE** 🔥"
    color_block = f"```fix\n- {metric.upper()} Usage Critical: {usage}%\n```"
    message = {"content": f"{title}\n**Server:** `Ubuntu-VM`\n{color_block}"}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to dispatch health alert: {e}")


def send_fim_alert(filepath: str, old_hash: str, new_hash: str) -> None:
    """Dispatches file tampering notifications to Discord."""
    title = "🚨 **CRITICAL: File Integrity Violation (FIM)** 🚨"
    diff_block = (
        f"```diff\n"
        f"- Target File: {filepath}\n"
        f"- Baseline Hash: {old_hash[:16]}...\n"
        f"+ Detected Hash: {new_hash[:16]}...\n"
        f"- Action: Unauthorized Modification Detected\n"
        f"```"
    )
    message = {"content": f"{title}\n**Host:** `Ubuntu-VM`\n{diff_block}"}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to dispatch FIM alert: {e}")


def ban_ip(ip: str) -> None:
    """Executes a system-level UFW command to block the attacker IP at priority 1."""
    try:
        subprocess.run(["ufw", "insert", "1", "deny", "from", ip], check=True, stdout=subprocess.DEVNULL)
        print(f"[!!!] Banned {ip} via UFW.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to execute UFW ban for {ip}: {e}")


# ==========================================
# MODULE 1: SYSTEM RESOURCE MONITOR (THREAD)
# ==========================================
def monitor_resources() -> None:
    """Continuously evaluates system CPU and RAM usage."""
    print(f"[*] Resource monitor running (CPU > {CPU_THRESHOLD}%, RAM > {RAM_THRESHOLD}%)...")
    while True:
        try:
            # Check CPU
            cpu_usage = psutil.cpu_percent(interval=1)
            if cpu_usage > CPU_THRESHOLD and not resource_alert_state["cpu"]:
                print(f"[!] CPU Spike Detected: {cpu_usage}%")
                send_health_alert("CPU", cpu_usage)
                resource_alert_state["cpu"] = True
            elif cpu_usage < (CPU_THRESHOLD - 5):
                resource_alert_state["cpu"] = False

            # Check RAM
            ram_usage = psutil.virtual_memory().percent
            if ram_usage > RAM_THRESHOLD and not resource_alert_state["ram"]:
                print(f"[!] RAM Spike Detected: {ram_usage}%")
                send_health_alert("RAM", ram_usage)
                resource_alert_state["ram"] = True
            elif ram_usage < (RAM_THRESHOLD - 5):
                resource_alert_state["ram"] = False

            time.sleep(RESOURCE_CHECK_INTERVAL)
        except Exception as e:
            print(f"[-] Error in resource monitor thread: {e}")
            time.sleep(RESOURCE_CHECK_INTERVAL)


# ==========================================
# MODULE 2: FILE INTEGRITY MONITOR (THREAD)
# ==========================================
def calculate_sha256(filepath: str) -> Optional[str]:
    """Calculates SHA-256 hash of a file."""
    if not os.path.exists(filepath):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except PermissionError:
        return "PERMISSION_DENIED"
    except Exception as e:
        print(f"[-] Error hashing {filepath}: {e}")
        return None


def initialize_fim_baselines() -> None:
    """Takes initial cryptographic snapshots of monitored files."""
    for filepath in MONITORED_FILES:
        current_hash = calculate_sha256(filepath)
        if current_hash:
            file_baselines[filepath] = current_hash
    print(f"[*] FIM: Established baselines for {len(file_baselines)} critical files.")


def monitor_file_integrity() -> None:
    """Audits monitored system files for integrity drift."""
    initialize_fim_baselines()
    while True:
        try:
            for filepath in MONITORED_FILES:
                current_hash = calculate_sha256(filepath)
                previous_hash = file_baselines.get(filepath)

                if current_hash is None or current_hash == "PERMISSION_DENIED":
                    continue

                if previous_hash and current_hash != previous_hash:
                    print(f"[!] FIM ALERT: Tampering detected on {filepath}!")
                    send_fim_alert(filepath, previous_hash, current_hash)
                    file_baselines[filepath] = current_hash

            time.sleep(FIM_CHECK_INTERVAL)
        except Exception as e:
            print(f"[-] Error in FIM monitor thread: {e}")
            time.sleep(FIM_CHECK_INTERVAL)


# ==========================================
# MODULE 3: SSH LOG MONITOR & IPS ENGINE
# ==========================================
def monitor_journal() -> None:
    """Ingests systemd journal logs to detect brute-force attempts and canary triggers."""
    print("[*] Starting Sentinel Daemon with Canary Deception active...")
    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )

    try:
        for line in iter(process.stdout.readline, ""):
            if not line:
                continue

            # 1. Parse failed authentication attempts
            fail_match: Optional[re.Match] = FAILED_LOGIN_PATTERN.search(line)
            if fail_match:
                target_user, attacker_ip = fail_match.groups()
                location = get_geolocation(attacker_ip)

                # Canary tripwire check
                if target_user in CANARY_ACCOUNTS:
                    print(f"[🪤] CANARY TRIPPED: {attacker_ip} targeted honeypot user '{target_user}'")
                    ban_ip(attacker_ip)
                    send_discord_alert(target_user, attacker_ip, location, "canary")
                    continue

                # Threshold tracking
                failed_attempts[attacker_ip] = failed_attempts.get(attacker_ip, 0) + 1
                strikes = failed_attempts[attacker_ip]

                if strikes == MAX_FAILURES:
                    ban_ip(attacker_ip)
                    send_discord_alert(target_user, attacker_ip, location, "banned")
                    continue
                elif strikes > MAX_FAILURES:
                    continue

                # Rate limiting for alerts
                current_time = time.time()
                last_time = last_alert_times.get(attacker_ip, 0)
                if (current_time - last_time) >= ALERT_COOLDOWN:
                    send_discord_alert(target_user, attacker_ip, location, "failure")
                    last_alert_times[attacker_ip] = current_time
                continue

            # 2. Parse successful authentications
            success_match: Optional[re.Match] = SUCCESS_LOGIN_PATTERN.search(line)
            if success_match:
                target_user, attacker_ip = success_match.groups()
                location = get_geolocation(attacker_ip)

                if target_user in CANARY_ACCOUNTS:
                    print(f"[🪤] CANARY COMPROMISED: {attacker_ip} logged into '{target_user}'")
                    ban_ip(attacker_ip)
                    send_discord_alert(target_user, attacker_ip, location, "canary")
                    continue

                send_discord_alert(target_user, attacker_ip, location, "success")

    except KeyboardInterrupt:
        print("\n[*] Stopping monitor.")
    finally:
        process.terminate()


# ==========================================
# MAIN EXECUTION ENTRY POINT
# ==========================================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Py-Sentinel requires administrative privileges to manipulate UFW and read /etc/shadow.")
        print("[!] Please run with: sudo python3 monitor.py")
        exit(1)

    # Thread 1: Hardware resource monitoring
    resource_thread = threading.Thread(target=monitor_resources, daemon=True)
    resource_thread.start()

    # Thread 2: File integrity monitoring
    fim_thread = threading.Thread(target=monitor_file_integrity, daemon=True)
    fim_thread.start()

    # Main Thread: Ingest SSH journal events
    monitor_journal()
