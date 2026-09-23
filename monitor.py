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

# Regex patterns for SSH activity
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?:invalid user )?(.*?) from (.*?) port")
SUCCESS_LOGIN_PATTERN = re.compile(r"Accepted (?:password|publickey) for (.*?) from (.*?) port")

# SSH IPS & Rate Limiting Configuration
ALERT_COOLDOWN = 60  # Seconds to wait before alerting again for the same IP
MAX_FAILURES = 3     # Strikes before UFW auto-ban
last_alert_times = {}
failed_attempts = {}

# Resource Monitoring Configuration
CPU_THRESHOLD = 90.0
RAM_THRESHOLD = 90.0
RESOURCE_CHECK_INTERVAL = 60  # Seconds between hardware checks
resource_alert_state = {"cpu": False, "ram": False}

def get_geolocation(ip: str) -> str:
    """Queries a free API to get the geographical location of an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")
            return f"{city}, {country}"
    except requests.exceptions.RequestException:
        pass
    return "Local/Unknown Network"

def send_discord_alert(user: str, ip: str, location: str, alert_type: str) -> None:
    """Sends a formatted SSH alert to Discord."""
    if alert_type == "failure":
        title = "🚨 **SSH Alert: Failed Login** 🚨"
        color_block = "```diff\n- Access Denied\n```"
    elif alert_type == "success":
        title = "⚠️ **CRITICAL: Root SSH Login** ⚠️" if user == "root" else "✅ **SSH Alert: Successful Login** ✅"
        color_block = "```yaml\nAccess Granted\n```"
    elif alert_type == "banned":
        title = "🛑 **IPS ACTION: IP Banned** 🛑"
        color_block = f"```diff\n- UFW Block Applied: {ip}\n- Strike Limit Exceeded ({MAX_FAILURES})\n```"

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
        print(f"[-] Failed to send Discord alert: {e}")

def send_health_alert(metric: str, usage: float) -> None:
    """Sends a formatted hardware alert to Discord."""
    title = f"🔥 **SYSTEM HEALTH ALERT: {metric.upper()} SPIKE** 🔥"
    color_block = f"```fix\n- {metric.upper()} Usage Critical: {usage}%\n```"

    message = {
        "content": f"{title}\n**Server:** `Ubuntu-VM`\n{color_block}"
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to send health alert: {e}")

def ban_ip(ip: str) -> None:
    """Executes a system-level UFW command to block the attacker IP at priority 1."""
    try:
        subprocess.run(["ufw", "insert", "1", "deny", "from", ip], check=True, stdout=subprocess.DEVNULL)
        print(f"[!!!] Successfully banned {ip} via UFW.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to ban {ip}: {e}")

def monitor_resources() -> None:
    """Background worker monitoring CPU and RAM usage."""
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

def monitor_journal() -> None:
    """Monitors journalctl for SSH login attempts, rate limits, and triggers IPS bans."""
    print("[*] Starting real-time IPS monitor (Failures, Successes, Auto-Ban)...")

    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )

    try:
        for line in iter(process.stdout.readline, ""):
            if not line:
                continue

            # Check for failed logins
            fail_match: Optional[re.Match] = FAILED_LOGIN_PATTERN.search(line)
            if fail_match:
                target_user, attacker_ip = fail_match.groups()
                
                # Track strikes
                failed_attempts[attacker_ip] = failed_attempts.get(attacker_ip, 0) + 1
                strikes = failed_attempts[attacker_ip]
                location = get_geolocation(attacker_ip)

                # IPS Auto-Banning logic
                if strikes == MAX_FAILURES:
                    print(f"[!!!] Strike limit reached for {attacker_ip}. Executing ban...")
                    ban_ip(attacker_ip)
                    send_discord_alert(target_user, attacker_ip, location, "banned")
                    continue
                elif strikes > MAX_FAILURES:
                    continue  # Already blocked

                # Rate limiting for notifications
                current_time = time.time()
                last_time = last_alert_times.get(attacker_ip, 0)
                if (current_time - last_time) >= ALERT_COOLDOWN:
                    print(f"[!] Strike {strikes}/{MAX_FAILURES}: {target_user} from {attacker_ip}")
                    send_discord_alert(target_user, attacker_ip, location, "failure")
                    last_alert_times[attacker_ip] = current_time
                else:
                    print(f"[*] Suppressed alert for {attacker_ip} (Rate limited)")
                continue

            # Check for successful logins
            success_match: Optional[re.Match] = SUCCESS_LOGIN_PATTERN.search(line)
            if success_match:
                target_user, attacker_ip = success_match.groups()
                location = get_geolocation(attacker_ip)
                print(f"[+] Success Alert: {target_user} from {attacker_ip} ({location})")
                send_discord_alert(target_user, attacker_ip, location, "success")

    except KeyboardInterrupt:
        print("\n[*] Stopping monitor.")
    finally:
        process.terminate()

if __name__ == "__main__":
    # Launch system resource monitor in a background daemon thread
    resource_thread = threading.Thread(target=monitor_resources, daemon=True)
    resource_thread.start()

    # Run SSH journal monitor on main thread
    monitor_journal()
