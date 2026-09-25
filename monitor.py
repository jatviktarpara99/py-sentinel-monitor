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

# Regex patterns
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?:invalid user )?(.*?) from (.*?) port")
SUCCESS_LOGIN_PATTERN = re.compile(r"Accepted (?:password|publickey) for (.*?) from (.*?) port")

# Canary Trap List (Deception Accounts)
CANARY_ACCOUNTS = {"honeyadmin", "backup_service", "dbadmin"}

# Configuration
ALERT_COOLDOWN = 60
MAX_FAILURES = 3
last_alert_times = {}
failed_attempts = {}

CPU_THRESHOLD = 85.0
RAM_THRESHOLD = 85.0
RESOURCE_CHECK_INTERVAL = 10
resource_alert_state = {"cpu": False, "ram": False}


def get_geolocation(ip: str) -> str:
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
    except requests.exceptions.RequestException:
        pass
    return "Local/Unknown Network"


def send_discord_alert(user: str, ip: str, location: str, alert_type: str) -> None:
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


def ban_ip(ip: str) -> None:
    """Executes a system-level UFW command to block the attacker IP at priority 1."""
    try:
        subprocess.run(["ufw", "insert", "1", "deny", "from", ip], check=True, stdout=subprocess.DEVNULL)
        print(f"[!!!] Banned {ip} via UFW.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to execute UFW ban for {ip}: {e}")


def monitor_resources() -> None:
    while True:
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            if cpu_usage > CPU_THRESHOLD and not resource_alert_state["cpu"]:
                send_health_alert("CPU", cpu_usage)
                resource_alert_state["cpu"] = True
            elif cpu_usage < (CPU_THRESHOLD - 5):
                resource_alert_state["cpu"] = False

            ram_usage = psutil.virtual_memory().percent
            if ram_usage > RAM_THRESHOLD and not resource_alert_state["ram"]:
                send_health_alert("RAM", ram_usage)
                resource_alert_state["ram"] = True
            elif ram_usage < (RAM_THRESHOLD - 5):
                resource_alert_state["ram"] = False

            time.sleep(RESOURCE_CHECK_INTERVAL)
        except Exception as e:
            time.sleep(RESOURCE_CHECK_INTERVAL)


def send_health_alert(metric: str, usage: float) -> None:
    title = f"🔥 **SYSTEM HEALTH ALERT: {metric.upper()} SPIKE** 🔥"
    color_block = f"```fix\n- {metric.upper()} Usage Critical: {usage}%\n```"
    message = {"content": f"{title}\n**Server:** `Ubuntu-VM`\n{color_block}"}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.exceptions.RequestException:
        pass


def monitor_journal() -> None:
    print("[*] Starting Sentinel Daemon with Canary Deception active...")
    process = subprocess.Popen(["journalctl", "-u", "ssh", "-f", "-n", "0"], stdout=subprocess.PIPE, text=True)

    try:
        for line in iter(process.stdout.readline, ""):
            if not line:
                continue

            # 1. Parse failed attempts
            fail_match: Optional[re.Match] = FAILED_LOGIN_PATTERN.search(line)
            if fail_match:
                target_user, attacker_ip = fail_match.groups()
                location = get_geolocation(attacker_ip)

                # Check Deception Trap
                if target_user in CANARY_ACCOUNTS:
                    print(f"[🪤] CANARY TRIPPED: {attacker_ip} targeted honeypot user '{target_user}'")
                    ban_ip(attacker_ip)
                    send_discord_alert(target_user, attacker_ip, location, "canary")
                    continue

                # Standard Threshold Tracking
                failed_attempts[attacker_ip] = failed_attempts.get(attacker_ip, 0) + 1
                strikes = failed_attempts[attacker_ip]

                if strikes == MAX_FAILURES:
                    ban_ip(attacker_ip)
                    send_discord_alert(target_user, attacker_ip, location, "banned")
                    continue
                elif strikes > MAX_FAILURES:
                    continue

                # Rate Limiting for standard failures
                current_time = time.time()
                last_time = last_alert_times.get(attacker_ip, 0)
                if (current_time - last_time) >= ALERT_COOLDOWN:
                    send_discord_alert(target_user, attacker_ip, location, "failure")
                    last_alert_times[attacker_ip] = current_time
                continue

            # 2. Parse successful attempts
            success_match: Optional[re.Match] = SUCCESS_LOGIN_PATTERN.search(line)
            if success_match:
                target_user, attacker_ip = success_match.groups()
                location = get_geolocation(attacker_ip)

                # Canary compromised (even if password succeeded, trigger lockout)
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


if __name__ == "__main__":
    t = threading.Thread(target=monitor_resources, daemon=True)
    t.start()
    monitor_journal()
