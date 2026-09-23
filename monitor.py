import os
import re
import subprocess
import time
from typing import Optional
from dotenv import load_dotenv
import requests

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

if not DISCORD_WEBHOOK_URL:
    raise ValueError("Missing DISCORD_WEBHOOK_URL! Please define it in your .env file.")

# Regex patterns
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?:invalid user )?(.*?) from (.*?) port")
SUCCESS_LOGIN_PATTERN = re.compile(r"Accepted (?:password|publickey) for (.*?) from (.*?) port")

# Rate Limiting Configuration
ALERT_COOLDOWN = 60  # Seconds to wait before alerting again for the SAME IP
last_alert_times = {}

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
    """Sends a formatted alert to a Discord webhook."""
    if alert_type == "failure":
        title = "🚨 **SSH Alert: Failed Login** 🚨"
        color_block = "```diff\n- Access Denied\n```"
    elif alert_type == "success":
        title = "⚠️ **CRITICAL: Root SSH Login** ⚠️" if user == "root" else "✅ **SSH Alert: Successful Login** ✅"
        color_block = "```yaml\nAccess Granted\n```"
        
    message = {
        "content": (
            f"{title}\n"
            f"**User:** `{user}`\n"
            f"**IP:** `{ip}`\n"
            f"**Location:** 🌍 `{location}`\n"
            f"{color_block}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to send alert: {e}")

def monitor_journal() -> None:
    """Continuously monitors the SSH systemd journal with Rate Limiting."""
    print("[*] Starting real-time monitor (Rate Limited)...")

    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )

    try:
        for line in iter(process.stdout.readline, ""):
            if not line:
                continue

            # 1. Check for failed logins (Rate Limited)
            fail_match: Optional[re.Match] = FAILED_LOGIN_PATTERN.search(line)
            if fail_match:
                target_user, attacker_ip = fail_match.groups()
                current_time = time.time()
                
                # Check cooldown dictionary
                last_time = last_alert_times.get(attacker_ip, 0)
                
                if (current_time - last_time) >= ALERT_COOLDOWN:
                    # Cooldown has passed; send alert
                    location = get_geolocation(attacker_ip)
                    print(f"[!] Failed Alert: {target_user} from {attacker_ip} ({location})")
                    send_discord_alert(target_user, attacker_ip, location, "failure")
                    
                    # Record the time we sent this alert
                    last_alert_times[attacker_ip] = current_time
                else:
                    # Alert is suppressed
                    print(f"[*] Suppressed alert for {attacker_ip} (Rate limited)")
                continue

            # 2. Check for successful logins (Never Rate Limited)
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
    monitor_journal()
