import os
import re
import subprocess
from typing import Optional
from dotenv import load_dotenv
import requests

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

if not DISCORD_WEBHOOK_URL:
    raise ValueError("Missing DISCORD_WEBHOOK_URL! Please define it in your .env file.")

# Regex patterns for both Failure and Success
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?:invalid user )?(.*?) from (.*?) port")
SUCCESS_LOGIN_PATTERN = re.compile(r"Accepted (?:password|publickey) for (.*?) from (.*?) port")

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
    """Sends a formatted alert to a Discord webhook based on event type."""
    if alert_type == "failure":
        title = "🚨 **SSH Alert: Failed Login** 🚨"
        color_block = "```diff\n- Access Denied\n```"
    elif alert_type == "success":
        # Highlight root logins as critical
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
    """Continuously monitors the SSH systemd journal for new entries."""
    print("[*] Starting real-time monitor (Tracking Failures & Successes)...")

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
                location = get_geolocation(attacker_ip)
                print(f"[!] Failed Alert: {target_user} from {attacker_ip} ({location})")
                send_discord_alert(target_user, attacker_ip, location, "failure")
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
    monitor_journal()
