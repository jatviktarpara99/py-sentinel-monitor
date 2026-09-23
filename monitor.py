import os
import re
import subprocess
from typing import Optional
from dotenv import load_dotenv
import requests

# Load variables from .env file
load_dotenv()

# Fetch secret from environment; exit gracefully if not set
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

if not DISCORD_WEBHOOK_URL:
    raise ValueError("Missing DISCORD_WEBHOOK_URL! Please define it in your .env file.")

# Regex pattern
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(.*?) from (.*?) port"
)


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


def send_discord_alert(user: str, ip: str, location: str) -> None:
    """Sends a formatted alert to a Discord webhook, including location."""
    message = {
        "content": (
            f"🚨 **SSH Alert** 🚨\n"
            f"Failed login attempt!\n"
            f"**User:** `{user}`\n"
            f"**IP:** `{ip}`\n"
            f"**Location:** 🌍 `{location}`"
        )
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
        response.raise_for_status()
        print("[+] Discord alert sent successfully!")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to send alert: {e}")


def monitor_journal() -> None:
    """Continuously monitors the SSH systemd journal for new entries."""
    print("[*] Starting real-time monitor on SSH journal with Geo-Location...")

    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )

    try:
        for line in iter(process.stdout.readline, ""):
            if not line:
                continue

            match: Optional[re.Match] = FAILED_LOGIN_PATTERN.search(line)
            if match:
                target_user, attacker_ip = match.groups()
                location = get_geolocation(attacker_ip)
                print(f"[!] Alert: {target_user} from {attacker_ip} ({location})")
                send_discord_alert(target_user, attacker_ip, location)

    except KeyboardInterrupt:
        print("\n[*] Stopping monitor.")
    finally:
        process.terminate()


if __name__ == "__main__":
    monitor_journal()