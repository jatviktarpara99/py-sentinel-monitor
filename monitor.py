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

FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?:invalid user )?(.*?) from (.*?) port")
SUCCESS_LOGIN_PATTERN = re.compile(r"Accepted (?:password|publickey) for (.*?) from (.*?) port")

# Rate Limiting & Auto-Ban Configuration
ALERT_COOLDOWN = 60  
MAX_FAILURES = 3
last_alert_times = {}
failed_attempts = {}

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
        
    message = {
        "content": (f"{title}\n**Target:** `{user}`\n**IP:** `{ip}`\n**Location:** 🌍 `{location}`\n{color_block}")
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to send alert: {e}")

def ban_ip(ip: str) -> None:
    """Executes UFW command to block the attacker IP at priority 1."""
    try:
        subprocess.run(["ufw", "insert", "1", "deny", "from", ip], check=True, stdout=subprocess.DEVNULL)
        print(f"[!!!] Successfully banned {ip} via UFW.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to ban {ip}: {e}")

def monitor_journal() -> None:
    print("[*] Starting real-time IPS monitor (Auto-Banning Enabled)...")
    process = subprocess.Popen(["journalctl", "-u", "ssh", "-f", "-n", "0"], stdout=subprocess.PIPE, text=True)

    try:
        for line in iter(process.stdout.readline, ""):
            if not line:
                continue

            fail_match: Optional[re.Match] = FAILED_LOGIN_PATTERN.search(line)
            if fail_match:
                target_user, attacker_ip = fail_match.groups()
                
                # Track strikes
                failed_attempts[attacker_ip] = failed_attempts.get(attacker_ip, 0) + 1
                strikes = failed_attempts[attacker_ip]
                location = get_geolocation(attacker_ip)

                if strikes == MAX_FAILURES:
                    print(f"[!!!] Threshold reached for {attacker_ip}. Executing ban...")
                    ban_ip(attacker_ip)
                    send_discord_alert(target_user, attacker_ip, location, "banned")
                    continue
                elif strikes > MAX_FAILURES:
                    continue # IP is already blocked, ignore subsequent trailing logs

                # Rate limiting for standard alerts
                current_time = time.time()
                last_time = last_alert_times.get(attacker_ip, 0)
                if (current_time - last_time) >= ALERT_COOLDOWN:
                    print(f"[!] Strike {strikes}/{MAX_FAILURES}: {target_user} from {attacker_ip}")
                    send_discord_alert(target_user, attacker_ip, location, "failure")
                    last_alert_times[attacker_ip] = current_time
                continue

            success_match: Optional[re.Match] = SUCCESS_LOGIN_PATTERN.search(line)
            if success_match:
                target_user, attacker_ip = success_match.groups()
                location = get_geolocation(attacker_ip)
                print(f"[+] Success Alert: {target_user} from {attacker_ip}")
                send_discord_alert(target_user, attacker_ip, location, "success")

    except KeyboardInterrupt:
        print("\n[*] Stopping monitor.")
    finally:
        process.terminate()

if __name__ == "__main__":
    monitor_journal()
