### 🛡️ Linux Security Monitor (SIEM-Lite)

  A lightweight, real-time security monitoring tool written in Python. This project hooks directly into Linux system logs to detect malicious activity and immediately alerts administrators via Discord, complete with IP geolocation tracking.
  
  Currently, the primary module focuses on SSH brute-force detection, with more security modules planned for future development.

### ✨ Features

  Real-Time Monitoring: Streams systemd logs (journalctl) for zero-delay threat detection, rather than relying on delayed file reading.
  
  Geo-Location Enrichment: Automatically traces attacker IP addresses to their registered city and country using the ip-api.com API.
  
  Discord Integration: Sends instant, beautifully formatted alert payloads to a private Discord channel via Webhooks.
  
  Secure Configuration: Uses .env files to keep sensitive Webhook URLs completely safe and out of source control.
  
  Modular Design: Built to be easily expanded with future alerts (e.g., Nginx/Apache log monitoring, failed sudo attempts, or system resource spikes).
  
  Automatically executes system-level UFW commands to block attacker IP addresses after 3 failed authentication attempts.

### 🏗️ How It Works

  Ingest: The Python script uses the subprocess module to continuously tail the live SSH journal.
  
  Detect: Regular expressions (Regex) scan incoming log lines for specific authentication failure patterns.
  
  Enrich: When an attack is detected, the script extracts the IP and queries a public geolocation API to find the physical origin.
  
  Alert: A JSON payload containing the targeted username, attacker IP, and geographical location is instantly pushed to Discord.

### 🛠️ Prerequisites

  A Linux environment utilizing systemd (Ubuntu, Debian, etc.)
  
  Python 3.x installed
  
  A Discord Server with Webhook generation permissions

### 🚀 Installation & Setup

  1. Clone the repository:
  
  git clone https://github.com/jatviktarpara99/py-sentinel-monitor.git
  
  
  2. Install dependencies:
  It is recommended to use a Python virtual environment or install the requirements globally depending on your system setup.
  
  pip install -r requirements.txt
  
  
  3. Configure your environment variables:
  Create a .env file in the root directory based on the provided example.
  
  cp .env.example .env
  
  
  Open the .env file and paste your actual Discord Webhook URL:
  
  DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR_URL_HERE"
  

### 💻 Usage

  Run the script with administrative privileges (so it can read the system journal logs):
  
  sudo python3 monitor.py
  
  
  To test the alert system locally without exposing your machine to the internet, open a second terminal and intentionally fail an SSH login:
  
  ssh username@localhost
  
  You should instantly receive a Discord notification flagging the local network attempt!

### 🧪 Testing & Validation 
  To test this tool in a real-world scenario, I simulated a brute-force attack:
  1. Used `nmap` to identify the open SSH port.
  2. Launched an automated dictionary attack using the Metasploit Framework (`auxiliary/scanner/ssh/ssh_login`).
  3. The Python daemon successfully detected the attack, sent a detailed Discord alert, and dynamically rate-limited the hundreds of subsequent attempts to prevent webhook spam.

### ⚙️ Deployment (Background Service)
  This project includes configurations to run as a persistent, headless background daemon. A sample `systemd` configuration file is provided in the `deployment/` directory so the script automatically starts on VM boot and runs invisibly.

### 🔮 Future Roadmap
  - [x] Add rate-limiting to prevent alert fatigue.
  - [x] Implement auto-banning using `ufw` or `iptables` for repeat offenders (IPS functionality).
  - [ ] Monitor web server access logs (Nginx/Apache) for SQLi and XSS payloads.
  - [x] Add system health alerts (CPU/RAM spikes).
  
  ---
*Developed as a portfolio project demonstrating foundational SIEM engineering, log parsing, and API integrations.*

### Live Alert Example
<img width="477" height="463" alt="image" src="https://github.com/user-attachments/assets/2d3cf216-1c26-4ed1-923d-00990cbf89ac" />

[ ] Implement auto-banning using ufw or iptables for repeat offenders.

Developed as a portfolio project demonstrating foundational SIEM engineering, log parsing, and API integrations.
