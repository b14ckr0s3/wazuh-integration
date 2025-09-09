#!/usr/bin/env python3
import json
import requests
import ipaddress
from datetime import datetime, timedelta, timezone
from dateutil import parser as dtparser
import subprocess

# === CONFIGURATION ===
WAZUH_ALERTS_LOG = "/var/ossec/logs/alerts/alerts.json"
VT_API_KEY = "<YOUR_VIRUSTOTAL_API_KEY>"
VT_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/"
MAX_MINUTES = 10
VT_THRESHOLD = 3  # số lượng engines báo là malicious

def extract_timestamp(alert_line):
    try:
        alert = json.loads(alert_line)
        timestamp = alert.get("@timestamp") or alert.get("timestamp")
        if timestamp:
            return dtparser.isoparse(timestamp)
    except:
        return None
    return None

def extract_ips(alert_line):
    try:
        alert = json.loads(alert_line)
        full_log = alert.get("full_log", "")
        return {ip for ip in re.findall(r'[0-9]+(?:\.[0-9]+){3}', full_log) if is_valid_ip(ip)}
    except:
        return set()

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def get_recent_alert_ips():
    now = datetime.now(timezone.utc)
    ips = set()
    with open(WAZUH_ALERTS_LOG, "r") as f:
        for line in f:
            ts = extract_timestamp(line)
            if ts and now - ts <= timedelta(minutes=MAX_MINUTES):
                ips.update(extract_ips(line))
    return ips

def check_virustotal(ip):
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(VT_ENDPOINT + ip, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            return malicious
        else:
            print(f"[ERROR] VT request failed: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Exception: {e}")
    return 0

def log_to_syslog(ip, score):
    message = f"[VIRUSTOTAL] IP={ip} Malicious={score}"
    subprocess.run(["logger", "-t", "virustotal", message])

def main():
    ips = get_recent_alert_ips()
    for ip in ips:
        malicious = check_virustotal(ip)
        if malicious >= VT_THRESHOLD:
            log_to_syslog(ip, malicious)

if __name__ == "__main__":
    main()
