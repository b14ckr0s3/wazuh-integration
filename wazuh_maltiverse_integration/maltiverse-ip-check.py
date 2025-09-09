#!/usr/bin/env python3

import json
import requests
import re
import ipaddress
import subprocess
from datetime import datetime, timedelta, timezone
from dateutil import parser as dtparser

# === CONFIGURATION ===
WAZUH_ALERTS_LOG = "/var/ossec/logs/alerts/alerts.json"
MALTIVERSE_ENDPOINT = "https://api.maltiverse.com/ip/"
MAX_MINUTES = 10

def extract_timestamp(alert_line):
    try:
        alert = json.loads(alert_line)
        timestamp = alert.get("@timestamp") or alert.get("timestamp")
        return dtparser.isoparse(timestamp) if timestamp else None
    except Exception:
        return None

def extract_ips(alert_line):
    try:
        alert = json.loads(alert_line)
        full_log = alert.get("full_log", "")
        return {ip for ip in re.findall(r'[0-9]+(?:\.[0-9]+){3}', full_log) if is_valid_ip(ip)}
    except Exception:
        return set()

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
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

def check_maltiverse(ip):
    try:
        response = requests.get(MALTIVERSE_ENDPOINT + ip, timeout=10)
        if response.status_code == 200:
            data = response.json()
            tags = data.get("blacklist", [])
            return "malicious" in tags
        elif response.status_code == 404:
            return False
        else:
            print(f"[ERROR] Maltiverse returned status {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Exception for IP {ip}: {e}")
    return False

def log_to_syslog(ip):
    message = f"[MALTIVERSE] IP={ip} Malicious=True"
    subprocess.run(["logger", "-t", "maltiverse", message])

def main():
    ips = get_recent_alert_ips()
    for ip in ips:
        if check_maltiverse(ip):
            log_to_syslog(ip)

if __name__ == "__main__":
    main()
