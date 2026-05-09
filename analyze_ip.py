import time

import requests


def analyze_ip_list(ips: list[str]) -> dict:
    results = {}

    for ip in ips:
        results[ip] = analyze_ip(ip)
        time.sleep(0.5)
    return results

def analyze_ip(ip):

    url = f"https://ipinfo.io/{ip}/json"

    r = requests.get(url)
    data = r.json()

    return data
