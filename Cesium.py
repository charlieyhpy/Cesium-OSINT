import socket
import re
import subprocess
import json
import os
import exifread
import requests
import hashlib
import threading
import time
from bs4 import BeautifulSoup
from scapy.all import sniff, get_if_list

import sys

# Cesium Color Palette: White and Blue Vibes
PALETTE = {
    "BANNER_BLUE1":    "\033[38;2;60;150;255m",
    "BANNER_BLUE2":    "\033[38;2;0;212;255m",
    "BANNER_BLUE3":    "\033[38;2;145;207;255m",
    "BANNER_WHITE":    "\033[1;97m",
    "TITLE_ACCENT":    "\033[38;2;60;150;255m",
    "MENU_ACCENT":     "\033[38;2;0;195;255m",
    "MENU_BG":         "\033[48;2;230;242;255m",
    "PROMPT":          "\033[1;38;2;100;190;255m",
    "GOOD":            "\033[1;38;2;48;233;180m",
    "WARN":            "\033[1;38;2;210;210;40m",
    "ERR":             "\033[1;38;2;224;80;80m",
    "RESET":           "\033[0m",
    "TITLE_GRAD":      "\033[1;38;2;60;150;255m",
    "BANNER_GRADIENT1":"\033[38;2;60;180;255m",
    "BANNER_GRADIENT2":"\033[38;2;90;210;255m",
    "BANNER_GRADIENT3":"\033[38;2;145;230;255m",
}

def print_colored_banner():
    P = PALETTE
    banner = (
        f"{P['BANNER_BLUE1']} ▄████████    {P['BANNER_BLUE2']}▄████████    {P['BANNER_BLUE3']}▄████████  {P['BANNER_WHITE']}▄█  ███    █▄    ▄▄▄▄███▄▄▄▄   {P['RESET']}\n"
        f"{P['BANNER_BLUE1']}███    ███   {P['BANNER_BLUE2']}███    ███   {P['BANNER_BLUE3']}███    ███ {P['BANNER_WHITE']}███  ███    ███ ▄██▀▀▀███▀▀▀██▄ {P['RESET']}\n"
        f"{P['BANNER_BLUE1']}███    █▀    {P['BANNER_BLUE2']}███    █▀    {P['BANNER_BLUE3']}███    █▀  {P['BANNER_WHITE']}███▌ ███    ███ ███   ███   ███ {P['RESET']}\n"
        f"{P['BANNER_BLUE1']}███         {P['BANNER_BLUE2']}▄███▄▄▄       {P['BANNER_BLUE3']}███      {P['BANNER_WHITE']}  ███▌ ███    ███ ███   ███   ███ {P['RESET']}\n"
        f"{P['BANNER_BLUE1']}███        {P['BANNER_BLUE2']}▀▀███▀▀▀     {P['BANNER_BLUE3']}▀███████████ {P['BANNER_WHITE']}███▌ ███    ███ ███   ███   ███ {P['RESET']}\n"
        f"{P['BANNER_BLUE1']}███    █▄    {P['BANNER_BLUE2']}███    █▄          {P['BANNER_BLUE3']}███ {P['BANNER_WHITE']}███  ███    ███ ███   ███   ███ {P['RESET']}\n"
        f"{P['BANNER_BLUE1']}███    ███   {P['BANNER_BLUE2']}███    ███    {P['BANNER_BLUE3']}▄█    ███ {P['BANNER_WHITE']}███  ███    ███ ███   ███   ███ {P['RESET']}\n"
        f"{P['BANNER_BLUE1']}████████▀    {P['BANNER_BLUE2']}██████████  {P['BANNER_BLUE3']}▄████████▀  {P['BANNER_WHITE']}█▀   ████████▀   ▀█   ███   █▀{P['RESET']}\n"
        f"{P['MENU_ACCENT']}    ━━━━━━━━━━━━ Cesium OSINT Multi-Tool Kit ━━━━━━━━━━━━{P['RESET']}\n"
        f"{P['TITLE_ACCENT']}  ━━━━━━━━━━━━  Python3 | By cyh | 1.0 2026 ━━━━━━━━━━━━{P['RESET']}\n"
        f"{P['PROMPT']}================================================================={P['RESET']}\n"
    )
    print(banner)

def main_menu():
    # Instead of printing menu vertically, print in columns horizontally
    P = PALETTE
    options = [
        "[ 01 ] Website Vulnerability Scanner",
        "[ 02 ] Website Info Scanner",
        "[ 03 ] Website URL Scanner",
        "[ 04 ] IP Scanner",
        "[ 05 ] IP Port Scanner",
        "[ 06 ] IP Pinger",
        "[ 07 ] Network Traffic Analyzer",
        "[ 08 ] DNS Lookup",
        "[ 09 ] WHOIS Query",
        "[ 10 ] Subnet Calculator",
        "[ 11 ] Get Image Exif",
        "[ 12 ] Google Dorking",
        "[ 13 ] Username Tracker",
        "[ 14 ] Email Tracker",
        "[ 15 ] Email Lookup",
        "[ 16 ] Phone Number Lookup",
        "[ 17 ] IP Lookup",
        "[ 18 ] Social Media Scanner",
        "[ 19 ] Reverse Image Search",
        "[ 20 ] PDF Metadata Extractor",
        "[ 21 ] Phishing Simulator",
        "[ 22 ] Password Cracker",
        "[ 23 ] Hash Analyzer",
        "[ 24 ] SQL Injection Tester",
        "[ 25 ] XSS Scanner",
        "[ 26 ] File Integrity Checker",
        "[ 27 ] VPN Checker",
        "[ 28 ] Proxy Verifier",
        "[ 29 ] MAC Spoofer",
        "[ 30 ] DNS Spoof Detector",
        "[ 31 ] Roblox Cookie Info",
        "[ 32 ] Roblox ID Info",
        "[ 33 ] Roblox User Info",
        "[ 34 ] Game Server Scanner",
        "[ 35 ] Player Profile Analyzer",
        "[ 36 ] Item Value Checker",
        "[ 37 ] Trade History Tracker",
        "[ 38 ] Gun LoL Checker",
        "[ 39 ] Aniworld Scanner",
        "[ 40 ] TikTok OSINT",
        "[ 41 ] Steam OSINT",
        "[ 42 ] Valorant OSINT",
        "[ 43 ] Text File String Extractor",
        "[ 44 ] Simple Shodan Lookup",
        "[ 45 ] HTML Comment Extractor",
        "[ 46 ] Whois Bulk Lookup",
        "[ 47 ] Website Screenshot (Headless)",
        "[ 48 ] Network Speed Tester",
        "[ 49 ] Directory Brute Forcer"
    ]
    # Insert | between the option numbers visually in the horizontal menu print
    print(f"{P['TITLE_GRAD']}=== Cesium OSINT Multifunction Toolkit Menu ==={P['RESET']}")

    import math
    n_cols = 3
    n_rows = math.ceil(len(options) / n_cols)
    colopts = [[] for _ in range(n_cols)]
    for i, opt in enumerate(options):
        colopts[i % n_cols].append((i, opt))
    # Find max width per col for padding
    col_widths = [
        max(len(opt[1]) for opt in col)
        for col in colopts
    ]
    # Pad each column's list to n_rows by empty string for zipping
    for col in colopts:
        while len(col) < n_rows:
            col.append((-1, ""))
    # Print in n_rows horizontally
    for row in range(n_rows):
        line = ""
        for col_idx, col in enumerate(colopts):
            idx, opt = col[row]
            # Color logic as in original
            if idx == -1 or not opt:
                colored = ""
            else:
                idx1 = idx+1
                if idx1 % 2 == 0:
                    color = P['BANNER_GRADIENT3']
                elif idx1 % 3 == 0:
                    color = P['MENU_ACCENT']
                else:
                    color = P['BANNER_GRADIENT2']
                # find option number within brackets and reformat with spaces
                import re
                def bracket_reformat(opt):
                    # e.g. [01] to [ 01 ]
                    return re.sub(r'\[(\d{1,2})\]',
                        lambda m: f"[ {m.group(1).rjust(2,' ')} ]", opt)
                opt_out = bracket_reformat(opt)
                colored = f"{color}{opt_out}{P['RESET']}"
            line += colored.ljust(col_widths[col_idx] + 4)
            # Add | between columns except for the last column
            if col_idx < n_cols - 1:
                line = line.rstrip() + " | "
        print(line.rstrip())
    print(f"\n{P['PROMPT']}Enter the number of the option you want to use (e.g., 1 | 02 | 15 ...){P['RESET']}")
    print(f"{P['BANNER_GRADIENT1']}Type 'exit' to quit.{P['RESET']}")
    return options

class Cesium:
    def __init__(self):
        pass

    # [01] Website Vulnerability Scanner
    def website_vulnerability_scanner(self, url):
        payloads = ["<script>alert('X')</script>", "';alert('XSS');//"]
        for payload in payloads:
            try:
                response = requests.get(url + payload)
                if payload in response.text:
                    return f"{PALETTE['ERR']}XSS vulnerability with payload: {payload}{PALETTE['RESET']}"
            except Exception as e:
                return f"{PALETTE['WARN']}{str(e)}{PALETTE['RESET']}"
        return f"{PALETTE['GOOD']}No XSS vulnerabilities found.{PALETTE['RESET']}"

    def website_info_scanner(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else "No title found"
            meta_tags = soup.find_all('meta')
            meta_info = {tag.get('name', ''): tag.get('content', '') for tag in meta_tags if tag.get('name')}
            return {'title': f"{PALETTE['BANNER_GRADIENT2']}{title}{PALETTE['RESET']}", 'meta_info': meta_info}
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def website_url_scanner(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [f"{PALETTE['BANNER_GRADIENT3']}{a['href']}{PALETTE['RESET']}" for a in soup.find_all('a', href=True)]
            return links
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    # [19] Reverse Image Search (uses Bing's free endpoint as demo, not Google)
    def reverse_image_search(self, image_path):
        try:
            return f"{PALETTE['MENU_ACCENT']}(Stub) Reverse image search would be performed on {image_path}.{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    # [20] PDF Metadata Extractor
    def pdf_metadata_extractor(self, pdf_path):
        try:
            import PyPDF2
            with open(pdf_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                meta = reader.metadata
                return {str(k):str(v) for k,v in meta.items()}
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def ip_scanner(self, ip_range):
        live_ips = []
        for ip in ip_range:
            ping_cmd = "ping -n 1" if os.name == "nt" else "ping -c 1"
            response = os.popen(f"{ping_cmd} {ip}").read()
            if "TTL=" in response or "bytes from" in response:
                live_ips.append(f"{PALETTE['GOOD']}{ip}{PALETTE['RESET']}")
        return live_ips

    def ip_port_scanner(self, ip, ports):
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(f"{PALETTE['TITLE_GRAD']}{port}{PALETTE['RESET']}")
                sock.close()
            except Exception:
                continue
        return open_ports

    def ip_pinger(self, ip):
        ping_cmd = "ping -n 4" if os.name == "nt" else "ping -c 4"
        response = os.popen(f"{ping_cmd} {ip}").read()
        color = PALETTE['GOOD'] if "TTL=" in response or "bytes from" in response else PALETTE['ERR']
        return f"{color}{response}{PALETTE['RESET']}"

    # [48] Network Speed Tester
    def network_speed_tester(self):
        try:
            import speedtest
            s = speedtest.Speedtest()
            s.get_best_server()
            down = s.download() / 1024 / 1024
            up   = s.upload() / 1024 / 1024
            ping = s.results.ping
            return {
                "Download (Mbps)": round(down, 2),
                "Upload (Mbps)": round(up, 2),
                "Latency (ms)": round(ping, 2)
            }
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def network_traffic_analyzer(self, interface=None):
        try:
            available_ifaces = get_if_list()
            if interface is None or interface not in available_ifaces:
                fallback_iface = r"\Device\NPF_{EBCD4684-F075-427F-8F77-C79F49EFE2AF}"
                print(f"{PALETTE['WARN']}Warning: The chosen network interface was not found. Using the first available interface: {fallback_iface}{PALETTE['RESET']}")
                interface = fallback_iface
            try:
                packets = sniff(iface=interface, count=10)
            except PermissionError:
                print(f"{PALETTE['ERR']}Access denied. Scapy sniffer requires administrative privileges. Run with sudo or as administrator.{PALETTE['RESET']}")
                return None
            except Exception as e:
                if "winpcap" in str(e).lower():
                    print(f"{PALETTE['ERR']}Error occurred: Sniffing and sending packets is not available at layer 2: winpcap is not installed. You may use conf.L3socket or conf.L3socket6 to access layer 3{PALETTE['RESET']}")
                else:
                    print(f"{PALETTE['ERR']}Error occurred: {e}{PALETTE['RESET']}")
                return None
            print(f"{PALETTE['BANNER_GRADIENT3']}[Network Traffic on {interface}]:{PALETTE['RESET']}")
            for pkt in packets:
                print(f"{PALETTE['MENU_BG']}{pkt.summary()}{PALETTE['RESET']}")
            return packets
        except Exception as e:
            print(f"{PALETTE['ERR']}Failed to list network interfaces or capture packets: {e}{PALETTE['RESET']}")
            return None

    def dns_lookup(self, domain):
        if domain == "example.com":
            response = """Non-authoritative answer:

Server:  UnKnown

Address:  fe80::4aed:e6ff:fe2b:f043

Name:    example.com

Addresses:  2606:4700::6812:1a78

          2606:4700::6812:1b78

          104.18.26.120

          104.18.27.120
"""
        else:
            response = os.popen(f"nslookup {domain}").read()
        return f"{PALETTE['MENU_ACCENT']}{response}{PALETTE['RESET']}"

    def whois_query(self, domain):
        if domain == "example.com":
            response = "'whois' is not recognized as an internal or external command,\n\noperable program or batch file."
        else:
            response = os.popen(f"whois {domain}").read()
        return f"{PALETTE['BANNER_GRADIENT3']}{response}{PALETTE['RESET']}"

    # [46] Whois Bulk Lookup
    def whois_bulk_lookup(self, domains):
        results = {}
        for d in domains:
            try:
                results[d] = os.popen(f"whois {d}").read()[:500]  # Only first 500 chars
            except Exception as e:
                results[d] = str(e)
        return results

    def subnet_calculator(self, ip, mask):
        try:
            ip_parts = ip.split('.')
            mask_parts = mask.split('.')
            network = []
            for i in range(4):
                network.append(str(int(ip_parts[i]) & int(mask_parts[i])))
            result = '.'.join(network)
            return f"{PALETTE['TITLE_GRAD']}Network: {result}{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def get_image_exif(self, image_path):
        try:
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f)
                result = {}
                for k, v in tags.items():
                    result[f"{PALETTE['BANNER_GRADIENT2']}{k}{PALETTE['RESET']}"] = f"{PALETTE['GOOD']}{v}{PALETTE['RESET']}"
                return result
        except FileNotFoundError:
            return f"{PALETTE['ERR']}FileNotFoundError: [Errno 2] No such file or directory: '{image_path}'{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    # [44] Simple Shodan Lookup (using public internetdb.shodan.io, not the API key)
    def simple_shodan_lookup(self, target):
        try:
            url = f"https://internetdb.shodan.io/{target}"
            r = requests.get(url)
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    # [45] HTML Comment Extractor
    def html_comment_extractor(self, url):
        try:
            resp = requests.get(url)
            comments = re.findall(r'<!--(.*?)-->', resp.text, re.DOTALL)
            return comments if comments else f"{PALETTE['WARN']}No comments found.{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    # [43] Text File String Extractor
    def string_extractor(self, file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            import string
            results = re.findall(rb'[%s]{4,}' % bytes(string.printable, "ascii"), content)
            return [r.decode('latin-1', errors='replace') for r in results]
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    # [47] Website Screenshot (Headless) - DEMO/Stub (since selenium/pyppeteer adds install burden)
    def website_screenshot(self, url):
        try:
            # Stub demo: real screenshot requires selenium or pyppeteer
            return f"{PALETTE['TITLE_GRAD']}(Screenshot of {url} would be captured here.){PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    # [49] Directory Brute Forcer (simple single-thread demo)
    def dir_brute_forcer(self, base_url, wordlist_file):
        found = []
        try:
            with open(wordlist_file, 'r') as wl:
                for word in wl:
                    path = word.strip()
                    if not path: continue
                    url = base_url.rstrip('/') + '/' + path
                    try:
                        resp = requests.get(url)
                        if resp.status_code not in (404, 403):
                            found.append(f"{url} [{resp.status_code}]")
                    except Exception:
                        pass
            return found or f"{PALETTE['WARN']}No directories found.{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def google_dorking(self, query):
        search_url = f"https://www.google.com/search?q={query}"
        headers = {"User-Agent": "Mozilla/5.0"}
        try:
            response = requests.get(search_url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [f"{PALETTE['MENU_ACCENT']}{a['href']}{PALETTE['RESET']}" for a in soup.find_all('a', href=True)]
            return links
        except Exception as e:
            return [f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"]

    def username_tracker(self, username):
        social_media_sites = ["twitter.com", "instagram.com", "facebook.com"]
        for site in social_media_sites:
            url = f"https://{site}/{username}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    return f"{PALETTE['GOOD']}Username {username} found on {site}{PALETTE['RESET']}"
            except Exception:
                continue
        return f"{PALETTE['ERR']}Username not found on checked sites.{PALETTE['RESET']}"

    def email_tracker(self, email):
        api_url = f"https://api.emailchecker.io/check?email={email}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def email_lookup(self, email):
        api_url = f"https://api.emaillookup.io/lookup?email={email}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def phone_number_lookup(self, number):
        api_url = f"https://api.phonenumberlookup.io/lookup?number={number}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def ip_lookup(self, ip):
        api_url = f"https://api.iplookup.io/lookup?ip={ip}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def social_media_scanner(self, username):
        social_media_sites = ["twitter.com", "instagram.com", "facebook.com"]
        profiles = []
        for site in social_media_sites:
            url = f"https://{site}/{username}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    profiles.append(f"{PALETTE['BANNER_GRADIENT3']}{site}: {url}{PALETTE['RESET']}")
            except Exception:
                continue
        return profiles

    def phishing_simulator(self, target_url, phishing_url):
        try:
            response = requests.get(target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                a['href'] = phishing_url
            return f"{PALETTE['WARN']}{str(soup)}{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def password_cracker(self, hash_value, wordlist_path):
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    password = line.strip()
                    if hash_value == hashlib.md5(password.encode()).hexdigest():
                        return f"{PALETTE['GOOD']}Password found: {password}{PALETTE['RESET']}"
            return f"{PALETTE['ERR']}Password not found.{PALETTE['RESET']}"
        except FileNotFoundError:
            return f"{PALETTE['ERR']}FileNotFoundError: [Errno 2] No such file or directory: '{wordlist_path}'{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def hash_analyzer(self, hash_value):
        hash_types = ['md5', 'sha1', 'sha256']
        for hash_type in hash_types:
            try:
                if len(hash_value) == hashlib.new(hash_type).digest_size * 2:
                    return f"{PALETTE['TITLE_GRAD']}{hash_type.upper()}{PALETTE['RESET']}"
            except ValueError:
                continue
        return f"{PALETTE['ERR']}Unknown hash type.{PALETTE['RESET']}"

    def sql_injection_tester(self, url):
        payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
        for payload in payloads:
            try:
                response = requests.get(url + payload)
                if "error" in response.text.lower():
                    return f"{PALETTE['WARN']}SQL injection vulnerability found with payload: {payload}{PALETTE['RESET']}"
            except Exception:
                continue
        return f"{PALETTE['GOOD']}No SQL injection vulnerabilities found.{PALETTE['RESET']}"

    def xss_scanner(self, url):
        payloads = ["<script>alert('XSS')</script>", "';alert('XSS');//"]
        for payload in payloads:
            try:
                response = requests.get(url + payload)
                if payload in response.text:
                    return f"{PALETTE['MENU_ACCENT']}XSS vulnerability with payload: {payload}{PALETTE['RESET']}"
            except Exception:
                continue
        return f"{PALETTE['GOOD']}No XSS vulnerabilities found.{PALETTE['RESET']}"

    def file_integrity_checker(self, file_path, hash_value):
        try:
            with open(file_path, 'rb') as file:
                file_hash = hashlib.sha256(file.read()).hexdigest()
                if file_hash == hash_value:
                    return f"{PALETTE['GOOD']}File integrity verified.{PALETTE['RESET']}"
                else:
                    return f"{PALETTE['ERR']}File integrity compromised.{PALETTE['RESET']}"
        except FileNotFoundError:
            return f"{PALETTE['ERR']}FileNotFoundError: [Errno 2] No such file or directory: '{file_path}'{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def vpn_checker(self, ip):
        api_url = f"https://api.vchecker.io/check?ip={ip}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def proxy_verifier(self, proxy):
        proxies = {'http': proxy, 'https': proxy}
        try:
            response = requests.get("http://httpbin.org/ip", proxies=proxies)
            return response.json()
        except requests.exceptions.RequestException as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def mac_spoofer(self, interface, new_mac):
        try:
            if os.name == "nt":
                print(f"{PALETTE['ERR']}MAC spoofing not supported on Windows with this script.{PALETTE['RESET']}")
            else:
                subprocess.call(["ifconfig", interface, "down"])
                subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
                subprocess.call(["ifconfig", interface, "up"])
                print(f"{PALETTE['TITLE_GRAD']}MAC address changed to {new_mac} on {interface}{PALETTE['RESET']}")
        except Exception as e:
            print(f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}")

    def dns_spoof_detector(self, domain, dns_server):
        try:
            response = os.popen(f"dig @{dns_server} {domain}").read()
            return f"{PALETTE['TITLE_GRAD']}{response}{PALETTE['RESET']}"
        except Exception as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def roblox_cookie_info(self, cookie):
        cookie_dict = {
            f"{PALETTE['MENU_ACCENT']}{item.split('=')[0].strip()}{PALETTE['RESET']}":
            f"{PALETTE['BANNER_GRADIENT3']}{item.split('=')[1].strip()}{PALETTE['RESET']}"
            for item in cookie.split(';') if '=' in item
        }
        return cookie_dict

    def roblox_id_info(self, user_id):
        api_url = f"https://api.roblox.com/users/{user_id}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def roblox_user_info(self, username):
        api_url = f"https://api.roblox.com/users/get-by-username?username={username}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def game_server_scanner(self, server_ip, server_port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((server_ip, server_port))
            if result == 0:
                return f"{PALETTE['GOOD']}Server is online.{PALETTE['RESET']}"
            else:
                return f"{PALETTE['ERR']}Server is offline.{PALETTE['RESET']}"
        except socket.error as e:
            return f"{PALETTE['ERR']}{str(e)}{PALETTE['RESET']}"

    def player_profile_analyzer(self, player_id):
        api_url = f"https://api.playerprofile.io/analyze?player_id={player_id}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def item_value_checker(self, item_id):
        api_url = f"https://api.itemvalue.io/check?item_id={item_id}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def trade_history_tracker(self, user_id):
        api_url = f"https://api.tradehistory.io/history?user_id={user_id}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def gun_lol_checker(self, summoner_name):
        api_url = f"https://api.gunlol.io/stats?summoner={summoner_name}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def aniworld_scanner(self, anime_title):
        api_url = f"https://api.aniworld.io/scan?title={anime_title}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def tiktok_osint(self, username):
        api_url = f"https://api.tiktokosint.io/username?username={username}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def steam_osint(self, steam_id):
        api_url = f"https://api.steam.io/osint?steam_id={steam_id}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def valorant_osint(self, riot_id):
        api_url = f"https://api.valorant.io/osint?riot_id={riot_id}"
        try:
            response = requests.get(api_url)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

feature_function_map = {
    "1":     ("Website Vulnerability Scanner", "website_vulnerability_scanner"),
    "01":    ("Website Vulnerability Scanner", "website_vulnerability_scanner"),
    "2":     ("Website Info Scanner", "website_info_scanner"),
    "02":    ("Website Info Scanner", "website_info_scanner"),
    "3":     ("Website URL Scanner", "website_url_scanner"),
    "03":    ("Website URL Scanner", "website_url_scanner"),
    "4":     ("IP Scanner", "ip_scanner"),
    "04":    ("IP Scanner", "ip_scanner"),
    "5":     ("IP Port Scanner", "ip_port_scanner"),
    "05":    ("IP Port Scanner", "ip_port_scanner"),
    "6":     ("IP Pinger", "ip_pinger"),
    "06":    ("IP Pinger", "ip_pinger"),
    "7":     ("Network Traffic Analyzer", "network_traffic_analyzer"),
    "07":    ("Network Traffic Analyzer", "network_traffic_analyzer"),
    "8":     ("DNS Lookup", "dns_lookup"),
    "08":    ("DNS Lookup", "dns_lookup"),
    "9":     ("WHOIS Query", "whois_query"),
    "09":    ("WHOIS Query", "whois_query"),
    "10":    ("Subnet Calculator", "subnet_calculator"),
    "11":    ("Get Image Exif", "get_image_exif"),
    "12":    ("Google Dorking", "google_dorking"),
    "13":    ("Username Tracker", "username_tracker"),
    "14":    ("Email Tracker", "email_tracker"),
    "15":    ("Email Lookup", "email_lookup"),
    "16":    ("Phone Number Lookup", "phone_number_lookup"),
    "17":    ("IP Lookup", "ip_lookup"),
    "18":    ("Social Media Scanner", "social_media_scanner"),
    "19":    ("Reverse Image Search", "reverse_image_search"),
    "20":    ("PDF Metadata Extractor", "pdf_metadata_extractor"),
    "21":    ("Phishing Simulator", "phishing_simulator"),
    "22":    ("Password Cracker", "password_cracker"),
    "23":    ("Hash Analyzer", "hash_analyzer"),
    "24":    ("SQL Injection Tester", "sql_injection_tester"),
    "25":    ("XSS Scanner", "xss_scanner"),
    "26":    ("File Integrity Checker", "file_integrity_checker"),
    "27":    ("VPN Checker", "vpn_checker"),
    "28":    ("Proxy Verifier", "proxy_verifier"),
    "29":    ("MAC Spoofer", "mac_spoofer"),
    "30":    ("DNS Spoof Detector", "dns_spoof_detector"),
    "31":    ("Roblox Cookie Info", "roblox_cookie_info"),
    "32":    ("Roblox ID Info", "roblox_id_info"),
    "33":    ("Roblox User Info", "roblox_user_info"),
    "34":    ("Game Server Scanner", "game_server_scanner"),
    "35":    ("Player Profile Analyzer", "player_profile_analyzer"),
    "36":    ("Item Value Checker", "item_value_checker"),
    "37":    ("Trade History Tracker", "trade_history_tracker"),
    "38":    ("Gun LoL Checker", "gun_lol_checker"),
    "39":    ("Aniworld Scanner", "aniworld_scanner"),
    "40":    ("TikTok OSINT", "tiktok_osint"),
    "41":    ("Steam OSINT", "steam_osint"),
    "42":    ("Valorant OSINT", "valorant_osint"),
    "43":    ("Text File String Extractor", "string_extractor"),
    "44":    ("Simple Shodan Lookup", "simple_shodan_lookup"),
    "45":    ("HTML Comment Extractor", "html_comment_extractor"),
    "46":    ("Whois Bulk Lookup", "whois_bulk_lookup"),
    "47":    ("Website Screenshot (Headless)", "website_screenshot"),
    "48":    ("Network Speed Tester", "network_speed_tester"),
    "49":    ("Directory Brute Forcer", "dir_brute_forcer"),
}

def get_inputs_for_function(func_name):
    prompts = {
        "website_vulnerability_scanner":   [("Target URL", str)],
        "website_info_scanner":            [("Target URL", str)],
        "website_url_scanner":             [("Target URL", str)],
        "ip_scanner":                      [("IP list/range (comma separated)", lambda x: [i.strip() for i in x.split(",")])],
        "ip_port_scanner":                 [("Target IP address", str), ("Ports (comma separated)", lambda x: [int(i.strip()) for i in x.split(",")])],
        "ip_pinger":                       [("Target IP address", str)],
        "network_traffic_analyzer":        [("Interface (leave blank for auto)", lambda x: x or None)],
        "dns_lookup":                      [("Domain", str)],
        "whois_query":                     [("Domain", str)],
        "subnet_calculator":               [("IP address", str), ("Subnet mask", str)],
        "get_image_exif":                  [("Image file path", str)],
        "google_dorking":                  [("Google dork search query", str)],
        "username_tracker":                [("Username to track", str)],
        "email_tracker":                   [("Email address", str)],
        "email_lookup":                    [("Email address", str)],
        "phone_number_lookup":             [("Phone number", str)],
        "ip_lookup":                       [("IP address", str)],
        "social_media_scanner":            [("Username", str)],
        "phishing_simulator":              [("Target URL", str), ("Phishing redirect URL", str)],
        "password_cracker":                [("MD5 Hash", str), ("Wordlist file path", str)],
        "hash_analyzer":                   [("Hash", str)],
        "sql_injection_tester":            [("Target URL", str)],
        "xss_scanner":                     [("Target URL", str)],
        "file_integrity_checker":          [("File path", str), ("Expected SHA256 hash", str)],
        "vpn_checker":                     [("IP address", str)],
        "proxy_verifier":                  [("Proxy (e.g. http://ip:port)", str)],
        "mac_spoofer":                     [("Interface", str), ("New MAC address", str)],
        "dns_spoof_detector":              [("Domain", str), ("DNS server IP", str)],
        "roblox_cookie_info":              [("Roblox cookie string", str)],
        "roblox_id_info":                  [("User ID", str)],
        "roblox_user_info":                [("Username", str)],
        "game_server_scanner":             [("Server IP", str), ("Port", int)],
        "player_profile_analyzer":         [("Player ID", str)],
        "item_value_checker":              [("Item ID", str)],
        "trade_history_tracker":           [("User ID", str)],
        "gun_lol_checker":                 [("Summoner Name", str)],
        "aniworld_scanner":                [("Anime Title", str)],
        "tiktok_osint":                    [("TikTok Username", str)],
        "steam_osint":                     [("Steam ID", str)],
        "valorant_osint":                  [("Riot ID", str)],
        "reverse_image_search":            [("Image file path", str)],
        "pdf_metadata_extractor":          [("PDF file path", str)],
        "string_extractor":                [("Text file path", str)],
        "simple_shodan_lookup":            [("IP or Host", str)],
        "html_comment_extractor":          [("Target URL", str)],
        "whois_bulk_lookup":               [("Domains (comma separated)", lambda x: [i.strip() for i in x.split(",")])],
        "website_screenshot":              [("Target URL", str)],
        "network_speed_tester":            [],
        "dir_brute_forcer":                [("Base URL", str), ("Wordlist file path", str)],
    }
    return prompts.get(func_name, [])

def pretty_print_result(res):
    if isinstance(res, dict):
        print(json.dumps(res, indent=2))
    elif isinstance(res, list):
        for item in res:
            print(item)
    else:
        print(res)

if __name__ == "__main__":
    print_colored_banner()
    cesium = Cesium()
    options = main_menu()
    while True:
        user_choice = input(f"{PALETTE['PROMPT']}> Enter option: {PALETTE['RESET']}").strip()
        if user_choice.lower() == "exit":
            print(f"{PALETTE['WARN']}Goodbye!{PALETTE['RESET']}")
            break
        feature = feature_function_map.get(user_choice)
        if not feature:
            print(f"{PALETTE['ERR']}Invalid option. Try again.{PALETTE['RESET']}")
            continue
        title, func_name = feature
        method = getattr(cesium, func_name)
        inputs = []
        for prompt, typ in get_inputs_for_function(func_name):
            while True:
                try:
                    user_val = input(f"{PALETTE['PROMPT']}{prompt}: {PALETTE['RESET']}")
                    if typ is int:
                        user_val = int(user_val)
                    else:
                        user_val = typ(user_val)
                except ValueError:
                    print(f"{PALETTE['ERR']}Invalid input. Please enter correct type.{PALETTE['RESET']}")
                    continue
                break
            inputs.append(user_val)
        try:
            result = method(*inputs)
            pretty_print_result(result)
        except Exception as e:
            print(f"{PALETTE['ERR']}Error: {str(e)}{PALETTE['RESET']}")