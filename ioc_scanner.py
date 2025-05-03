import os
import re
import requests
import time
import ctypes
import sys
import json
import ipaddress
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

# === CONFIG ===
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
SCAN_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\\AppData\\Local\\Logs"),
    r"C:\\Users",
    r"C:\\ProgramData",
    r"C:\\Windows\\System32\\LogFiles"
]
ALERT_FILE = "alerts.txt"
RESULT_FILE = "results.txt"
SCAN_DB_FILE = "scan_db.json"
IOC_DB_FILE = "ioc_db.json"

# === IOC REGEX ===
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|int|edu|gov|mil|arpa|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw|հայ|বাংলা)\b"
HASH_REGEX = r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b"

# === Load/Save Databases ===
def load_json_file(path, default=None):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default if default is not None else {}, f)
        return default if default is not None else {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load {path}: {e}")
        return default if default is not None else {}

def save_json_file(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# === IP Check ===
def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return True

# === VirusTotal API ===
def check_virustotal(ioc):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        if re.fullmatch(IP_REGEX, ioc):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif re.fullmatch(HASH_REGEX, ioc):
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif re.fullmatch(DOMAIN_REGEX, ioc):
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        else:
            return None

        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes']['last_analysis_stats']['malicious']
        elif response.status_code == 404:
            return 0
        else:
            print(Fore.BLUE + f"[VT] Error {response.status_code}: Failed to query {ioc}" + Style.RESET_ALL)
            return None
    except requests.RequestException as e:
        print(Fore.BLUE + f"[VT] Connection error: {e}" + Style.RESET_ALL)
        input("Press Enter to continue...")

        return None


# === AbuseIPDB API ===
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "30"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data['data']['abuseConfidenceScore']
        else:
            print(Fore.BLUE + f"[AbuseIPDB] Error {response.status_code} while checking {ip}" + Style.RESET_ALL)
            input("Press Enter to continue...")

            return None
    except requests.RequestException as e:
        print(Fore.BLUE + f"[AbuseIPDB] Connection error: {e}" + Style.RESET_ALL)
        return None


# === Write alert to result.txt ===
def log_result(alert):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {alert}\n"
    with open(RESULT_FILE, "a") as rf:
        rf.write(entry)

# === Scan logs ===
def scan_logs():
    scan_db = load_json_file(SCAN_DB_FILE)
    ioc_db = load_json_file(IOC_DB_FILE)

    for base_dir in SCAN_DIRS:
        for path in Path(base_dir).rglob("*.log"):
            try:
                path_str = str(path)
                size = os.path.getsize(path)

                if path_str in scan_db and scan_db[path_str] == size:
                    print(f"[~] Skipping unchanged file: {path_str}")
                    continue

                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    iocs = set()
                    iocs.update(re.findall(IP_REGEX, content))
                    iocs.update(re.findall(DOMAIN_REGEX, content))
                    for h in re.findall(HASH_REGEX, content):
                        if len(h) in (32, 40, 64):
                            iocs.add(h)

                    for ioc in iocs:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        alert = None

                        if ioc in ioc_db:
                            prev_data = ioc_db[ioc]
                            relist = f"[{timestamp}] [!] Previously flagged IOC: {ioc} (First found in: {prev_data['path']}, Date: {prev_data['timestamp']}, VT: {prev_data['vt_score']}, AbuseIPDB: {prev_data.get('abuse_score', 'N/A')}, Also found in: {path_str})"
                            print(Fore.YELLOW + relist + Style.RESET_ALL)
                            log_result(re.sub(r'\x1b\[[0-9;]*m', '', relist))
                            with open(ALERT_FILE, "a") as af:
                                af.write(re.sub(r'\x1b\[[0-9;]*m', '', relist) + "\n")
                            continue

                        vt_score = None
                        abuse_score = None

                        if re.fullmatch(IP_REGEX, ioc) and not is_internal_ip(ioc):
                            vt_score = check_virustotal(ioc)
                            abuse_score = check_abuseipdb(ioc)
                            if vt_score and vt_score >= 1:
                                alert = f"[!] Suspicious IP: {ioc} in {path_str} (VT: {vt_score}, AbuseIPDB: {abuse_score})"
                            elif abuse_score and abuse_score > 30:
                                alert = f"[!] High Abuse Score IP: {ioc} in {path_str} (VT: {vt_score}, AbuseIPDB: {abuse_score})"
                        elif re.fullmatch(DOMAIN_REGEX, ioc) or re.fullmatch(HASH_REGEX, ioc):
                            vt_score = check_virustotal(ioc)
                            if vt_score and vt_score >= 1:
                                alert = f"[!] Suspicious IOC: {ioc} in {path_str} (VT: {vt_score})"

                        if alert:
                            final_alert = f"[{timestamp}] {alert}"
                            print(Fore.RED + final_alert + Style.RESET_ALL)
                            log_result(re.sub(r'\x1b\[[0-9;]*m', '', final_alert))
                            with open(ALERT_FILE, "a") as af:
                                af.write(re.sub(r'\x1b\[[0-9;]*m', '', final_alert) + "\n")

                            ioc_db[ioc] = {
                                "timestamp": timestamp,
                                "path": path_str,
                                "vt_score": vt_score,
                                "abuse_score": abuse_score
                            }
                            save_json_file(IOC_DB_FILE, ioc_db)

                        time.sleep(1.2)

                scan_db[path_str] = size
                save_json_file(SCAN_DB_FILE, scan_db)

            except Exception as e:
                print(f"[!] Failed to scan {path}: {e}")

    print("[+] Scan complete.")

# === Request Admin Privileges ===
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if not is_admin():
        print("[!] Admin privileges required. Relaunching as admin...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

    print("[+] Starting IOC scan in directories:")
    for d in SCAN_DIRS:
        print("   ", d)
    scan_logs()
    print("[+] Alerts saved to", ALERT_FILE)
    print("[+] Detailed results saved to", RESULT_FILE)
