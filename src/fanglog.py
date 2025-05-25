import argparse
import re
import ipaddress
from pathlib import Path
import requests
import sys
import os

# ------------------------------------------
# FangLog Testing Guide
#
# 1. Prepare sample log file (e.g., sample.log) with lines like:
#    2024-06-01 12:00:00 Connection from 185.225.19.240 to server
#    2024-06-01 12:01:00 User ran: powershell -nop -w hidden -enc aGVsbG8=
#    2024-06-01 12:02:00 Downloaded from malicious-domain.com
#    2024-06-01 12:03:00 File hash: 9f0d1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd
#
# 2. Ensure you have threat lists:
#    - bad_ips.txt (e.g., contains 185.225.19.240)
#    - bad_domains.txt (e.g., contains malicious-domain.com)
#    - bad_hashes.txt (e.g., contains 9f0d1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd)
#
# 3. Run the tool:
#    python fanglog.py sample.log
#
# 4. Check the terminal output for detected IOCs.
#
# 5. Try with --ioc-only or custom threat list paths if desired.
# ------------------------------------------

# --- IOC regex patterns ---
IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
DOMAIN_REGEX = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
HASH_REGEX = r'\b[a-fA-F0-9]{32,64}\b'
BASE64_REGEX = r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])'
CMD_REGEX = r'\b(powershell|cmd\.exe|certutil|wget|curl|net user|base64)\b'
SUSP_PATH_REGEX = r'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'

def load_threat_list(path):
    if not Path(path).exists():
        return set()
    with open(path, 'r') as f:
        # Only add non-empty, stripped lines
        return set(line.strip() for line in f if line.strip())

def extract_iocs(line):
    iocs = {
        'ips': re.findall(IP_REGEX, line),
        'domains': re.findall(DOMAIN_REGEX, line),
        'hashes': re.findall(HASH_REGEX, line),
        'base64': re.findall(BASE64_REGEX, line),
        'commands': re.findall(CMD_REGEX, line.lower()),
        'susp_paths': re.findall(SUSP_PATH_REGEX, line),
    }
    return iocs

def match_iocs(iocs, bad_ips, bad_domains, bad_hashes):
    # Normalize domains for case-insensitive comparison
    bad_domains_lower = set(d.lower() for d in bad_domains)
    matches = {
        'malicious_ips': [ip for ip in iocs['ips'] if ip in bad_ips],
        'suspicious_domains': [d for d in iocs['domains'] if d.lower() in bad_domains_lower],
        'malicious_hashes': [h for h in iocs['hashes'] if h in bad_hashes],
        'suspicious_commands': iocs['commands'],
        'base64_blobs': iocs['base64'],
        'suspicious_paths': iocs['susp_paths'],
    }
    return matches

def abuseipdb_check(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()["data"]
            if data.get("abuseConfidenceScore", 0) >= 50:
                return f"{ip} (AbuseIPDB score: {data['abuseConfidenceScore']})"
        return None
    except Exception:
        return None

def virustotal_check(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return f"{hash_value} (VirusTotal: {malicious} engines flagged)"
        return None
    except Exception:
        return None

def print_report(all_matches, abuseipdb_api_key=None, virustotal_api_key=None, ioc_only=False):
    if ioc_only:
        # Only print detected indicators, one per line, grouped by type
        for k, label in [
            ('malicious_ips', 'Malicious IPs'),
            ('suspicious_domains', 'Suspicious domains'),
            ('malicious_hashes', 'Suspicious file hash'),
            ('suspicious_commands', 'Suspicious commands'),
            ('base64_blobs', 'Base64 blobs'),
            ('suspicious_paths', 'Suspicious paths'),
        ]:
            if all_matches[k]:
                print(f"[{label}]")
                for v in set(all_matches[k]):
                    if k == 'base64_blobs':
                        print(f"    - {v[:40]}...")
                    else:
                        print(f"    - {v}")
        return

    print("FangLog - ANALYSIS REPORT\n" + "="*32)
    if all_matches['malicious_ips']:
        print("[!] Malicious IPs found:")
        for ip in set(all_matches['malicious_ips']):
            print(f"    - {ip}")
    # AbuseIPDB API check for all found IPs
    if abuseipdb_api_key and all_matches['malicious_ips']:
        print("[!] AbuseIPDB API results:")
        for ip in set(all_matches['malicious_ips']):
            result = abuseipdb_check(ip, abuseipdb_api_key)
            if result:
                print(f"    - {result}")
    if all_matches['suspicious_domains']:
        print("[!] Suspicious domains:")
        for d in set(all_matches['suspicious_domains']):
            print(f"    - {d}")
    if all_matches['malicious_hashes']:
        print("[!] Suspicious file hash:")
        for h in set(all_matches['malicious_hashes']):
            print(f"    - {h}")
    # VirusTotal API check for all found hashes
    if virustotal_api_key and all_matches['malicious_hashes']:
        print("[!] VirusTotal API results:")
        for h in set(all_matches['malicious_hashes']):
            result = virustotal_check(h, virustotal_api_key)
            if result:
                print(f"    - {result}")
    if all_matches['suspicious_commands']:
        print("[!] Suspicious commands:")
        for c in set(all_matches['suspicious_commands']):
            print(f"    - {c}")
    if all_matches['base64_blobs']:
        print("[!] Base64 blobs detected")
        for b in set(all_matches['base64_blobs']):
            print(f"    - {b[:40]}...")
    if all_matches['suspicious_paths']:
        print("[!] Suspicious paths detected")
        for p in set(all_matches['suspicious_paths']):
            print(f"    - {p}")

def resolve_sample_path(filename):
    """
    Resolve a sample file path relative to the project root if not found in cwd.
    """
    # Try current working directory first
    if Path(filename).exists():
        return filename
    # Try project root/sample/
    project_root = Path(__file__).parent.parent
    sample_path = project_root / "sample" / filename
    if sample_path.exists():
        return str(sample_path)
    # Try project root
    root_path = project_root / filename
    if root_path.exists():
        return str(root_path)
    # Not found
    return filename

def main():
    parser = argparse.ArgumentParser(
        description="FangLog - Scan logs for Indicators of Compromise (IOCs)",
        epilog="""
Examples:
  python -m src.fanglog sample.log
      Scan 'sample.log' using local threat lists.

  python -m src.fanglog sample.csv
      Scan 'sample.csv' in the sample/ folder if not found in cwd.

  python -m src.fanglog --bad-ips my_ips.txt --bad-domains my_domains.txt
      Use custom threat lists.

  python -m src.fanglog sample.log --abuseipdb-key <APIKEY>
      Scan and check all found IPs against AbuseIPDB.

  python -m src.fanglog sample.log --virustotal-key <APIKEY>
      Scan and check all found hashes against VirusTotal.

  python -m src.fanglog sample.log --abuseipdb-key <APIKEY> --virustotal-key <APIKEY>
      Use both APIs for live threat intelligence.

Threat List Files:
  - bad_ips.txt: One IP address per line.
  - bad_domains.txt: One domain per line (no blank lines).
  - bad_hashes.txt: One hash (MD5/SHA1/SHA256) per line.

Log File:
  - Accepts .log, .txt, or .csv files.
  - Each line is scanned for IOCs (IPs, domains, hashes, suspicious commands, base64, suspicious paths).

API Keys:
  - AbuseIPDB: https://www.abuseipdb.com/api.html
  - VirusTotal: https://developers.virustotal.com/reference/overview

Exit Codes:
  0 = Success, 1 = Error

For more info, see the FangLog Testing Guide at the top of this script.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("logfile", nargs="?", help="Path to log file (.log, .txt, .csv) to scan for IOCs (filename only is fine if in sample/)")
    parser.add_argument("--bad-ips", help="Path to bad IPs list (default: bad_ips.txt)", default="bad_ips.txt")
    parser.add_argument("--bad-domains", help="Path to bad domains list (default: bad_domains.txt)", default="bad_domains.txt")
    parser.add_argument("--bad-hashes", help="Path to bad hashes list (default: bad_hashes.txt)", default="bad_hashes.txt")
    parser.add_argument("--ioc-only", action="store_true", help="List only detected indicators, suppressing other output")
    parser.add_argument("--abuseipdb-key", help="AbuseIPDB API key for live IP reputation checks (optional)")
    parser.add_argument("--virustotal-key", help="VirusTotal API key for live hash reputation checks (optional)")
    args = parser.parse_args()

    # Print ASCII art banner
    print("""
 ______                _                 _ 
|  ____|              | |               | |
| |__ __ _ _ __   __ _| |     ___   __ _| |
|  __/ _` | '_ \ / _` | |    / _ \ / _` | |
| | | (_| | | | | (_| | |___| (_) | (_| |_|
|_|  \__,_|_| |_|\__, |______\___/ \__, (_)
                  __/ |             __/ |  
                 |___/             |___/   
""")

    if not args.logfile:
        parser.error("the following arguments are required: logfile")

    # Allow users to specify just the filename for sample logs
    logfile_path = resolve_sample_path(args.logfile)
    if not Path(logfile_path).exists():
        print(f"Error: Log file '{args.logfile}' not found (tried '{logfile_path}').", file=sys.stderr)
        sys.exit(1)

    # Also resolve threat lists from sample/ if not found in cwd
    def resolve_threat_list(path, default_name):
        if Path(path).exists():
            return path
        # Try sample/ directory
        project_root = Path(__file__).parent.parent
        sample_path = project_root / "sample" / default_name
        if sample_path.exists():
            return str(sample_path)
        return path

    bad_ips_path = resolve_threat_list(args.bad_ips, "bad_ips.txt")
    bad_domains_path = resolve_threat_list(args.bad_domains, "bad_domains.txt")
    bad_hashes_path = resolve_threat_list(args.bad_hashes, "bad_hashes.txt")

    bad_ips = load_threat_list(bad_ips_path)
    bad_domains = load_threat_list(bad_domains_path)
    bad_hashes = load_threat_list(bad_hashes_path)

    all_matches = {
        'malicious_ips': [],
        'suspicious_domains': [],
        'malicious_hashes': [],
        'suspicious_commands': [],
        'base64_blobs': [],
        'suspicious_paths': [],
    }

    with open(logfile_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            iocs = extract_iocs(line)
            matches = match_iocs(iocs, bad_ips, bad_domains, bad_hashes)
            for k in all_matches:
                all_matches[k].extend(matches[k])

    print_report(
        all_matches,
        abuseipdb_api_key=args.abuseipdb_key,
        virustotal_api_key=args.virustotal_key,
        ioc_only=args.ioc_only
    )

if __name__ == "__main__":
    main()
