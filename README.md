# FangLog

FangLog is a Python tool for scanning log files and detecting Indicators of Compromise (IOCs) such as malicious IP addresses, suspicious domains, file hashes, suspicious commands, base64 blobs, and persistence paths. It is designed for security analysts, incident responders, and anyone who needs to quickly triage logs for signs of compromise.

---

## Features

- **IOC Extraction:** Detects IPs, domains, file hashes, suspicious commands, base64 blobs, and suspicious persistence paths in `.log`, `.txt`, or `.csv` files.
- **Threat List Matching:** Compares extracted IOCs against local threat lists (`bad_ips.txt`, `bad_domains.txt`, `bad_hashes.txt`).
- **Live Threat Intelligence (Optional):**
  - **AbuseIPDB:** Checks found IPs against AbuseIPDB for reputation scoring.
  - **VirusTotal:** Checks found file hashes against VirusTotal for malware detection.
- **Flexible Input:** Accepts log files from any location or from the `sample/` directory.
- **Customizable:** Use your own threat lists or the provided samples.
- **Clear Reporting:** Outputs a concise analysis report highlighting detected threats.

---

## Quick Start

```sh
git clone https://github.com/yourusername/FangLog.git
cd FangLog
```

- Python 3.7+ required.
- Install dependencies:

```sh
pip install -r requirements.txt
```

- Place your log file (e.g., `sample.log`, `sample.csv`) in the project root or `sample/` directory.
- Ensure you have threat lists:
  - `bad_ips.txt`
  - `bad_domains.txt`
  - `bad_hashes.txt`
- Sample files are provided in the `sample/` directory.

---

## Usage

```sh
python -m src.fanglog [options] <logfile>
```

### Options

- `-h`, `--help`: Show help message and exit.
- `--bad-ips`: Path to bad IPs list (default: bad_ips.txt)
- `--bad-domains`: Path to bad domains list (default: bad_domains.txt)
- `--bad-hashes`: Path to bad hashes list (default: bad_hashes.txt)
- `--ioc-only`: List only detected indicators, suppressing other output
- `--abuseipdb-key`: AbuseIPDB API key for live IP reputation checks (optional)
- `--virustotal-key`: VirusTotal API key for live hash reputation checks (optional)

---

## Threat List Configuration

FangLog uses plain text files for threat lists by default. You can specify custom paths using command-line options.

- `bad_ips.txt`: One IP address per line.
- `bad_domains.txt`: One domain per line.
- `bad_hashes.txt`: One hash (MD5/SHA1/SHA256) per line.

Example usage with custom threat lists:

```sh
python -m src.fanglog mylog.log --bad-ips my_ips.txt --bad-domains my_domains.txt --bad-hashes my_hashes.txt
```

---

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.