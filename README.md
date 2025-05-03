# 🛡️ IOC Enrichment Scanner

A standalone Python-based IOC (Indicators of Compromise) enrichment tool for threat intelligence analysis. Scans directories for IPs, domains, and hashes in log files, checks them against VirusTotal and AbuseIPDB, and logs alerts with detailed context.
👉 For a full code walkthrough and detailed explanation, [read the Medium post here.]([url](https://medium.com/@ameer123.1999/from-coursera-to-code-building-a-simple-ioc-scanner-in-python-1efeadf8ffa9))



---

## 🚀 Features

- 🔍 Scans log files for IPs, domains, and hashes
- ☁️ Integrates with [VirusTotal](https://www.virustotal.com/) and [AbuseIPDB](https://www.abuseipdb.com/)
- 🧠 Avoids duplicate IOC lookups with result caching
- 📋 Generates enriched logs with detection timestamps
- ⚙️ Simple CLI tool – works on Windows with no extra setup

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/ameeraz19/IOC-Hunter.git
cd IOC-Hunter
```
2. Install Requirements
Make sure you have Python 3.8+ installed, then install dependencies:

```bash
pip install -r requirements.txt
```

🔑 Configuration
1. Get API Keys
VirusTotal: [Get your API key here]([url](https://www.virustotal.com/gui/my-apikey))

AbuseIPDB: [Sign up and get an API key]([url](https://www.abuseipdb.com/account/api))

2. Set Your API Keys

[API_KEYS]
change this parameters in ioc_scanner.py
virustotal = YOUR_VIRUSTOTAL_API_KEY
abuseipdb = YOUR_ABUSEIPDB_API_KEY


