# 🛡️ IP Reputation Checker

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Made with Bash](https://img.shields.io/badge/made%20with-bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![VirusTotal API](https://img.shields.io/badge/API-VirusTotal-blueviolet)](https://www.virustotal.com/)
[![AbuseIPDB API](https://img.shields.io/badge/API-AbuseIPDB-orange)](https://www.abuseipdb.com/)

> ⚔️ A Bash-based threat intelligence tool to check the reputation of IPs using AbuseIPDB and VirusTotal APIs.  
> Fast, simple, and great for incident response, SOC automation, or security investigations.

---

## ✨ Features

- 🔍 **Instantly check** IP reputation via trusted public sources
- 📊 **AbuseIPDB** score, usage type, country, and last reported time
- 🛡️ **VirusTotal** vendor detection stats and threat flags
- 📁 Supports **bulk input** via `.txt` file
- ⚙️ Minimal dependencies, just `curl` and `jq`

---

## 🚀 Getting Started

### 1. 🔐 Insert Your API Keys

Edit `ipcheck.sh`:

```bash
ABUSEIPDB_API_KEY="Insert Your AbuseIPDB API Key Here"
VIRUSTOTAL_API_KEY="Insert Your VirusTotal API Key Here"
```
### 2. 👨‍💻 Usage
```
./ipcheck.sh 185.254.75.43
Checking IP: 185.254.75.43
AbuseIPDB - IP: 185.254.75.43 | Confidence Score: 19 | Country: DE | Usage Type: Data Center/Web Hosting/Transit | Last Reported: 2025-04-23T14:20:35+00:00
VirusTotal - IP: 185.254.75.43 | Malicious Reports: 1 | Vendors: MalwareURL

./ipcheck.sh file.txt
Checking IP: 1.1.1.1
AbuseIPDB - IP: 1.1.1.1 | Confidence Score: 0 | Country: AU | Usage Type: CDN | Last Reported: Never
VirusTotal - IP: 1.1.1.1 | Malicious Reports: 0 | Vendors: 
----------------------------------------

Checking IP: 8.8.8.8
AbuseIPDB - IP: 8.8.8.8 | Confidence Score: 0 | Country: US | Usage Type: ISP | Last Reported: Never
VirusTotal - IP: 8.8.8.8 | Malicious Reports: 0 | Vendors: 
----------------------------------------
```

---

## 🤝 Contributing

Got ideas or improvements?  
Feel free to **fork**, **star ⭐**, and submit a **pull request** — all contributions are welcome!

---

## 👨‍💻 Author

Created with ❤️ by [Sahil Ojha](https://github.com/sahiloj)
