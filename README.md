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

