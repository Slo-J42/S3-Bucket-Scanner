# CloudACLCheck_Detector

CloudACLCheck_Detector is an advanced autonomous security agent designed to discover, audit, and analyze cloud storage assets (AWS S3, GCP Storage, Azure Blob).

Unlike standard scanners that rely solely on name permutations, this agent utilizes OSINT techniques (Source Code Scraping, CNAME Fingerprinting) to find hidden buckets, analyzes their ACL policies, and provides a Grouped File Management System for safe data exfiltration and auditing.

---

## 🚀 Key Features

### Multi-Vector Discovery:
- **Permutations:** Intelligent bucket name guessing (e.g., target-backup, prod-target)
- **Source Code Scraping:** Crawls HTML/JS to find hardcoded cloud URLs
- **CNAME Fingerprinting:** Identifies buckets behind custom subdomains
- **Auto-Guess:** Brute-forces common asset subdomains

### Security & Auditing:
- **ACL Analysis:** Detects public access (AllUsers / AuthenticatedUsers)
- **IAM Audit Rules:** Flags critical risks based on sensitive data exposure
- **Content Heuristics:** Identifies sensitive files (.pem, .sql, backups, passwords)

### Data Management (v9):
- Smart Categorization (Images, Documents, Backups, Keys, Configs)
- Bulk Download options
- Interactive CLI preview

### Operational Security:
- Tor Integration (Port 9050/9150)
- Proxychains Compatible

### Reporting:
- JSON & TXT Export
- Real-time logging

---

## 📋 Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

```bash
git clone https://github.com/yourusername/CloudACLCheck_Detector.git
cd CloudACLCheck_Detector
pip install requests
```

### Optional (Tor Support)

```bash
pip install requests[socks]
sudo service tor start
```

---

## 📖 Usage

### Basic Scan
```bash
python CloudACLCheck_Detector_v9.py mycompany
```

### Deep Web Discovery
```bash
python CloudACLCheck_Detector_v9.py https://www.example.com
```

### Subdomain File Audit
```bash
python CloudACLCheck_Detector_v9.py placeholder --file subdomains.txt
```

### Tor Scanning
```bash
python CloudACLCheck_Detector_v9.py mycompany --tor
python CloudACLCheck_Detector_v9.py mycompany --tor --tor-port 9150
```

### Export Reports
```bash
python CloudACLCheck_Detector_v9.py mycompany --output report.json --format json
python CloudACLCheck_Detector_v9.py mycompany --output report.txt --format txt
```

---

## 🔍 Workflow

1. **Discovery** – Identify targets
2. **Scanning** – Check access & ACL
3. **Enumeration** – List and categorize files
4. **Audit & Exfiltration** – Risk analysis & file management

---

## 💻 Interactive Menu (v9)

Example:

```
PUBLIC FILE MANAGER (GROUPED)
Found 450 files across categories.

[1] Images
[2] Config & Text
[3] Documents
[4] Backups
[5] Keys

Options:
Download, View, Bulk Download
```

---

## ⚠️ Disclaimer

This tool is for educational and authorized testing only. Unauthorized use is strictly prohibited.

---

## 📝 License

MIT License

---

## 🤝 Contributing

Pull requests are welcome!
