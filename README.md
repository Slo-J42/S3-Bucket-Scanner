# S3 Bucket Listener / Cloud ACL Check Detector

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![Type](https://img.shields.io/badge/Type-Red--Team%20Recon-red)
![Focus](https://img.shields.io/badge/Focus-Cloud%20Security-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)


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
git clone https://github.com/Slo-J42/S3-Bucket-Scanner.git
cd S3_bucket_scanner
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
python S3_bucket_scanner.py mycompany
```

### Deep Web Discovery
```bash
python S3_bucket_scanner.py https://www.example.com
```

### Subdomain File Audit
```bash
python S3_bucket_scanner.py placeholder --file subdomains.txt
```

### Tor Scanning
```bash
python S3_bucket_scanner.py mycompany --tor
python S3_bucket_scanner.py mycompany --tor --tor-port 9150
```

### Export Reports
```bash
python S3_bucket_scanner.py mycompany --output report.json --format json
python S3_bucket_scanner.py mycompany --output report.txt --format txt
```

---

## 🔍 Workflow

1. **Discovery** – Identify targets
2. **Scanning** – Check access & ACL
3. **Enumeration** – List and categorize files
4. **Audit & Exfiltration** – Risk analysis & file management

---


## 🏗️ Architecture

```
                +----------------------+
                |   Target Input       |
                +----------+-----------+
                           |
            +--------------+--------------+
            | Discovery Engine (OSINT)    |
            | - Permutations             |
            | - Scraping                 |
            | - CNAME Analysis           |
            +--------------+-------------+
                           |
                    +------+------+
                    |   Scanner   |
                    | ACL Checks  |
                    +------+------+
                           |
                 +---------+----------+
                 |  Enumeration       |
                 | File Listing       |
                 +---------+----------+
                           |
               +-----------+------------+
               |  Audit Engine          |
               | Risk Correlation       |
               +-----------+------------+
                           |
               +-----------+------------+
               | Interactive CLI +      |
               | Report Generator       |
               +------------------------+


```

---

## 💻 Interactive Menu (v9)

Once public files are found, the agent provides an interactive CLI to manage data:

Example:

```
================================================================================
PUBLIC FILE MANAGER (GROUPED)
================================================================================
Found 450 files across 5 categories.
Select a category to view files or download.

[1] Images (420 files)
[2] Config & Text (25 files)
[3] Documents (3 files)
[4] Backups & Archives (2 files)
[5] Keys & Certificates (1 file)
[q] Quit

Select Category: 4

--- CATEGORY: Backups & Archives (2 files) ---
Preview:
  [1] db_backup.sql (bucket-name)
  [2] site_backup.zip (bucket-name)

Options:
[d<number>] Download specific file (e.g., d1, d5)
[v<number>] View specific file (e.g., v1, v5)
[A] Download ALL files in this category
[B] Back to Main Menu

Action: A
Download ALL 2 files in 'Backups & Archives'? (y/n): y

```


## 📄 Documentation

For detailed technical specifications, architecture diagrams, and phase breakdowns, please refer to the included documentation:

![Cloud ACL Documentation.docx](https://github.com/Slo-J42/S3-Bucket-Scanner/blob/main/CloudACL_Documentation.docx)



---

## ⚠️ Disclaimer

This tool is for educational and authorized testing only. Unauthorized use is strictly prohibited.

---

## 📝 License

MIT License

---

## 🤝 Contributing

Pull requests are welcome!
