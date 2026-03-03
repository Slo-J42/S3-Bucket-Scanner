
# S3 Bucket Listener / Cloud Asset Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![Type](https://img.shields.io/badge/Type-Red--Team%20Recon-red)
![Focus](https://img.shields.io/badge/Focus-Cloud%20Security-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

A red-team focused cloud reconnaissance tool for identifying publicly exposed storage assets across AWS S3, Google Cloud Storage, and Azure Blob Storage.

Designed strictly for authorized security testing and research.

---

## Overview

Misconfigured cloud storage buckets are one of the most common cloud security risks. 
This tool performs unauthenticated enumeration of cloud storage assets by generating intelligent name permutations and checking public accessibility.

It identifies:
- Publicly listable buckets/containers
- Existing but private buckets
- Exposed file listings
- Potentially sensitive files based on keyword analysis

---

## Features

- Multi-cloud support:
  - AWS S3
  - Google Cloud Storage
  - Azure Blob Storage
- Intelligent bucket name permutation engine
- Unauthenticated public access testing
- XML and JSON response parsing
- Sensitive file keyword detection
- Full file listing for public buckets
- Structured console reporting with risk indicators

---

## Project Structure

S3-Bucket-Listener/

├── S3_bucket_scanner.py

├── LICENSE

└── README.md

---

## Requirements

- Python 3.8+
- requests

Create a requirements.txt file:

requests

Install dependencies:

pip install -r requirements.txt

---

## Usage

Basic scan:

python S3_bucket_scanner.py targetname

Example:

python S3_bucket_scanner.py mycompany

The tool will:
1. Generate bucket/container name permutations.
2. Check AWS, GCP, and Azure storage endpoints.
3. Detect public listable assets.
4. Highlight potentially sensitive exposed files.

---

## Detection Methodology

- Generates common environment-based permutations (dev, prod, backup, logs, data, etc.)
- Sends unauthenticated requests to cloud storage endpoints
- Parses XML/JSON listings when accessible
- Flags sensitive filenames using keyword heuristics
- Reports findings with risk classification

---

## Sample Output

[HIGH RISK] AWS | mycompany-backup  
Status: PUBLIC (Listable)  
Total Files Found: 3  
- database_backup.sql <--- SENSITIVE  
- users.csv <--- SENSITIVE  
- index.html  

---


## Disclaimer

This tool is intended strictly for educational purposes and authorized penetration testing.
Do not scan infrastructure without explicit written permission from the asset owner.
