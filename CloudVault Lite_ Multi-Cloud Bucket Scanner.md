# CloudVault Lite: Multi-Cloud Bucket Scanner

**Author**: Manus AI

## Overview

**CloudVault Lite** is a lightweight, asynchronous Python tool designed for security professionals and developers to quickly identify misconfigured, publicly accessible cloud storage buckets across major cloud providers. It focuses on discovering "open" buckets, detecting sensitive files, and checking for overly permissive Cross-Origin Resource Sharing (CORS) policies.

This tool is intended for **defensive security auditing** and **educational purposes** only. Unauthorized access to computer systems is illegal and unethical.

## Features

| Feature | Description | Supported Providers |
| :--- | :--- | :--- |
| **Multi-Cloud Scan** | Scans for buckets/containers across three major cloud platforms. | AWS S3, GCP Cloud Storage, Azure Blob Storage |
| **Asynchronous Speed** | Uses `asyncio` and `aiohttp` for high-speed, concurrent scanning. | All |
| **Sensitive File Check** | Automatically checks for common sensitive files like `.env`, `id_rsa`, and `credentials`. | AWS S3, GCP Cloud Storage |
| **CORS Check** | Detects overly permissive CORS policies (e.g., `Access-Control-Allow-Origin: *`). | AWS S3 |
| **Keyword Enumeration** | Generates common bucket name permutations based on a single keyword (e.g., company name). | All |

## Installation

CloudVault Lite requires Python 3.8+ and the following dependencies:

\`\`\`bash
# Navigate to the project directory
cd /home/ubuntu/cloudvault_lite

# Install dependencies
sudo pip3 install aiohttp colorama
\`\`\`

## Usage

The tool is executed via the command line, requiring a single keyword (e.g., a company name or project name) to begin the enumeration and scanning process.

\`\`\`bash
python3 scanner.py <keyword>
\`\`\`

### Example

To scan for buckets related to the keyword "manus":

\`\`\`bash
python3 scanner.py manus
\`\`\`

### Output Interpretation

The tool will print results in real-time.

| Output Indicator | Meaning |
| :--- | :--- |
| \`[+] Found Open ...\` | A publicly accessible bucket or container was discovered. |
| \`[!] Sensitive Files Found\` | One or more sensitive files (e.g., `.env`, `id_rsa`) were found in the bucket. **Immediate investigation is required.** |
| \`[!] Permissive CORS detected!\` | The bucket's CORS policy allows access from any origin (\`*\`). |
| \`[-] No open buckets found ...\` | No publicly accessible buckets were found for the given keyword and permutations. |

## Technical Details

### Sensitive Files Checked

The scanner attempts to access the following files within discovered buckets:

- \`.env\`
- \`.key\`
- \`id_rsa\`
- \`credentials\`
- \`backup.sql\`
- \`config.json\`
- \`settings.py\`
- \`.git/config\`
- \`web.config\`

### Bucket Name Permutations

The tool uses the following patterns to generate potential bucket names from the input keyword:

- \`{keyword}\`
- \`{keyword}-backup\`, \`{keyword}-dev\`, \`{keyword}-prod\`, \`{keyword}-test\`, \`{keyword}-data\`, \`{keyword}-public\`, \`{keyword}-private\`, \`{keyword}-internal\`, \`{keyword}-staging\`, \`{keyword}-assets\`, \`{keyword}-logs\`
- \`{keyword}backup\`, \`{keyword}dev\`, \`{keyword}prod\`, \`{keyword}test\`, \`{keyword}data\`, \`{keyword}public\`, \`{keyword}assets\`, \`{keyword}logs\`

### Provider Check Logic

- **AWS S3 & GCP GCS**: A successful HTTP GET request (status 200) to the bucket's URL indicates public read access.
- **Azure Blob Storage**: A successful HTTP GET request (status 200) to a common container URL with the \`restype=container&comp=list\` query parameter indicates public access. Due to Azure's structure, the tool focuses on enumerating common container names within the storage account.
