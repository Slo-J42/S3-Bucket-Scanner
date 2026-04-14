import requests
import re
import sys
import os
import xml.etree.ElementTree as ET
import tempfile
import subprocess
import platform
import argparse
import urllib.parse
import datetime
import json

# Check for PySocks
try:
    import socks
except ImportError:
    pass 

SENSITIVE_KEYWORDS = [
    'password', 'secret', 'key', '.pem', '.key', 'private', 
    'credential', 'sql', 'backup', 'dump', 'config', 'env', 
    'database', 'users', 'customer', 'ssn', 'creditcard', '.zip'
]

PERMUTATIONS = [
    '', '-backup', '-backups', '-dev', '-prod', '-staging', '-data',
    '-public', '-assets', '-media', '-logs', '-archive', 'backup',
    'data', 'files', 'uploads', 'static', 'www', 'web'
]

class CloudACLCheck_Detector:
    def __init__(self, target, use_tor=False, tor_port=9050, subdomain_file=None, output_file=None, output_format='txt'):
        self.raw_target = target
        self.subdomain_file = subdomain_file
        self.scan_results = []
        self.downloadable_assets = []
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.output_file = output_file
        self.output_format = output_format
        
        # Configure Proxies
        self.proxies = {
            'http': f'socks5h://127.0.0.1:{self.tor_port}',
            'https': f'socks5h://127.0.0.1:{self.tor_port}'
        } if self.use_tor else None

        self.log(f"Initializing CloudACLCheck_Detector v9...", "INIT")

        if self.use_tor:
            self.log(f"INTERNAL TOR MODE ENABLED (Port: {self.tor_port}). Verifying connection...", "INFO")
            try:
                requests.get('https://check.torproject.org', proxies=self.proxies, timeout=15)
                self.log("Tor connection verified.", "SUCCESS")
            except Exception as e:
                self.log(f"CRITICAL: Tor connection failed.", "ERROR")
                self.log(f"Details: {e}", "ERROR")
                print("-" * 80)
                print("TROUBLESHOOTING TOR:")
                print("1. If using System Tor (Port 9050): Run 'sudo systemctl restart tor'")
                print("2. If using Tor Browser: Try adding '--tor-port 9150' to your command.")
                print("3. Check status: 'sudo systemctl status tor'")
                print("-" * 80)
                sys.exit(1)
        else:
            self.log("STANDARD MODE (No Tor).", "INFO")

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def log(self, message, level="INFO"):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = "[*]"
        if level == "INIT": prefix = "[#]"
        elif level == "SUCCESS": prefix = "[+]"
        elif level == "ERROR": prefix = "[-]"
        elif level == "WARN": prefix = "[!]"
        elif level == "SCAN": prefix = "[>]"
        elif level == "FOUND": prefix = "[+]"

        print(f"[{timestamp}] {prefix} {message}")

    def _make_request(self, url, timeout=5):
        try:
            return requests.get(url, headers=self.headers, proxies=self.proxies, timeout=timeout)
        except Exception:
            return None

    def run_scan(self):
        self.log("="*80, "INFO")
        self.log(f"Target: {self.raw_target if self.raw_target else 'File Input'}", "INIT")
        self.log("Starting Discovery Phase...", "INIT")
        
        buckets_to_scan = set()

        if self.subdomain_file:
            self.log(f"Reading subdomains from file: {self.subdomain_file}", "INFO")
            found_buckets = self.discover_buckets_from_file(self.subdomain_file)
            buckets_to_scan.update(found_buckets)
        
        elif self.raw_target and self.raw_target.startswith("http"):
            self.log("Target is a URL. Starting Deep Discovery...", "INFO")
            found_buckets = self.deep_scrape_domain(self.raw_target)
            buckets_to_scan.update(found_buckets)
            
            if not buckets_to_scan:
                self.log("No links in code. Attempting Auto-Subdomain Guessing...", "WARN")
                guessed_buckets = self.auto_guess_subdomains(self.raw_target)
                buckets_to_scan.update(guessed_buckets)
            
        elif self.raw_target:
            self.log("Target is a Bucket Name. Generating permutations...", "INFO")
            for p in PERMUTATIONS:
                buckets_to_scan.add(f"{self.raw_target}{p}")
                if p: buckets_to_scan.add(f"{p}-{self.raw_target}")

        if not buckets_to_scan:
            self.log("No targets discovered. Exiting.", "ERROR")
            return

        self.log(f"Discovery Complete. {len(buckets_to_scan)} unique targets found.", "SUCCESS")
        self.log("-" * 80, "INFO")
        self.log("Starting ACL Scan Phase...", "INIT")
        
        count = 0
        for bucket in buckets_to_scan:
            count += 1
            self.log(f"Scanning target {count}/{len(buckets_to_scan)}: {bucket}", "SCAN")
            self.check_aws_bucket(bucket)
            self.check_gcp_bucket(bucket)

        self.print_report()
        violations = self.check_iam_audit_rules() 

        if self.downloadable_assets:
            self.interactive_group_menu() # NEW: Grouped Menu
        else:
            self.log("No public files available for download/viewing.", "INFO")
        
        if self.output_file:
            self.export_results(self.output_file, self.output_format, violations)

    # ==========================================
    # NEW: CATEGORIZATION LOGIC
    # ==========================================
    def get_file_category(self, filename):
        """Determines the category of a file based on extension."""
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        
        images = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'ico', 'webp']
        docs = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt']
        backups = ['sql', 'zip', 'tar', 'gz', 'rar', '7z', 'bak', 'backup', 'dump']
        config = ['txt', 'log', 'xml', 'json', 'yaml', 'yml', 'ini', 'conf', 'env', 'sh']
        keys = ['pem', 'key', 'crt', 'p12', 'pfx', 'der']

        if ext in images: return "Images"
        if ext in docs: return "Documents"
        if ext in backups: return "Backups & Archives"
        if ext in config: return "Config & Text"
        if ext in keys: return "Keys & Certificates"
        
        return "Other"

    def group_assets(self):
        """Groups the downloadable assets into categories."""
        groups = {}
        for asset in self.downloadable_assets:
            cat = self.get_file_category(asset['file'])
            if cat not in groups:
                groups[cat] = []
            groups[cat].append(asset)
        return groups

    # ==========================================
    # NEW: GROUPED INTERACTIVE MENU
    # ==========================================
    def interactive_group_menu(self):
        print("\n" + "="*80)
        print("PUBLIC FILE MANAGER (GROUPED)")
        print("="*80)
        
        grouped = self.group_assets()
        total_files = len(self.downloadable_assets)
        
        print(f"Found {total_files} files across {len(grouped)} categories.")
        print("Select a category to view files or download.\n")

        # Create a sorted list of keys for consistent display
        sorted_categories = sorted(grouped.keys())
        category_map = {str(i+1): cat for i, cat in enumerate(sorted_categories)}

        for i, cat in enumerate(sorted_categories):
            count = len(grouped[cat])
            print(f"[{i+1}] {cat} ({count} file{'s' if count != 1 else ''})")
        
        print("[q] Quit")
        
        while True:
            choice = input("\nSelect Category: ").strip().lower()
            
            if choice == 'q':
                break
            
            if choice in category_map:
                selected_cat = category_map[choice]
                self.handle_group_interaction(selected_cat, grouped[selected_cat])
            else:
                print("Invalid option.")

    def handle_group_interaction(self, category_name, assets):
        """Handles actions for a specific group of files."""
        while True:
            print(f"\n--- CATEGORY: {category_name} ({len(assets)} files) ---")
            
            # Show first 10 files as preview
            print("Preview:")
            for i, asset in enumerate(assets[:10]):
                print(f"  [{i+1}] {asset['file']} ({asset['bucket']})")
            
            if len(assets) > 10:
                print(f"  ... and {len(assets) - 10} more files.")
            
            print("\nOptions:")
            print(f"[d<number>] Download specific file (e.g., d1, d5)")
            print(f"[v<number>] View specific file (e.g., v1, v5)")
            print("[A] Download ALL files in this category")
            print("[B] Back to Main Menu")
            
            action = input("Action: ").strip().lower()
            
            if action == 'b':
                break
            elif action == 'a':
                confirm = input(f"Download ALL {len(assets)} files in '{category_name}'? (y/n): ").lower()
                if confirm == 'y':
                    self.download_group(assets)
            elif action.startswith('d'):
                try:
                    idx = int(action[1:]) - 1
                    if 0 <= idx < len(assets):
                        self.download_file(assets[idx])
                    else:
                        print("Index out of range.")
                except:
                    print("Invalid format.")
            elif action.startswith('v'):
                try:
                    idx = int(action[1:]) - 1
                    if 0 <= idx < len(assets):
                        self.view_file_content(assets[idx])
                    else:
                        print("Index out of range.")
                except:
                    print("Invalid format.")

    def download_group(self, assets):
        """Downloads a list of assets."""
        self.log(f"Starting bulk download for {len(assets)} files...", "INIT")
        success_count = 0
        for asset in assets:
            try:
                # We call the internal logic directly but adapted for bulk (less chat)
                safe_filename = os.path.basename(asset['file'])
                # Add bucket prefix to avoid filename collision in bulk download
                safe_filename = f"{asset['bucket']}_{safe_filename}" 
                
                base, ext = os.path.splitext(safe_filename)
                c = 1
                while os.path.exists(safe_filename):
                    safe_filename = f"{base}_{c}{ext}"; c+=1
                
                resp = requests.get(asset['url'], headers=self.headers, proxies=self.proxies, stream=True, timeout=10)
                if resp.status_code == 200:
                    with open(safe_filename, 'wb') as f:
                        for chunk in resp.iter_content(chunk_size=8192): f.write(chunk)
                    print(f"  [+] Downloaded: {safe_filename}")
                    success_count += 1
                else:
                    print(f"  [-] Failed: {asset['file']} (HTTP {resp.status_code})")
            except Exception as e:
                print(f"  [-] Error: {asset['file']} ({e})")
        
        self.log(f"Bulk Download Complete: {success_count}/{len(assets)} files saved.", "SUCCESS")

    # ==========================================
    # EXISTING FUNCTIONS (Discovery, Scanning, Utils)
    # ==========================================
    
    def export_results(self, filename, format_type, violations):
        self.log(f"Exporting report to {filename} ({format_type.upper()})...", "INIT")
        try:
            if format_type.lower() == 'json':
                data = {
                    "scan_metadata": {
                        "target": self.raw_target if self.raw_target else "File Input",
                        "timestamp": str(datetime.datetime.now()),
                        "tor_used": self.use_tor
                    },
                    "summary": {
                        "total_buckets_scanned": len(self.scan_results),
                        "public_buckets": sum(1 for r in self.scan_results if 'PUBLIC' in r['status']),
                        "sensitive_files_found": sum(r['sensitive_count'] for r in self.scan_results),
                        "total_violations": len(violations)
                    },
                    "violations": violations,
                    "buckets": self.scan_results,
                    "public_assets": self.downloadable_assets
                }
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=4)
                self.log(f"Successfully saved JSON report to {filename}", "SUCCESS")
            elif format_type.lower() == 'txt':
                with open(filename, 'w') as f:
                    f.write("=" * 80 + "\n")
                    f.write(f"CLOUD ACL SCAN REPORT: {self.raw_target if self.raw_target else 'File Input'}\n")
                    f.write(f"Generated: {datetime.datetime.now()}\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"SUMMARY:\nTotal Buckets Scanned: {len(self.scan_results)}\nPublic Buckets Found: {sum(1 for r in self.scan_results if 'PUBLIC' in r['status'])}\nTotal Sensitive Files: {sum(r['sensitive_count'] for r in self.scan_results)}\n")
                    f.write("\n" + "-" * 80 + "\n\n")
                    if violations:
                        f.write("VIOLATIONS:\n")
                        for v in violations: f.write(f"[{v['severity']}] {v['rule']}\n  Resource: {v['resource']}\n  Detail: {v['detail']}\n\n")
                    f.write("\n" + "=" * 80 + "\nDETAILED BUCKET REPORT:\n" + "=" * 80 + "\n")
                    for r in self.scan_results:
                        status_marker = "[HIGH RISK]" if "PUBLIC" in r['status'] else "[INFO]"
                        f.write(f"\n{status_marker} {r['provider']} | {r['name']}\n    Status:   {r['status']}\n    ACL Info: {r.get('acl_status', 'N/A')}\n")
                        if "PUBLIC" in r['status']:
                            f.write(f"    Files:    {len(r['files'])}\n")
                            if r['sensitive_count'] > 0:
                                f.write(f"    (!) Sensitive Files: {r['sensitive_count']}\n")
                                for sf in r['sensitive_files']: f.write(f"       - {sf}\n")
                    f.write("\n\n" + "=" * 80 + "\nPUBLIC ASSETS (FILES):\n" + "=" * 80 + "\n")
                    for asset in self.downloadable_assets: f.write(f"{asset['provider']} | {asset['bucket']}/{asset['file']}\nURL: {asset['url']}\n\n")
                self.log(f"Successfully saved TXT report to {filename}", "SUCCESS")
        except Exception as e:
            self.log(f"Failed to save report: {e}", "ERROR")

    def deep_scrape_domain(self, url):
        found = set()
        try:
            self.log(f"Fetching HTML: {url}", "SCAN")
            resp = self._make_request(url, timeout=10)
            if resp and resp.status_code == 200:
                html_content = resp.text
                found.update(self._extract_cloud_urls(html_content))
                js_links = re.findall(r'src=[\'"](.*?\.js)[\'"]', html_content)
                base_url = f"{resp.scheme}://{resp.netloc}"
                absolute_js_links = list(set([urllib.parse.urljoin(base_url, link) for link in js_links]))
                self.log(f"Found {len(absolute_js_links)} JS files. Analyzing...", "SCAN")
                for js_url in absolute_js_links:
                    self.log(f"   Reading JS: {js_url.split('/')[-1]}", "SCAN")
                    try:
                        js_resp = self._make_request(js_url, timeout=5)
                        if js_resp and js_resp.status_code == 200:
                            js_content = js_resp.text
                            found.update(self._extract_cloud_urls(js_content))
                    except: pass
        except Exception as e: self.log(f"Error scraping {url}: {e}", "ERROR")
        return found

    def _extract_cloud_urls(self, text_content):
        found = set()
        patterns = [r'https?://([a-z0-9\.\-]+)\.s3\.amazonaws\.com', r'https?://([a-z0-9\.\-]+)\.s3-website[-.](?:[a-z0-9\-]+)\.amazonaws\.com', r'https?://([a-z0-9\.\-]+)\.cloudfront\.net', r'https?://storage\.googleapis\.com/([a-z0-9\.\-]+)']
        for p in patterns:
            for m in re.findall(p, text_content): found.add(m)
        return found

    def auto_guess_subdomains(self, url):
        found = set()
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        prefixes = ['static', 'cdn', 'assets', 'media', 'img', 'images', 'files', 'data', 'content', 's3', 'storage', 'buckets', 'downloads']
        self.log(f"Guessing subdomains for {domain}...", "SCAN")
        for prefix in prefixes:
            guess = f"{prefix}.{domain}"
            self.log(f"   Checking guess: {guess}", "SCAN")
            target_url = f"http://{guess}"
            try:
                resp = requests.head(target_url, headers=self.headers, proxies=self.proxies, timeout=2, allow_redirects=True)
                server = resp.headers.get('Server', '').lower()
                if 'amazon' in server or 's3' in server:
                    self.log(f"   HIT (Header): {guess}", "FOUND")
                    found.add(guess)
                    continue
                resp_get = self._make_request(target_url, timeout=2)
                if resp_get and ('ListBucketResult' in resp_get.text or 'x-amz' in resp_get.text):
                    self.log(f"   HIT (Body): {guess}", "FOUND")
                    found.add(guess)
            except: pass
        return found

    def discover_buckets_from_file(self, filepath):
        found_buckets = set()
        try:
            with open(filepath, 'r') as f: subs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"File not found: {filepath}", "ERROR")
            return set()
        self.log(f"Processing {len(subs)} subdomains from file...", "SCAN")
        for sub in subs:
            self.log(f"Checking subdomain: {sub}", "SCAN")
            if sub.startswith("http"): sub = urllib.parse.urlparse(sub).netloc
            target_url = f"http://{sub}"
            try:
                resp = requests.head(target_url, headers=self.headers, proxies=self.proxies, timeout=3, allow_redirects=True)
                server = resp.headers.get('Server', '').lower()
                if 'amazon' in server or 's3' in server:
                    self.log(f"   -> FOUND (Via Header): {sub}", "FOUND")
                    found_buckets.add(sub)
                    continue
                resp_get = self._make_request(target_url, timeout=3)
                if resp_get and 'ListBucketResult' in resp_get.text:
                    self.log(f"   -> FOUND (Via XML): {sub}", "FOUND")
                    found_buckets.add(sub)
            except Exception: pass
        return found_buckets

    def check_aws_bucket(self, target_input):
        is_virtual_host = False
        bucket_name = target_input
        if target_input.startswith("http"):
            parsed = urllib.parse.urlparse(target_input)
            bucket_name = parsed.netloc
            is_virtual_host = True
        elif "." in target_input and ".s3.amazonaws.com" not in target_input:
            is_virtual_host = True
        url = ""
        display_name = bucket_name
        if is_virtual_host: url = f"https://{bucket_name}/"
        else: url = f"https://{bucket_name}.s3.amazonaws.com/"; display_name = bucket_name
        resp = self._make_request(url)
        if resp and resp.status_code == 200:
            self.log(f"   -> AWS S3: {display_name} is PUBLIC", "FOUND")
            files = self._parse_s3_xml(resp.text)
            sensitive = self._find_sensitive_files(files)
            acl_status = "ACL Check Skipped (Virtual Host)"
            if not is_virtual_host: acl_status = self.check_aws_acl(bucket_name)
            else: acl_status = "PUBLIC (Virtual Host Access)"
            result = {'provider': 'AWS', 'name': display_name, 'status': 'PUBLIC (Listable)', 'acl_status': acl_status, 'files': files, 'sensitive_count': len(sensitive), 'sensitive_files': sensitive}
            self.scan_results.append(result)
            for f in files:
                dl_url = f"{url}{f}"
                self.downloadable_assets.append({'provider': 'AWS', 'bucket': display_name, 'file': f, 'url': dl_url})
        elif resp and resp.status_code == 403:
            self.log(f"   -> AWS S3: {display_name} is PRIVATE (403)", "INFO")
            acl_status = "ACL Check Failed/Inaccessible"
            if not is_virtual_host: acl_status = self.check_aws_acl(bucket_name)
            else: acl_status = "Private (Virtual Host)"
            self.scan_results.append({'provider': 'AWS', 'name': display_name, 'status': 'PRIVATE (Forbidden)', 'acl_status': acl_status, 'files': [], 'sensitive_count': 0, 'sensitive_files': []})

    def check_aws_acl(self, bucket_name):
        acl_url = f"https://{bucket_name}.s3.amazonaws.com/?acl"
        resp = self._make_request(acl_url)
        if resp and resp.status_code == 200:
            xml_content = resp.text.lower()
            if "http://acs.amazonaws.com/groups/global/AllUsers".lower() in xml_content: return "CRITICAL: Public Access (AllUsers) granted in ACL"
            elif "http://acs.amazonaws.com/groups/global/AuthenticatedUsers".lower() in xml_content: return "WARNING: Authenticated Users granted in ACL"
            else: return "No obvious public ACL grants found via ?acl"
        return "ACL Check Failed/Inaccessible"

    def check_gcp_bucket(self, bucket_name):
        url = f"https://storage.googleapis.com/{bucket_name}/"
        resp = self._make_request(url)
        if resp and resp.status_code == 200:
            self.log(f"   -> GCP Storage: {bucket_name} is PUBLIC", "FOUND")
            files = self._parse_gcp_json(resp.text)
            sensitive = self._find_sensitive_files(files)
            acl_status = self.check_gcp_acl(bucket_name)
            result = {'provider': 'GCP', 'name': bucket_name, 'status': 'PUBLIC (Listable)', 'acl_status': acl_status, 'files': files, 'sensitive_count': len(sensitive), 'sensitive_files': sensitive}
            self.scan_results.append(result)
            for f in files:
                self.downloadable_assets.append({'provider': 'GCP', 'bucket': bucket_name, 'file': f, 'url': f"https://storage.googleapis.com/{bucket_name}/{f}"})

    def check_gcp_acl(self, bucket_name):
        acl_url = f"https://storage.googleapis.com/{bucket_name}/?acl"
        resp = self._make_request(acl_url)
        if resp and resp.status_code == 200:
            content = resp.text.lower()
            if 'allusers' in content: return "CRITICAL: allUsers granted in ACL"
            elif 'allauthenticatedusers' in content: return "WARNING: allAuthenticatedUsers granted in ACL"
        return "Could not verify ACL"

    def _parse_s3_xml(self, xml_text): return re.compile(r'<Key>(.*?)</Key>').findall(xml_text)
    def _parse_gcp_json(self, json_text):
        try: import json; return [item['name'] for item in json.loads(json_text).get('items', [])]
        except: return []
    def _find_sensitive_files(self, file_list): return [f for f in file_list if self._is_sensitive(f)]
    def _is_sensitive(self, filename): return any(k in filename.lower() for k in SENSITIVE_KEYWORDS)

    def check_iam_audit_rules(self):
        self.log("Running IAM Audit Rules...", "INIT")
        violations = []
        for r in self.scan_results:
            if "PUBLIC" in r['status']: violations.append({'rule': 'STORAGE_PUBLIC_READ', 'severity': 'HIGH', 'resource': f"{r['provider']}://{r['name']}", 'detail': 'Bucket allows unauthenticated listing.'})
            if r['sensitive_count'] > 0: violations.append({'rule': 'DATA_EXPOSURE', 'severity': 'CRITICAL', 'resource': f"{r['provider']}://{r['name']}", 'detail': f'Bucket contains {r["sensitive_count"]} sensitive files.'})
            if "CRITICAL" in r.get('acl_status', ''): violations.append({'rule': 'ACL_OVER_PERMISSIVE', 'severity': 'HIGH', 'resource': f"{r['provider']}://{r['name']}", 'detail': r['acl_status']})
        if not violations: self.log("No critical IAM audit violations found.", "SUCCESS")
        else:
            self.log(f"AUDIT REPORT: {len(violations)} Violations Found", "WARN")
            print("=" * 80)
            for v in violations: print(f"[{v['severity']}] Rule: {v['rule']}\n    Resource: {v['resource']}\n    Detail:   {v['detail']}\n" + "-" * 80)
        return violations

    # Single file handlers (reused)
    def handle_file_action(self, asset):
        print(f"\nSelected: {asset['file']} from {asset['provider']} bucket '{asset['bucket']}'")
        print("[1] View Content (Text Preview or Open Image/PDF)")
        print("[2] Download File (Anonymized)")
        print("[3] Back")
        action = input("Choose action: ").strip()
        if action == '1': self.view_file_content(asset)
        elif action == '2': self.download_file(asset)

    def view_file_content(self, asset):
        self.log(f"Viewing file: {asset['file']}", "SCAN")
        try:
            with requests.get(asset['url'], headers=self.headers, proxies=self.proxies, stream=True) as r:
                if r.status_code == 200:
                    content_type = r.headers.get('Content-Type', '').lower()
                    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.basename(asset['file'])) as tmp_file:
                        for chunk in r.iter_content(chunk_size=8192): tmp_file.write(chunk)
                        tmp_path = tmp_file.name
                    if 'text' in content_type or 'json' in content_type or 'xml' in content_type:
                        try:
                            with open(tmp_path, 'r', encoding='utf-8') as f:
                                text = f.read()
                                print("-" * 40); print(text[:500]); 
                                if len(text) > 500: print("\n... (truncated)")
                                print("-" * 40)
                        except: print("[!] Binary file.")
                    elif 'image' in content_type or 'pdf' in content_type:
                        self.log(f"Opening {content_type}...", "INFO")
                        if platform.system() == "Linux": subprocess.run(['xdg-open', tmp_path])
                        elif platform.system() == "Windows": os.startfile(tmp_path)
                        self.log("File opened.", "SUCCESS")
                    else: print(f"[!] Unknown type {content_type}.")
                else: print(f"[!] Failed HTTP {r.status_code}")
        except Exception as e: print(f"[!] Error: {e}")

    def download_file(self, asset):
        self.log(f"Downloading: {asset['file']}", "SCAN")
        safe_filename = os.path.basename(asset['file']) or "downloaded_file"
        base, ext = os.path.splitext(safe_filename)
        c = 1
        while os.path.exists(safe_filename):
            safe_filename = f"{base}_{c}{ext}"; c+=1
        try:
            resp = requests.get(asset['url'], headers=self.headers, proxies=self.proxies, stream=True, timeout=10)
            if resp.status_code == 200:
                with open(safe_filename, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=8192): f.write(chunk)
                self.log(f"Saved to: {safe_filename}", "SUCCESS")
        except Exception as e: self.log(f"Download Error: {e}", "ERROR")

    def print_report(self):
        self.log("Generating Final Report...", "INIT")
        print(f"\n{'='*80}\nCLOUD ACL SCAN REPORT\n{'='*80}")
        for r in self.scan_results:
            risk = "HIGH RISK" if "PUBLIC" in r['status'] else "INFO"
            print(f"\n[{risk}] {r['provider']} | {r['name']}\n    Status: {r['status']}\n    ACL: {r.get('acl_status')}")
            if "PUBLIC" in r['status']:
                print(f"    Files:    {len(r['files'])}")
                if r['sensitive_count'] > 0:
                    print(f"    (!) Sensitive: {r['sensitive_count']}")
                    for sf in r['sensitive_files']: print(f"       - {sf}")
        print(f"\n{'='*80}\nSUMMARY:\nTotal Public: {sum(1 for r in self.scan_results if 'PUBLIC' in r['status'])}\nTotal Sensitive: {sum(r['sensitive_count'] for r in self.scan_results)}\n{'='*80}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudACLCheck Detector Agent v9")
    parser.add_argument("target", help="Target: Bucket Name, Website URL (https://...), or placeholder if using --file", nargs='?')
    parser.add_argument("--file", help="Path to a text file containing subdomains to scan", default=None)
    parser.add_argument("--tor", action="store_true", help="Enable internal Tor routing")
    parser.add_argument("--tor-port", type=int, default=9050, help="Tor SOCKS5 Port (Default: 9050, Tor Browser: 9150)")
    parser.add_argument("--output", help="Filename to save the report (e.g. report.txt or report.json)", default=None)
    parser.add_argument("--format", choices=['txt', 'json'], default='txt', help="Output format for the report (Default: txt)")
    
    args = parser.parse_args()

    if not args.target and not args.file:
        print("Usage: python script.py <target_name_or_url> [--output report.json] [--format json]")
        print("   OR: python script.py --file <subs.txt> [--tor]")
        sys.exit(1)

    agent = CloudACLCheck_Detector(args.target, use_tor=args.tor, tor_port=args.tor_port, subdomain_file=args.file, output_file=args.output, output_format=args.format)
    agent.run_scan()
