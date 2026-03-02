import requests
import re
import sys

# Keywords that flag a file as sensitive
SENSITIVE_KEYWORDS = [
    'password', 'secret', 'key', '.pem', '.key', 'private', 
    'credential', 'sql', 'backup', 'dump', 'config', 'env', 
    'database', 'users', 'customer', 'ssn', 'creditcard', '.zip'
]

# Common suffixes to append to the target name for guessing
PERMUTATIONS = [
    '', '-backup', '-backups', '-dev', '-prod', '-staging', '-data',
    '-public', '-assets', '-media', '-logs', '-archive', 'backup',
    'data', 'files', 'uploads', 'static', 'www', 'web'
]

class CloudAssetScannerNoAuth:
    def __init__(self, target_name):
        self.target_name = target_name
        self.results = []
        # User-Agent to look like a browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def run_scan(self):
        print(f"[*] Starting Unauthenticated Scan for target: {self.target_name}")
        print(f"[*] Generating name permutations and checking public availability...")
        print("-" * 80)
        
        # Generate list of names to check
        names_to_check = []
        for p in PERMUTATIONS:
            names_to_check.append(f"{self.target_name}{p}")
            if p: 
                names_to_check.append(f"{p}-{self.target_name}")

        # Remove duplicates
        names_to_check = list(set(names_to_check))

        for name in names_to_check:
            self.check_aws_bucket(name)
            self.check_gcp_bucket(name)
            self.check_azure_container(name)

        self.print_report()

    def check_aws_bucket(self, bucket_name):
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        try:
            resp = requests.get(url, headers=self.headers, timeout=5)
            
            if resp.status_code == 200:
                files = self._parse_s3_xml(resp.text)
                sensitive = self._find_sensitive_files(files)
                
                self.results.append({
                    'provider': 'AWS',
                    'name': bucket_name,
                    'status': 'PUBLIC (Listable)',
                    'all_files': files,           # CHANGED: Storing all files
                    'sensitive_count': len(sensitive),
                    'sensitive_files': sensitive
                })
            elif resp.status_code == 403:
                self.results.append({
                    'provider': 'AWS',
                    'name': bucket_name,
                    'status': 'EXISTS (Private/Forbidden)',
                    'all_files': [],              # No files visible
                    'sensitive_count': 0,
                    'sensitive_files': []
                })
        except requests.exceptions.RequestException:
            pass

    def check_gcp_bucket(self, bucket_name):
        url = f"https://storage.googleapis.com/{bucket_name}/"
        try:
            resp = requests.get(url, headers=self.headers, timeout=5)
            
            if resp.status_code == 200:
                files = self._parse_gcp_json(resp.text)
                sensitive = self._find_sensitive_files(files)
                
                self.results.append({
                    'provider': 'GCP',
                    'name': bucket_name,
                    'status': 'PUBLIC (Listable)',
                    'all_files': files,           # CHANGED: Storing all files
                    'sensitive_count': len(sensitive),
                    'sensitive_files': sensitive
                })
            elif resp.status_code == 403:
                self.results.append({
                    'provider': 'GCP',
                    'name': bucket_name,
                    'status': 'EXISTS (Private/Forbidden)',
                    'all_files': [],              # No files visible
                    'sensitive_count': 0,
                    'sensitive_files': []
                })
        except requests.exceptions.RequestException:
            pass

    def check_azure_container(self, container_name):
        url = f"https://{self.target_name}.blob.core.windows.net/{container_name}/"
        try:
            resp = requests.get(url, headers=self.headers, timeout=5)
            
            if resp.status_code == 200:
                files = self._parse_azure_xml(resp.text)
                sensitive = self._find_sensitive_files(files)
                
                self.results.append({
                    'provider': 'Azure',
                    'name': f"{self.target_name}/{container_name}",
                    'status': 'PUBLIC (Listable)',
                    'all_files': files,           # CHANGED: Storing all files
                    'sensitive_count': len(sensitive),
                    'sensitive_files': sensitive
                })
            # Note: Azure 403/404 is ambiguous, skipping to reduce noise
        except requests.exceptions.RequestException:
            pass

    # ==========================================
    # PARSING HELPERS
    # ==========================================
    def _parse_s3_xml(self, xml_text):
        pattern = re.compile(r'<Key>(.*?)</Key>')
        return pattern.findall(xml_text)

    def _parse_gcp_json(self, json_text):
        try:
            import json
            data = json.loads(json_text)
            return [item['name'] for item in data.get('items', [])]
        except:
            return []

    def _parse_azure_xml(self, xml_text):
        pattern = re.compile(r'<Name>(.*?)</Name>')
        return pattern.findall(xml_text)

    def _find_sensitive_files(self, file_list):
        found = []
        for f in file_list:
            if self._is_sensitive(f):
                found.append(f)
        return found

    def _is_sensitive(self, filename):
        f_low = filename.lower()
        for k in SENSITIVE_KEYWORDS:
            if k in f_low:
                return True
        return False

    # ==========================================
    # REPORTING
    # ==========================================
    def print_report(self):
        print(f"\n{'='*80}")
        print(f"SCAN REPORT FOR TARGET: {self.target_name}")
        print(f"{'='*80}")
        
        public_count = 0
        total_sensitive = 0
        
        for r in self.results:
            status = r['status']
            risk = "INFO"
            if "PUBLIC" in status:
                risk = "HIGH RISK"
                public_count += 1
            
            print(f"\n[{risk}] {r['provider']} | {r['name']}")
            print(f"    Status: {status}")
            
            # NEW LOGIC: If public, list ALL files
            if "PUBLIC" in status:
                print(f"    Total Files Found: {len(r['all_files'])}")
                if len(r['all_files']) > 0:
                    for f in r['all_files']:
                        # Add visual marker if sensitive
                        marker = " <--- SENSITIVE" if self._is_sensitive(f) else ""
                        print(f"       - {f}{marker}")
                else:
                    print("       (Bucket is empty)")
        
        print(f"\n{'='*80}")
        print(f"SUMMARY:")
        print(f"Total Public Assets Found: {public_count}")
        print(f"Total Sensitive Files Exposed: {total_sensitive}")
        print(f"{'='*80}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cloud_asset_scan.py <target_name>")
        print("Example: python cloud_asset_scan.py mycompany")
        sys.exit(1)

    target = sys.argv[1]
    scanner = CloudAssetScannerNoAuth(target)
    scanner.run_scan()
