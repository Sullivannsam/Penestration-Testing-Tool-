#!/usr/bin/env python3
"""
Advanced Security Assessment Framework (ASAF)
Professional penetration testing tool for authorized security assessments
Version: 2.1.0
Author: Security Research Team
License: For authorized testing only
"""

import requests
import sys
import time
import json
import hashlib
import random
import string
import re
import urllib.parse
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import logging
import warnings
warnings.filterwarnings('ignore')

# Disable SSL warnings for development
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONFIGURATION ====================
@dataclass
class Config:
    """Configuration for security assessment"""
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0'
    ]
    
    REQUEST_DELAY = 0.5  # Delay between requests
    TIMEOUT = 10  # Request timeout in seconds
    MAX_THREADS = 5  # Maximum concurrent threads
    REPORT_FORMAT = 'json'  # json, html, txt

# ==================== LOGGING ====================
class CustomLogger:
    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_assessment.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def info(self, message):
        self.logger.info(f"[*] {message}")
    
    def warning(self, message):
        self.logger.warning(f"[!] {message}")
    
    def error(self, message):
        self.logger.error(f"[-] {message}")
    
    def success(self, message):
        self.logger.info(f"[+] {message}")

logger = CustomLogger()

# ==================== SECURITY HEADERS ====================
class SecurityHeadersScanner:
    """Scan for missing security headers"""
    
    ESSENTIAL_HEADERS = {
        'Strict-Transport-Security': 'Protects against SSL stripping',
        'Content-Security-Policy': 'Prevents XSS attacks',
        'X-Frame-Options': 'Prevents clickjacking',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'Referrer-Policy': 'Controls referrer information',
        'Permissions-Policy': 'Controls browser features'
    }
    
    @staticmethod
    def scan(url: str) -> Dict:
        """Scan for security headers"""
        try:
            response = requests.get(url, timeout=Config.TIMEOUT, verify=False)
            headers = response.headers
            
            results = {
                'url': url,
                'missing_headers': [],
                'present_headers': [],
                'recommendations': []
            }
            
            for header, description in SecurityHeadersScanner.ESSENTIAL_HEADERS.items():
                if header in headers:
                    results['present_headers'].append({
                        'header': header,
                        'value': headers[header],
                        'description': description
                    })
                else:
                    results['missing_headers'].append({
                        'header': header,
                        'description': description,
                        'severity': 'medium'
                    })
                    results['recommendations'].append(f"Add {header} header: {description}")
            
            return results
        except Exception as e:
            logger.error(f"Header scan failed: {e}")
            return {}

# ==================== ADVANCED SQLI DETECTION ====================
class AdvancedSQLiDetector:
    """Advanced SQL injection detection with multiple techniques"""
    
    PAYLOADS = {
        'boolean_based': [
            "' OR '1'='1'--",
            "' OR 1=1--",
            "admin' OR 1=1--",
            "' OR EXISTS(SELECT * FROM users)--",
            "' AND SUBSTRING(@@version,1,1)='5'--"
        ],
        'time_based': [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ],
        'error_based': [
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "' AND 1=(SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ]
    }
    
    @staticmethod
    def detect(url: str, param: str = 'id') -> Dict:
        """Detect SQL injection vulnerabilities"""
        results = {
            'vulnerable': False,
            'technique': None,
            'payload': None,
            'confidence': 0
        }
        
        test_url = f"{url}?{param}=test"
        
        # Boolean-based detection
        logger.info("Testing boolean-based SQLi...")
        for payload in AdvancedSQLiDetector.PAYLOADS['boolean_based']:
            try:
                test_payload = test_url.replace('test', payload)
                response = requests.get(test_payload, timeout=Config.TIMEOUT)
                
                # Check for differences
                baseline = requests.get(f"{url}?{param}=baseline", timeout=Config.TIMEOUT)
                
                if len(response.content) != len(baseline.content):
                    results.update({
                        'vulnerable': True,
                        'technique': 'boolean_based',
                        'payload': payload,
                        'confidence': 85
                    })
                    logger.success(f"Boolean-based SQLi detected: {payload}")
                    return results
            except:
                continue
        
        # Time-based detection
        logger.info("Testing time-based SQLi...")
        for payload in AdvancedSQLiDetector.PAYLOADS['time_based']:
            try:
                start_time = time.time()
                test_payload = test_url.replace('test', payload)
                requests.get(test_payload, timeout=Config.TIMEOUT + 5)
                elapsed = time.time() - start_time
                
                if elapsed >= 5:
                    results.update({
                        'vulnerable': True,
                        'technique': 'time_based',
                        'payload': payload,
                        'confidence': 95
                    })
                    logger.success(f"Time-based SQLi detected: {payload}")
                    return results
            except:
                continue
        
        return results

# ==================== XSS DETECTOR ====================
class XSSDetector:
    """Advanced XSS detection with context awareness"""
    
    PAYLOADS = {
        'basic': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
        'event_handlers': [
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src=javascript:alert(1)>'
        ],
        'encoded': [
            '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
            'javascript:alert(1)',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
        ],
        'polyglot': [
            'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e'
        ]
    }
    
    @staticmethod
    def detect(url: str, param: str = 'q') -> Dict:
        """Detect XSS vulnerabilities"""
        results = {
            'vulnerable': False,
            'payloads': [],
            'context': None
        }
        
        test_url = f"{url}?{param}="
        
        for category, payload_list in XSSDetector.PAYLOADS.items():
            for payload in payload_list:
                try:
                    full_url = test_url + urllib.parse.quote(payload)
                    response = requests.get(full_url, timeout=Config.TIMEOUT)
                    
                    # Check if payload appears in response (reflected XSS)
                    if payload in response.text or urllib.parse.unquote(payload) in response.text:
                        results['vulnerable'] = True
                        results['payloads'].append({
                            'category': category,
                            'payload': payload,
                            'type': 'reflected'
                        })
                        logger.success(f"Reflected XSS detected: {payload}")
                    
                    # Check for DOM-based XSS indicators
                    if 'document.write' in response.text or 'innerHTML' in response.text:
                        if payload in response.text:
                            results['payloads'].append({
                                'category': category,
                                'payload': payload,
                                'type': 'dom_based'
                            })
                            logger.success(f"Potential DOM-based XSS: {payload}")
                    
                except Exception as e:
                    continue
        
        return results

# ==================== DIRECTORY ENUMERATION ====================
class DirectoryEnumerator:
    """Advanced directory and file enumeration"""
    
    COMMON_PATHS = [
        # Administrative
        'admin', 'administrator', 'wp-admin', 'dashboard', 'control',
        'login', 'signin', 'auth', 'register', 'signup',
        'panel', 'cp', 'manager', 'backend',
        
        # Configuration
        'config', 'configuration', 'settings', 'setup',
        'install', 'update', 'upgrade',
        
        # Files
        'robots.txt', 'sitemap.xml', '.git/HEAD', '.env',
        'phpinfo.php', 'test.php', 'info.php',
        'backup.zip', 'dump.sql', 'backup.tar',
        
        # API endpoints
        'api', 'api/v1', 'graphql', 'rest',
        
        # Documentation
        'docs', 'documentation', 'help', 'wiki'
    ]
    
    @staticmethod
    def enumerate(url: str, wordlist: List[str] = None) -> Dict:
        """Enumerate directories and files"""
        if wordlist is None:
            wordlist = DirectoryEnumerator.COMMON_PATHS
        
        results = {
            'found': [],
            'protected': [],
            'info_disclosure': []
        }
        
        def check_path(path):
            full_url = f"{url.rstrip('/')}/{path}"
            try:
                response = requests.get(full_url, timeout=Config.TIMEOUT, allow_redirects=False)
                
                if response.status_code == 200:
                    logger.success(f"Found: {full_url} (200)")
                    results['found'].append({
                        'url': full_url,
                        'status': 200,
                        'size': len(response.content)
                    })
                    
                    # Check for information disclosure
                    disclosure_indicators = [
                        ('database_password', 'Database credentials'),
                        ('api_key', 'API key exposed'),
                        ('secret', 'Secret key exposed'),
                        ('password', 'Password in response')
                    ]
                    
                    for indicator, description in disclosure_indicators:
                        if indicator in response.text.lower():
                            results['info_disclosure'].append({
                                'url': full_url,
                                'indicator': indicator,
                                'description': description
                            })
                            logger.warning(f"Information disclosure: {description} at {full_url}")
                
                elif response.status_code == 403:
                    results['protected'].append({
                        'url': full_url,
                        'status': 403
                    })
                    logger.info(f"Protected: {full_url} (403)")
                
                time.sleep(Config.REQUEST_DELAY)
                
            except Exception as e:
                pass
        
        # Use threading for faster enumeration
        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            futures = [executor.submit(check_path, path) for path in wordlist]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
        
        return results

# ==================== VULNERABILITY SCANNER ====================
class VulnerabilityScanner:
    """Main vulnerability scanner coordinating all checks"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.results = {
            'target': target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_id': hashlib.md5(target_url.encode()).hexdigest()[:8],
            'findings': []
        }
    
    def scan_all(self) -> Dict:
        """Run complete security assessment"""
        logger.info(f"Starting security assessment for {self.target_url}")
        
        # 1. Security Headers
        logger.info("Scanning security headers...")
        headers = SecurityHeadersScanner.scan(self.target_url)
        if headers:
            self.results['findings'].append({
                'category': 'security_headers',
                'data': headers
            })
        
        # 2. Directory Enumeration
        logger.info("Enumerating directories...")
        directories = DirectoryEnumerator.enumerate(self.target_url)
        if directories['found']:
            self.results['findings'].append({
                'category': 'directory_enumeration',
                'data': directories
            })
        
        # 3. SQL Injection
        logger.info("Testing for SQL injection...")
        sqli = AdvancedSQLiDetector.detect(self.target_url)
        if sqli['vulnerable']:
            self.results['findings'].append({
                'category': 'sql_injection',
                'data': sqli
            })
        
        # 4. XSS
        logger.info("Testing for XSS vulnerabilities...")
        xss = XSSDetector.detect(self.target_url)
        if xss['vulnerable']:
            self.results['findings'].append({
                'category': 'xss',
                'data': xss
            })
        
        # 5. Additional checks can be added here
        
        return self.results
    
    def generate_report(self, format: str = 'json'):
        """Generate comprehensive report"""
        if format == 'json':
            filename = f"report_{self.results['scan_id']}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.success(f"Report saved to {filename}")
        
        elif format == 'html':
            filename = f"report_{self.results['scan_id']}.html"
            html_report = self._generate_html_report()
            with open(filename, 'w') as f:
                f.write(html_report)
            logger.success(f"HTML report saved to {filename}")
        
        return filename
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
                .critical {{ background: #ffebee; border-left: 4px solid #f44336; }}
                .high {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
                .medium {{ background: #fff8e1; border-left: 4px solid #ffc107; }}
                .low {{ background: #e8f5e9; border-left: 4px solid #4caf50; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Assessment Report</h1>
                <p>Target: {self.results['target']}</p>
                <p>Scan ID: {self.results['scan_id']}</p>
                <p>Date: {self.results['timestamp']}</p>
            </div>
        """
        
        for finding in self.results['findings']:
            html += f"""
            <div class="finding">
                <h3>{finding['category'].replace('_', ' ').title()}</h3>
                <pre>{json.dumps(finding['data'], indent=2)}</pre>
            </div>
            """
        
        html += "</body></html>"
        return html

# ==================== MAIN INTERFACE ====================
class SecurityAssessmentFramework:
    """Main framework interface"""
    
    @staticmethod
    def parse_arguments():
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="Advanced Security Assessment Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --full
  %(prog)s https://example.com --output html
            """
        )
        
        parser.add_argument('target', help='Target URL to assess')
        parser.add_argument('--full', action='store_true', help='Run comprehensive scan')
        parser.add_argument('--output', choices=['json', 'html', 'both'], default='json',
                          help='Output format (default: json)')
        parser.add_argument('--threads', type=int, default=5,
                          help='Number of threads (default: 5)')
        parser.add_argument('--delay', type=float, default=0.5,
                          help='Delay between requests (default: 0.5)')
        
        return parser.parse_args()

# ==================== MAIN EXECUTION ====================
def main():
    """Main execution function"""
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║    Advanced Security Assessment Framework (ASAF)          ║
    ║                    Version 2.1.0                          ║
    ║          For Authorized Security Testing Only             ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    args = SecurityAssessmentFramework.parse_arguments()
    
# Update config based on arguments
    Config.MAX_THREADS = args.threads
    Config.REQUEST_DELAY = args.delay
    
    # Legal disclaimer
    print("\n" + "="*60)
    print("LEGAL DISCLAIMER:")
    print("This tool is for authorized security testing only.")
    print("Unauthorized use against systems you don't own is illegal.")
    print("You are responsible for your actions.")
    print("="*60 + "\n")
    
    confirm = input("Do you have authorization to test this target? (yes/no): ")
    if confirm.lower() != 'yes':
        logger.error("Aborting: Authorization not confirmed")
        sys.exit(1)
    
    try:
        # Initialize scanner
        scanner = VulnerabilityScanner(args.target)
        
        # Run scan
        results = scanner.scan_all()
        
        # Generate report
        if args.output in ['json', 'both']:
            scanner.generate_report('json')
        if args.output in ['html', 'both']:
            scanner.generate_report('html')
        
        # Summary
        print("\n" + "="*60)
        print("SCAN SUMMARY:")
        print(f"Target: {args.target}")
        print(f"Findings: {len(results['findings'])} categories")
        
        critical_count = sum(1 for f in results['findings'] 
                           if f['category'] in ['sql_injection', 'xss'])
        
        if critical_count > 0:
            print(f"Critical Findings: {critical_count}")
            logger.warning("Critical vulnerabilities found!")
        
        print("="*60)
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()