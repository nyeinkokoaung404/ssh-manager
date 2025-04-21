#!/bin/bash

# =============================================
# CHANNEL 404 SSH MANAGER - ENHANCED VERSION
# =============================================
# Features:
# - User management (create/delete/list)
# - UDP SSH configuration (fixed port range support)
# - DNSTT server setup
# - Backup/restore functionality
# - Bandwidth limiting
# - Session monitoring
# =============================================

# Colors
plain='\033[0m'
red='\e[31m'
yellow='\e[33m'
green='\e[92m'
blue='\e[94m'
cyan='\e[96m'
magenta='\e[95m'
dnstt_color='\e[35m'
udp_color='\e[38;5;208m'

# Configuration
USER_DB="/root/usuarios.db"
BACKUP_DIR="/root/ssh_backups"
BANNER_FILE="/etc/ssh/channel_404"
SSH_CONFIG="/etc/ssh/sshd_config"
UDP_CONFIG="/etc/ssh/sshd_udp"
UDP_SERVICE="/etc/systemd/system/udp-ssh.service"
DNSTT_DIR="/etc/dnstt"
DNSTT_SERVICE="/etc/systemd/system/dnstt-server.service"
LOG_FILE="/var/log/ssh_manager.log"
IPTABLES_RULES="/etc/iptables.rules"
FIREWALLD_ENABLED=$(systemctl is-enabled firewalld 2>/dev/null)
VERSION="1.2.2"

# Initialize logging
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    log "=== SSH Manager Session Started ==="
}

# Enhanced logging function
log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp - [$level] - $message" >> "$LOG_FILE"
    [ "$level" = "ERROR" ] && echo -e "${red}[ERROR]${plain} $message" >&2
    [ "$level" = "WARNING" ] && echo -e "${yellow}[WARNING]${plain} $message" >&1
}

# Check root with better error message
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "This script must be run as root" "ERROR"
        echo -e "${red}Error:${plain} Please run as root using sudo or switch to root user"
        exit 1
    fi
}

# Header display with version info
show_header() {
    clear
    echo -e "${green}==============================================="
    echo -e "   🌺 CHANNEL 404 SSH MANAGER v$VERSION 🌺  "
    echo -e "===============================================${plain}"
    echo -e "${blue}▣ Server: ${green}$(hostname)${plain}"
    echo -e "${blue}▣ IP: ${green}$(curl -s ifconfig.me)${plain}"
    echo -e "${blue}▣ Date: ${green}$(date)${plain}"
    echo -e "${blue}▣ Uptime: ${green}$(uptime -p)${plain}"
    echo ""
}

# Footer display with execution time
show_footer() {
    local start_time="$1"
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo -e "${yellow}--------------------------------------------${plain}"
    echo -e "Execution time: ${green}${duration} seconds${plain}"
    echo -e "Developed by \033[1;35m 『ᔰ ⭕️⃤ 『ᔰ 🇲🇲${plain}"
    echo -e "${yellow}--------------------------------------------${plain}"
    echo -e "${cyan}Contact: https://t.me/nkka404${plain}"
    echo -e "${yellow}--------------------------------------------${plain}"
    log "Operation completed in ${duration} seconds"
}

# Validate input parameters
validate_input() {
    local type="$1"
    local value="$2"
    
    case "$type" in
        username)
            if ! [[ "$value" =~ ^[a-z_][a-z0-9_-]{3,15}$ ]]; then
                log "Invalid username: $value" "ERROR"
                echo -e "${red}Error:${plain} Username must be 4-16 chars (a-z, 0-9, _-) starting with letter"
                return 1
            fi
            ;;
        password)
            if [[ ${#value} -lt 4 ]]; then
                log "Password too short: $value" "ERROR"
                echo -e "${red}Error:${plain} Password must be at least 4 characters"
                return 1
            fi
            ;;
        port)
            if ! [[ "$value" =~ ^[0-9]+(:[0-9]+)?$ ]]; then
                log "Invalid port range: $value" "ERROR"
                echo -e "${red}Error:${plain} Invalid port format. Use single port or range (e.g., 10000:20000)"
                return 1
            fi
            ;;
        days)
            if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 1 ]; then
                log "Invalid days value: $value" "ERROR"
                echo -e "${red}Error:${plain} Days must be a positive number"
                return 1
            fi
            ;;
    esac
    return 0
}

# Create SSH user with enhanced validation
create_user() {
    local start_time=$(date +%s)
    local username="$1"
    local password="$2"
    local limit="$3"
    local days="$4"
    local protocol="$5"
    local message="$6"
    local token="$7"

    show_header
    
    # Validate all inputs
    validate_input username "$username" || return 1
    validate_input password "$password" || return 1
    validate_input days "$days" || return 1
    
    # Token validation (5 minute window)
    local current_time=$(date +%s)
    if [[ -z "$token" || $((current_time - token)) -gt 300 ]]; then
        log "Invalid or expired token provided" "ERROR"
        echo -e "${red}Error: Token invalid or expired${plain}"
        return 1
    fi

    # Configure SSH with backup
    cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"
    sed -i 's/#\?AllowTcpForwarding .*/AllowTcpForwarding yes/' "$SSH_CONFIG"
    sed -i 's/#\?PasswordAuthentication .*/PasswordAuthentication yes/' "$SSH_CONFIG"
    sed -i "s|#\?Banner .*|Banner $BANNER_FILE|" "$SSH_CONFIG"
    
    # Restart SSH service with error handling
    if ! systemctl restart sshd; then
        log "Failed to restart SSH service" "ERROR"
        # Restore backup on failure
        mv "${SSH_CONFIG}.bak" "$SSH_CONFIG"
        systemctl restart sshd
        return 1
    fi

    # Set banner
    echo -e "$message" > "$BANNER_FILE"

    # Create user with expiry
    local expiry_date=$(date -d "+$days days" +%Y-%m-%d)
    local pass_hash=$(openssl passwd -1 "$password")
    
    if ! useradd -e "$expiry_date" -m -s /bin/bash -p "$pass_hash" "$username"; then
        log "Failed to create user: $username" "ERROR"
        return 1
    fi

    # Add to database
    echo "$username $limit $protocol $(date +%F)" >> "$USER_DB"
    
    # Display info
    local ip=$(curl -s ifconfig.me)
    echo -e "${green}✔ User created successfully${plain}"
    echo -e "${blue}▣ Account Type: ${green}SSH ${protocol^^}${plain}"
    echo -e "${blue}▣ Server IP: ${green}$ip${plain}"
    echo -e "${blue}▣ Username: ${green}$username${plain}"
    echo -e "${blue}▣ Password: ${green}$password${plain}"
    echo -e "${blue}▣ Expiry Date: ${green}$(date -d "$expiry_date" +%d/%m/%Y)${plain}"
    echo -e "${blue}▣ Concurrent Login: ${green}$limit${plain}"
    
    # Protocol-specific info
    case "$protocol" in
        udp|both)
            echo -e "${udp_color}▣ UDP Ports: 1:65535${plain}"
            ;;
        dnstt)
            if [ -f "$DNSTT_DIR/config" ]; then
                echo -e "${dnstt_color}▣ DNSTT Domain: $(grep '^domain=' "$DNSTT_DIR/config" | cut -d= -f2)${plain}"
                echo -e "${dnstt_color}▣ DNSTT Key: $(grep '^key=' "$DNSTT_DIR/config" | cut -d= -f2)${plain}"
            fi
            ;;
    esac
    
    log "Created user: $username with $protocol protocol"
    show_footer "$start_time"
    return 0
}

# Fixed and improved UDP configuration
configure_udp() {
    local start_time=$(date +%s)
    local action="$1"
    local ports="${2:-1:65535}"
    
    show_header
    
    case "$action" in
        enable)
            log "Enabling UDP SSH on ports $ports"
            echo -e "${udp_color}➤ Enabling UDP SSH...${plain}"
            
            # Install dependencies
            echo -e "${blue}▣ Installing required packages...${plain}"
            if ! apt-get update || ! apt-get install -y iptables-persistent; then
                log "Failed to install dependencies" "ERROR"
                return 1
            fi
            
            # Configure iptables
            echo -e "${blue}▣ Configuring network rules...${plain}"
            
            # Clear existing rules first
            iptables -t nat -F PREROUTING
            
            # Handle port range or single port
            if [[ "$ports" == *":"* ]]; then
                local start_port=${ports%:*}
                local end_port=${ports#*:}
                
                # Check if we're using nftables
                if iptables --version | grep -q nf_tables; then
                    # nftables version - need to add rules individually
                    for (( port=start_port; port<=end_port; port++ )); do
                        iptables -t nat -A PREROUTING -p udp --dport $port -j REDIRECT --to-ports 22
                    done
                else
                    # legacy iptables version
                    iptables -t nat -A PREROUTING -p udp --dport $start_port:$end_port -j REDIRECT --to-ports 22
                fi
            else
                # Single port
                iptables -t nat -A PREROUTING -p udp --dport $ports -j REDIRECT --to-ports 22
            fi
            
            # Save rules
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
            
            # Create systemd service
            cat > "$UDP_SERVICE" <<EOF
[Unit]
Description=UDP SSH Redirect
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore < /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

            systemctl daemon-reload
            systemctl enable --now udp-ssh
            
            echo -e "${green}✔ UDP SSH enabled on ports $ports${plain}"
            log "UDP enabled on ports $ports"
            ;;
            
        disable)
            log "Disabling UDP SSH"
            echo -e "${udp_color}➤ Disabling UDP SSH...${plain}"
            
            # Remove iptables rules
            iptables -t nat -F PREROUTING
            iptables-save > /etc/iptables/rules.v4
            
            # Stop service
            systemctl stop udp-ssh
            systemctl disable udp-ssh
            
            echo -e "${green}✔ UDP SSH disabled${plain}"
            log "UDP disabled"
            ;;
    esac
    
    show_footer "$start_time"
    return 0
}

# Install DNSTT server with better error handling
install_dnstt() {
    local start_time=$(date +%s)
    local domain="$1"
    local key="$2"
    local port="$3"
    
    show_header
    echo -e "${dnstt_color}➤ Installing DNSTT server...${plain}"
    log "Starting DNSTT server installation"
    
    # Validate inputs
    if [[ -z "$domain" || -z "$key" || -z "$port" ]]; then
        log "Missing DNSTT parameters" "ERROR"
        echo -e "${red}Error: Domain, key and port are required${plain}"
        return 1
    fi
    
    validate_input port "$port" || return 1
    
    # Check dependencies
    local dependencies=(git build-essential cmake libuv1-dev libssl-dev)
    local missing=()
    
    for dep in "${dependencies[@]}"; do
        if ! dpkg -s "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    # Install missing dependencies
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${yellow}➤ Installing dependencies: ${missing[*]}${plain}"
        if ! apt-get update || ! apt-get install -y "${missing[@]}"; then
            log "Failed to install dependencies" "ERROR"
            return 1
        fi
    fi
    
    # Create DNSTT directory
    mkdir -p "$DNSTT_DIR" || {
        log "Failed to create DNSTT directory" "ERROR"
        return 1
    }
    
    # Clone and build DNSTT
    cd "$DNSTT_DIR" || return 1
    if [ ! -d "$DNSTT_DIR/mtprotoproxy" ]; then
        echo -e "${blue}▣ Cloning repository...${plain}"
        if ! git clone https://github.com/alexbers/mtprotoproxy.git; then
            log "Failed to clone DNSTT repository" "ERROR"
            return 1
        fi
    fi
    
    cd mtprotoproxy || return 1
    if [ ! -f "$DNSTT_DIR/mtprotoproxy/mtprotoproxy" ]; then
        echo -e "${blue}▣ Building DNSTT...${plain}"
        if ! cmake . || ! make -j$(nproc); then
            log "Failed to build DNSTT" "ERROR"
            return 1
        fi
    fi
    
    # Create config
    cat > "$DNSTT_DIR/config" <<EOF
domain=$domain
key=$key
port=$port
EOF
    
    # Create systemd service
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server
After=network.target

[Service]
User=root
WorkingDirectory=$DNSTT_DIR/mtprotoproxy
ExecStart=$DNSTT_DIR/mtprotoproxy/mtprotoproxy -c $DNSTT_DIR/config
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start service
    echo -e "${blue}▣ Starting service...${plain}"
    systemctl daemon-reload
    if ! systemctl enable --now dnstt-server; then
        log "Failed to start DNSTT service" "ERROR"
        return 1
    fi
    
    echo -e "${green}✔ DNSTT server installed successfully!${plain}"
    echo -e "${dnstt_color}▣ Domain: ${green}$domain${plain}"
    echo -e "${dnstt_color}▣ Secret Key: ${green}$key${plain}"
    echo -e "${dnstt_color}▣ Local Port: ${green}$port${plain}"
    
    log "DNSTT server installed - Domain: $domain"
    show_footer "$start_time"
    return 0
}

# Enhanced user deletion
delete_user() {
    local start_time=$(date +%s)
    local username="$1"
    
    show_header
    
    if grep -q "^$username " "$USER_DB"; then
        echo -e "${yellow}➤ Deleting user $username...${plain}"
        
        # Kill all user processes
        pkill -u "$username" 2>/dev/null
        
        # Remove user
        if userdel -r "$username" 2>/dev/null; then
            # Remove from database
            sed -i "/^$username /d" "$USER_DB"
            echo -e "${green}✔ User $username deleted successfully${plain}"
            log "Deleted user: $username"
        else
            echo -e "${red}Error: Failed to delete user $username${plain}"
            log "Failed to delete user: $username" "ERROR"
            return 1
        fi
    else
        echo -e "${yellow}⚠ User $username not found${plain}"
        log "User not found: $username" "WARNING"
        return 1
    fi
    
    show_footer "$start_time"
    return 0
}

# Enhanced user listing
list_users() {
    local start_time=$(date +%s)
    show_header
    
    if [ ! -f "$USER_DB" ] || [ ! -s "$USER_DB" ]; then
        echo -e "${yellow}No users found in database${plain}"
        log "User list requested - no users found"
        return 0
    fi
    
    echo -e "${blue}=== SSH User List ===${plain}"
    printf "${green}%-20s %-15s %-10s %-10s %-15s${plain}\n" "Username" "Expiry Date" "Limit" "Protocol" "Status"
    echo "------------------------------------------------------------------"
    
    while read -r line; do
        local user=$(echo "$line" | awk '{print $1}')
        local limit=$(echo "$line" | awk '{print $2}')
        local protocol=$(echo "$line" | awk '{print $3}')
        local created=$(echo "$line" | awk '{print $4}')
        
        local expiry=$(chage -l "$user" | grep "Account expires" | cut -d: -f2 | sed 's/^ *//')
        local status
        
        if [[ "$expiry" == "never" ]]; then
            expiry="Never"
            status=$(echo -e "${green}Active${plain}")
        elif [[ $(date -d "$expiry" +%s) -lt $(date +%s) ]]; then
            status=$(echo -e "${red}Expired${plain}")
        else
            status=$(echo -e "${green}Active${plain}")
        fi
        
        # Color protocol
        case "$protocol" in
            tcp) protocol=$(echo -e "${blue}$protocol${plain}") ;;
            udp|both) protocol=$(echo -e "${udp_color}$protocol${plain}") ;;
            dnstt) protocol=$(echo -e "${dnstt_color}$protocol${plain}") ;;
        esac
        
        printf "%-20s %-15s %-10s %-10s %-15s\n" "$user" "$expiry" "$limit" "$protocol" "$status"
    done < "$USER_DB"
    
    log "Listed all users"
    show_footer "$start_time"
    return 0
}

# Active sessions with more details
active_sessions() {
    local start_time=$(date +%s)
    show_header
    
    echo -e "${blue}=== Active SSH Sessions ===${plain}"
    
    if ! command -v who &> /dev/null; then
        echo -e "${red}Error: 'who' command not available${plain}"
        return 1
    fi
    
    local session_count=$(who | wc -l)
    echo -e "${blue}▣ Total sessions: ${green}$session_count${plain}"
    echo ""
    
    printf "${green}%-15s %-20s %-10s %-15s %-10s${plain}\n" "User" "IP Address" "Login Time" "Session ID" "Duration"
    echo "----------------------------------------------------------------------------"
    
    who -u | awk '{print $1,$5,$3,$4,$7}' | while read -r user ip date time session; do
        # Calculate session duration
        local login_epoch=$(date -d "$date $time" +%s)
        local now_epoch=$(date +%s)
        local duration_sec=$((now_epoch - login_epoch))
        local duration=$(printf "%02d:%02d:%02d" $((duration_sec/3600)) $((duration_sec%3600/60)) $((duration_sec%60)))
        
        printf "%-15s %-20s %-10s %-15s %-10s\n" "$user" "$ip" "$time" "$session" "$duration"
    done
    
    log "Viewed active sessions"
    show_footer "$start_time"
    return 0
}

# Backup users with compression
backup_users() {
    local start_time=$(date +%s)
    show_header
    
    mkdir -p "$BACKUP_DIR"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/ssh_backup_$timestamp.tar.gz"
    
    echo -e "${blue}➤ Creating backup...${plain}"
    log "Starting backup process"
    
    # Files to backup
    local backup_files=(
        "$USER_DB"
        "$BANNER_FILE"
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/gshadow"
        "/etc/ssh/sshd_config"
    )
    
    echo -e "${blue}▣ Backing up:${plain}"
    printf "  - %s\n" "${backup_files[@]}"
    
    if tar -czf "$backup_file" "${backup_files[@]}" 2>/dev/null; then
        local backup_size=$(du -h "$backup_file" | cut -f1)
        echo -e "${green}✔ Backup created successfully${plain}"
        echo -e "${blue}▣ Backup file: ${green}$backup_file${plain}"
        echo -e "${blue}▣ Size: ${green}$backup_size${plain}"
        log "Backup created: $backup_file ($backup_size)"
    else
        echo -e "${red}Error: Failed to create backup${plain}"
        log "Failed to create backup" "ERROR"
        return 1
    fi
    
    show_footer "$start_time"
    return 0
}

# Restore users from backup
restore_users() {
    local start_time=$(date +%s)
    local backup_file="$1"
    
    show_header
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${red}Error: Backup file not found${plain}"
        log "Backup file not found: $backup_file" "ERROR"
        return 1
    fi
    
    echo -e "${yellow}⚠ WARNING: This will overwrite current user data${plain}"
    read -p "Are you sure you want to restore from backup? (y/N) " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${red}Restore canceled${plain}"
        return 0
    fi
    
    echo -e "${blue}➤ Restoring from backup...${plain}"
    log "Starting restore from backup: $backup_file"
    
    if tar -xzf "$backup_file" -C /; then
        systemctl restart sshd
        echo -e "${green}✔ Users restored successfully${plain}"
        log "Restore completed from: $backup_file"
    else
        echo -e "${red}Error: Failed to restore backup${plain}"
        log "Failed to restore backup" "ERROR"
        return 1
    fi
    
    show_footer "$start_time"
    return 0
}

# Extend user expiry
extend_user() {
    local start_time=$(date +%s)
    local username="$1"
    local days="$2"
    
    show_header
    
    validate_input days "$days" || return 1
    
    if ! grep -q "^$username " "$USER_DB"; then
        echo -e "${red}Error: User $username not found${plain}"
        log "User not found: $username" "ERROR"
        return 1
    fi
    
    local current_expiry=$(chage -l "$username" | grep "Account expires" | cut -d: -f2 | sed 's/^ *//')
    if [[ "$current_expiry" == "never" ]]; then
        echo -e "${yellow}User $username has no expiry date${plain}"
        return 0
    fi
    
    local new_expiry=$(date -d "$current_expiry + $days days" +%Y-%m-%d)
    
    if usermod -e "$new_expiry" "$username"; then
        echo -e "${green}✔ User $username expiry extended${plain}"
        echo -e "${blue}▣ New expiry date: ${green}$(date -d "$new_expiry" +%d/%m/%Y)${plain}"
        log "Extended user $username expiry by $days days"
    else
        echo -e "${red}Error: Failed to extend user expiry${plain}"
        log "Failed to extend user $username expiry" "ERROR"
        return 1
    fi
    
    show_footer "$start_time"
    return 0
}

# Limit user bandwidth
limit_bandwidth() {
    local start_time=$(date +%s)
    local username="$1"
    local down_mbps="$2"
    local up_mbps="$3"
    
    show_header
    
    if ! grep -q "^$username " "$USER_DB"; then
        echo -e "${red}Error: User $username not found${plain}"
        return 1
    fi
    
    # Check if wondershaper is installed
    if ! command -v wondershaper &> /dev/null; then
        echo -e "${blue}▣ Installing wondershaper...${plain}"
        if ! apt-get install -y wondershaper; then
            echo -e "${red}Error: Failed to install wondershaper${plain}"
            return 1
        fi
    fi
    
    # TODO: Implement actual bandwidth limiting
    # This is a placeholder for actual implementation
    echo -e "${yellow}⚠ Bandwidth limiting not fully implemented yet${plain}"
    echo -e "${blue}▣ User: ${green}$username${plain}"
    echo -e "${blue}▣ Download limit: ${green}$down_mbps Mbps${plain}"
    echo -e "${blue}▣ Upload limit: ${green}$up_mbps Mbps${plain}"
    
    log "Set bandwidth limits for $username (Down: $down_mbps Mbps, Up: $up_mbps Mbps)"
    show_footer "$start_time"
    return 0
}

# Show usage information
show_usage() {
    show_header
    echo -e "${green}Usage: $0 [option] [arguments]${plain}"
    echo ""
    echo -e "${blue}User Management:${plain}"
    echo -e "  --create <user> <pass> <limit> <days> <protocol> <message> <token>"
    echo -e "  --delete <user>"
    echo -e "  --list"
    echo -e "  --extend <user> <days>"
    echo -e "  --limit <user> <down_mbps> <up_mbps>"
    echo ""
    echo -e "${udp_color}UDP Configuration:${plain}"
    echo -e "  --enable-udp [ports]  (e.g., 10000:20000 or 22)"
    echo -e "  --disable-udp"
    echo ""
    echo -e "${dnstt_color}DNSTT Configuration:${plain}"
    echo -e "  --install-dnstt <domain> <key> <port>"
    echo ""
    echo -e "${blue}Other Functions:${plain}"
    echo -e "  --sessions"
    echo -e "  --backup"
    echo -e "  --restore <backup_file>"
    echo ""
    echo -e "${yellow}Examples:${plain}"
    echo -e "  Create user: $0 --create user1 pass123 2 30 tcp \"Welcome\" 12345"
    echo -e "  Enable UDP: $0 --enable-udp 10000:20000"
    echo -e "  Install DNSTT: $0 --install-dnstt example.com secretkey 443"
    echo ""
    log "Usage information displayed"
}

# Main execution
init_logging
check_root

case "$1" in
    --create)
        create_user "$2" "$3" "$4" "$5" "$6" "$7" "$8"
        ;;
    --install-dnstt)
        install_dnstt "$2" "$3" "$4"
        ;;
    --enable-udp)
        configure_udp "enable" "$2"
        ;;
    --disable-udp)
        configure_udp "disable"
        ;;
    --delete)
        delete_user "$2"
        ;;
    --list)
        list_users
        ;;
    --sessions)
        active_sessions
        ;;
    --backup)
        backup_users
        ;;
    --restore)
        restore_users "$2"
        ;;
    --extend)
        extend_user "$2" "$3"
        ;;
    --limit)
        limit_bandwidth "$2" "$3" "$4"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

exit 0
