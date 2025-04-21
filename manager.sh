#!/bin/bash

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
DNSTT_DIR="/etc/dnstt"
DNSTT_SERVICE="/etc/systemd/system/dnstt-server.service"
LOG_FILE="/var/log/ssh_manager.log"

# Logging function
log() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# Check root
[[ $EUID -ne 0 ]] && echo -e "${red}Error: ${plain} Run as root!${plain}" && exit 1

# Header display
show_header() {
    echo -e "${green}==========================================="
    echo -e "   🌺 CHANNEL 404 SSH MANAGER 🌺  "
    echo -e "===========================================${plain}"
    echo ""
}

# Footer display
show_footer() {
    echo ""
    echo -e "${yellow}------------------------------------${plain}"
    echo -e "Developed by \033[1;35m 『ᔰ ⭕️⃤ 『ᔰ 🇲🇲${plain}"
    echo -e "${yellow}------------------------------------${plain}"
    echo ""
    echo -e "${cyan}Contact to developer: https://t.me/nkka404${plain}"
    echo -e "${yellow}------------------------------------${plain}"
    log "Operation completed at $(date)"
}

# Create SSH user
create_user() {
    local username="$1"
    local password="$2"
    local limit="$3"
    local days="$4"
    local protocol="$5"
    local message="$6"
    local token="$7"

    # Token validation (5 minute window)
    local current_time=$(date +%s)
    if [[ -z "$token" || $((current_time - token)) -gt 300 ]]; then
        echo -e "${red}Error: Invalid or expired token${plain}"
        log "Failed - Invalid token for user creation"
        return 1
    fi

    # Validate username
    if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        echo -e "${red}Error: Invalid username${plain}"
        log "Failed - Invalid username: $username"
        return 1
    fi

    # Password validation
    if [[ ${#password} -lt 3 ]]; then
        echo -e "${red}Error: Password too short (min 3 chars)${plain}"
        log "Failed - Password too short for user: $username"
        return 1
    fi

    # Configure SSH
    sed -i 's/#\?AllowTcpForwarding .*/AllowTcpForwarding yes/' "$SSH_CONFIG"
    sed -i 's/#\?PasswordAuthentication .*/PasswordAuthentication yes/' "$SSH_CONFIG"
    sed -i "s|#\?Banner .*|Banner $BANNER_FILE|" "$SSH_CONFIG"
    
    # Restart SSH service
    if ! systemctl restart sshd; then
        echo -e "${red}Error: Failed to restart SSH service${plain}"
        log "Failed - SSH service restart failed"
        return 1
    fi

    # Set banner
    echo -e "$message" > "$BANNER_FILE"

    # Create user
    local expiry_date=$(date -d "+$days days" +%Y-%m-%d)
    local pass_hash=$(openssl passwd -1 "$password")
    
    if ! useradd -e "$expiry_date" -m -s /bin/bash -p "$pass_hash" "$username"; then
        echo -e "${red}Error: Failed to create user${plain}"
        log "Failed - User creation error: $username"
        return 1
    fi

    # Add to database
    echo "$username $limit $protocol $(date +%F)" >> "$USER_DB"
    
    # Display info
    local ip=$(curl -s ifconfig.me)
    show_header
    echo -e "${blue}▣ Account Type: ${green}SSH ${protocol^^}${plain}"
    echo -e "${blue}▣ Server IP: ${green}$ip${plain}"
    echo -e "${blue}▣ Username: ${green}$username${plain}"
    echo -e "${blue}▣ Password: ${green}$password${plain}"
    echo -e "${blue}▣ Expiry Date: ${green}$(date -d "$expiry_date" +%d/%m/%Y)${plain}"
    echo -e "${blue}▣ Concurrent Login: ${green}$limit${plain}"
    
    # Special protocol info
    case "$protocol" in
        udp|both)
            echo -e "${udp_color}▣ UDP Ports: 1-65535${plain}"
            ;;
        dnstt)
            if [ -f "$DNSTT_DIR/config" ]; then
                echo -e "${dnstt_color}▣ DNSTT Domain: $(grep '^domain=' "$DNSTT_DIR/config" | cut -d= -f2)${plain}"
                echo -e "${dnstt_color}▣ DNSTT Key: $(grep '^key=' "$DNSTT_DIR/config" | cut -d= -f2)${plain}"
            fi
            ;;
    esac
    
    log "Created user: $username with $protocol protocol"
    return 0
}

# Install DNSTT server
install_dnstt() {
    local domain="$1"
    local key="$2"
    local port="$3"
    
    show_header
    echo -e "${dnstt_color}➤ Installing DNSTT server...${plain}"
    log "Starting DNSTT server installation"
    
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
        apt-get update
        if ! apt-get install -y "${missing[@]}"; then
            echo -e "${red}Error: Failed to install dependencies${plain}"
            log "Failed - Dependency installation"
            return 1
        fi
    fi
    
    # Create DNSTT directory
    mkdir -p "$DNSTT_DIR" || {
        echo -e "${red}Error: Failed to create DNSTT directory${plain}"
        log "Failed - DNSTT directory creation"
        return 1
    }
    
    # Clone and build DNSTT
    cd "$DNSTT_DIR" || return 1
    if [ ! -d "$DNSTT_DIR/mtprotoproxy" ]; then
        if ! git clone https://github.com/alexbers/mtprotoproxy.git; then
            echo -e "${red}Error: Failed to clone DNSTT repository${plain}"
            log "Failed - DNSTT git clone"
            return 1
        fi
    fi
    
    cd mtprotoproxy || return 1
    if [ ! -f "$DNSTT_DIR/mtprotoproxy/mtprotoproxy" ]; then
        if ! cmake . || ! make -j$(nproc); then
            echo -e "${red}Error: Failed to build DNSTT${plain}"
            log "Failed - DNSTT build"
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
    systemctl daemon-reload
    if ! systemctl enable --now dnstt-server; then
        echo -e "${red}Error: Failed to start DNSTT service${plain}"
        log "Failed - DNSTT service start"
        return 1
    fi
    
    echo -e "${green}✔ DNSTT server installed successfully!${plain}"
    echo -e "${dnstt_color}▣ Domain: ${green}$domain${plain}"
    echo -e "${dnstt_color}▣ Secret Key: ${green}$key${plain}"
    echo -e "${dnstt_color}▣ Local Port: ${green}$port${plain}"
    
    log "DNSTT server installed - Domain: $domain"
    return 0
}

# Configure UDP
configure_udp() {
    local action="$1"
    local ports="${2:-1-65535}"
    
    show_header
    case "$action" in
        enable)
            echo -e "${udp_color}➤ Enabling UDP SSH on ports $ports...${plain}"
            log "Enabling UDP ports: $ports"
            
            # Install UDP relay if needed
            if ! command -v udp2raw &> /dev/null; then
                echo -e "${yellow}➤ Installing UDP relay...${plain}"
                wget -O /usr/bin/udp2raw https://github.com/nyeinkokoaung404/ssh-manager/raw/main/udp2raw
                chmod +x /usr/bin/udp2raw
            fi
            
            # Create UDP config
            echo "PORTS=$ports" > "$UDP_CONFIG"
            echo "ENABLED=yes" >> "$UDP_CONFIG"
            
            # Create systemd service
            cat > /etc/systemd/system/udp-ssh.service <<EOF
[Unit]
Description=UDP SSH Relay
After=network.target

[Service]
User=root
ExecStart=/usr/bin/udp2raw -s -l0.0.0.0:53 -r 127.0.0.1:22 --raw-mode faketcp -a -k "your-secret-key"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
            
            systemctl daemon-reload
            systemctl enable --now udp-ssh
            
            echo -e "${green}✔ UDP SSH enabled on ports $ports${plain}"
            log "UDP enabled on ports $ports"
            ;;
            
        disable)
            echo -e "${udp_color}➤ Disabling UDP SSH...${plain}"
            log "Disabling UDP"
            
            systemctl stop udp-ssh
            systemctl disable udp-ssh
            echo "ENABLED=no" > "$UDP_CONFIG"
            
            echo -e "${green}✔ UDP SSH disabled${plain}"
            log "UDP disabled"
            ;;
            
        *)
            echo -e "${red}Error: Invalid UDP action${plain}"
            return 1
            ;;
    esac
    
    return 0
}

# User management functions
delete_user() {
    local username="$1"
    
    show_header
    if grep -q "^$username " "$USER_DB"; then
        if userdel -r "$username" 2>/dev/null; then
            sed -i "/^$username /d" "$USER_DB"
            echo -e "${green}✔ User $username deleted successfully${plain}"
            log "Deleted user: $username"
        else
            echo -e "${red}Error: Failed to delete user $username${plain}"
            log "Failed - Delete user: $username"
            return 1
        fi
    else
        echo -e "${yellow}⚠ User $username not found${plain}"
        log "User not found: $username"
        return 1
    fi
    
    return 0
}

list_users() {
    show_header
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
    return 0
}

# Active sessions
active_sessions() {
    show_header
    echo -e "${blue}=== Active SSH Sessions ===${plain}"
    printf "${green}%-15s %-20s %-10s %-15s${plain}\n" "User" "IP Address" "Login Time" "Session ID"
    echo "------------------------------------------------------------"
    
    who -u | awk '{print $1,$5,$3,$4,$7}' | while read -r user ip date time session; do
        printf "%-15s %-20s %-10s %-15s\n" "$user" "$ip" "$date $time" "$session"
    done
    
    log "Viewed active sessions"
    return 0
}

# Backup and restore
backup_users() {
    show_header
    local backup_file="$BACKUP_DIR/ssh_backup_$(date +%F_%H-%M-%S).tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    echo -e "${blue}➤ Creating backup...${plain}"
    
    if tar -czf "$backup_file" "$USER_DB" "$BANNER_FILE" /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null; then
        echo -e "${green}✔ Backup created: $backup_file${plain}"
        echo -e "${yellow}ℹ Size: $(du -h "$backup_file" | cut -f1)${plain}"
        log "Created backup: $backup_file"
    else
        echo -e "${red}Error: Failed to create backup${plain}"
        log "Failed - Backup creation"
        return 1
    fi
    
    return 0
}

restore_users() {
    show_header
    local backup_file="$1"
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${red}Error: Backup file not found${plain}"
        log "Failed - Backup file not found: $backup_file"
        return 1
    fi
    
    echo -e "${blue}➤ Restoring from backup...${plain}"
    
    if tar -xzf "$backup_file" -C /; then
        systemctl restart sshd
        echo -e "${green}✔ Users restored from $backup_file${plain}"
        log "Restored from backup: $backup_file"
    else
        echo -e "${red}Error: Failed to restore backup${plain}"
        log "Failed - Backup restore"
        return 1
    fi
    
    return 0
}

# Main execution
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
        show_header
        echo -e "${red}Usage: $0 [option]${plain}"
        echo ""
        echo -e "${blue}User Management:${plain}"
        echo -e "  --create [user] [pass] [limit] [days] [protocol] [message] [token]  Create SSH user"
        echo -e "  --delete [user]                                                    Delete user"
        echo -e "  --list                                                             List all users"
        echo -e "  --extend [user] [days]                                             Extend user expiry"
        echo ""
        echo -e "${udp_color}UDP Configuration:${plain}"
        echo -e "  --enable-udp [ports]                                               Enable UDP (default: 1-65535)"
        echo -e "  --disable-udp                                                      Disable UDP"
        echo ""
        echo -e "${dnstt_color}DNSTT Configuration:${plain}"
        echo -e "  --install-dnstt [domain] [key] [port]                              Install DNSTT server"
        echo ""
        echo -e "${blue}Other Functions:${plain}"
        echo -e "  --sessions                                                         Show active sessions"
        echo -e "  --backup                                                           Backup user database"
        echo -e "  --restore [file]                                                   Restore from backup"
        echo -e "  --limit [user] [down_mbps] [up_mbps]                               Set bandwidth limit"
        echo ""
        log "Invalid command executed: $0 $*"
        exit 1
        ;;
esac

# Show footer if command was valid
if [[ "$1" == --* ]]; then
    show_footer
fi

exit 0
