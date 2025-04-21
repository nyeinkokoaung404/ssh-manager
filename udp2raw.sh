#!/bin/bash

# =============================================
# UDP SSH Manager
# Version: 2.0
# Author: Channel 404
# =============================================

# Colors
plain='\033[0m'
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'

# Configuration
CONFIG_DIR="/etc/udp-ssh-manager"
UDP_CONFIG="${CONFIG_DIR}/config"
UDP_SERVICE="/etc/systemd/system/udp-ssh.service"
IPTABLES_RULES="${CONFIG_DIR}/iptables.rules"
LOG_FILE="${CONFIG_DIR}/udp-ssh.log"
PORTS="1-65535"
SSH_PORT=22

# Initialize
init_config() {
    mkdir -p "$CONFIG_DIR"
    touch "$LOG_FILE"
    [[ ! -f "$UDP_CONFIG" ]] && echo -e "# UDP SSH Configuration\nENABLED=no" > "$UDP_CONFIG"
}

# Logging
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Header
show_header() {
    clear
    echo -e "${magenta}"
    echo -e "==========================================="
    echo -e "   🌺 UDP SSH Manager - Channel 404 🌺  "
    echo -e "===========================================${plain}"
    echo ""
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${red}✗ Error: This script must be run as root${plain}"
        log "Permission denied - User is not root"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing=()
    local required=("iptables" "systemctl")
    
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${red}✗ Missing dependencies: ${missing[*]}${plain}"
        log "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

# Verify installation
verify_status() {
    local status=0
    
    echo -e "${blue}➤ Verifying current configuration...${plain}"
    log "Verification started"
    
    # Check config file
    if [[ -f "$UDP_CONFIG" ]]; then
        source "$UDP_CONFIG"
        echo -e "${green}✔ Config file exists at $UDP_CONFIG${plain}"
        echo -e "Current status: ${ENABLED}"
    else
        echo -e "${yellow}⚠ Config file missing${plain}"
        status=1
    fi
    
    # Check iptables rules
    if iptables -t nat -L PREROUTING -n | grep -q "udp dpt:1:65535 redir ports $SSH_PORT"; then
        echo -e "${green}✔ UDP redirect rules are active${plain}"
    else
        echo -e "${yellow}⚠ UDP redirect rules not found${plain}"
        [[ "$ENABLED" == "yes" ]] && status=1
    fi
    
    # Check service
    if systemctl is-active udp-ssh &>/dev/null; then
        echo -e "${green}✔ udp-ssh service is running${plain}"
    else
        echo -e "${yellow}⚠ udp-ssh service is not running${plain}"
        [[ "$ENABLED" == "yes" ]] && status=1
    fi
    
    log "Verification completed with status $status"
    return $status
}

# Enable UDP
enable_udp() {
    check_root
    check_dependencies
    show_header
    
    echo -e "${yellow}➤ Enabling UDP SSH on ports $PORTS...${plain}"
    log "Starting UDP SSH enable process"
    
    # Install dependencies
    echo -e "${blue}➤ Installing required packages...${plain}"
    if ! apt-get update &>> "$LOG_FILE"; then
        echo -e "${red}✗ Failed to update packages${plain}"
        log "Package update failed"
        exit 1
    fi
    
    if ! apt-get install -y iptables &>> "$LOG_FILE"; then
        echo -e "${red}✗ Failed to install iptables${plain}"
        log "iptables installation failed"
        exit 1
    fi
    
    # Configure iptables
    echo -e "${blue}➤ Configuring iptables rules...${plain}"
    if ! iptables -t nat -A PREROUTING -p udp --dport "$PORTS" -j REDIRECT --to-ports "$SSH_PORT" &>> "$LOG_FILE"; then
        echo -e "${red}✗ Failed to add iptables rule${plain}"
        log "iptables rule addition failed"
        exit 1
    fi
    
    # Create systemd service
    echo -e "${blue}➤ Creating systemd service...${plain}"
    cat > "$UDP_SERVICE" <<EOF
[Unit]
Description=UDP SSH Redirect Service
After=network.target
Requires=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/iptables-restore < $IPTABLES_RULES
ExecReload=/sbin/iptables-restore < $IPTABLES_RULES
ExecStop=/sbin/iptables -t nat -F PREROUTING

[Install]
WantedBy=multi-user.target
EOF

    # Save iptables rules
    echo -e "${blue}➤ Saving iptables rules...${plain}"
    mkdir -p "$(dirname "$IPTABLES_RULES")"
    if ! iptables-save > "$IPTABLES_RULES"; then
        echo -e "${red}✗ Failed to save iptables rules${plain}"
        log "Failed to save iptables rules"
        exit 1
    fi
    
    # Enable service
    echo -e "${blue}➤ Enabling and starting service...${plain}"
    systemctl daemon-reload
    if ! systemctl enable --now udp-ssh &>> "$LOG_FILE"; then
        echo -e "${red}✗ Failed to enable udp-ssh service${plain}"
        log "Service enable failed"
        exit 1
    fi
    
    # Update config
    echo -e "ENABLED=yes" > "$UDP_CONFIG"
    echo -e "PORTS=$PORTS" >> "$UDP_CONFIG"
    echo -e "SSH_PORT=$SSH_PORT" >> "$UDP_CONFIG"
    echo -e "LAST_ENABLED=$(date '+%Y-%m-%d %H:%M:%S')" >> "$UDP_CONFIG"
    
    echo -e "${green}✔ Successfully enabled UDP SSH on ports $PORTS${plain}"
    echo -e "${yellow}ℹ Note: Make sure your firewall allows UDP traffic${plain}"
    log "UDP SSH successfully enabled"
    
    verify_status
}

# Disable UDP
disable_udp() {
    check_root
    show_header
    
    echo -e "${yellow}➤ Disabling UDP SSH...${plain}"
    log "Starting UDP SSH disable process"
    
    # Remove iptables rules
    echo -e "${blue}➤ Removing iptables rules...${plain}"
    iptables -t nat -D PREROUTING -p udp --dport "$PORTS" -j REDIRECT --to-ports "$SSH_PORT" &>> "$LOG_FILE"
    
    # Save clean iptables
    echo -e "${blue}➤ Saving iptables rules...${plain}"
    iptables-save > "$IPTABLES_RULES"
    
    # Stop service
    echo -e "${blue}➤ Stopping service...${plain}"
    systemctl stop udp-ssh
    systemctl disable udp-ssh
    
    # Update config
    echo -e "ENABLED=no" > "$UDP_CONFIG"
    echo -e "LAST_DISABLED=$(date '+%Y-%m-%d %H:%M:%S')" >> "$UDP_CONFIG"
    
    echo -e "${green}✔ Successfully disabled UDP SSH${plain}"
    log "UDP SSH successfully disabled"
    
    verify_status
}

# Show help
show_help() {
    show_header
    echo -e "${cyan}Usage: $0 [command]${plain}"
    echo ""
    echo -e "${blue}Available commands:${plain}"
    echo -e "  ${green}enable${plain}    - Enable UDP SSH redirection"
    echo -e "  ${green}disable${plain}   - Disable UDP SSH redirection"
    echo -e "  ${green}status${plain}    - Show current configuration status"
    echo -e "  ${green}help${plain}      - Show this help message"
    echo ""
    echo -e "${yellow}Note: This script requires root privileges${plain}"
}

# Main execution
init_config

case "$1" in
    enable|--enable|-e)
        enable_udp
        ;;
    disable|--disable|-d)
        disable_udp
        ;;
    status|--status|-s)
        show_header
        verify_status
        ;;
    help|--help|-h|*)
        show_help
        ;;
esac

exit 0
