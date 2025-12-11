#!/bin/bash

# Security Tools Installation Script
# This script installs all the security tools required for AIPentester/HexStrike integration

# Colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print section headers
print_section() {
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}============================================================${NC}\n"
}

# Function to install a tool with apt
install_apt_tool() {
    local tool_name=$1
    local package_name=${2:-$tool_name}
    
    echo -e "${YELLOW}Installing $tool_name...${NC}"
    if which $tool_name > /dev/null 2>&1; then
        echo -e "${GREEN}$tool_name is already installed.${NC}"
    else
        sudo apt-get install -y $package_name
        if which $tool_name > /dev/null 2>&1; then
            echo -e "${GREEN}$tool_name installed successfully.${NC}"
        else
            echo -e "${RED}Failed to install $tool_name.${NC}"
        fi
    fi
}

# Function to install a tool with pip
install_pip_tool() {
    local tool_name=$1
    local package_name=${2:-$tool_name}
    
    echo -e "${YELLOW}Installing $tool_name with pip...${NC}"
    if which $tool_name > /dev/null 2>&1; then
        echo -e "${GREEN}$tool_name is already installed.${NC}"
    else
        pip3 install $package_name
        if which $tool_name > /dev/null 2>&1; then
            echo -e "${GREEN}$tool_name installed successfully.${NC}"
        else
            echo -e "${RED}Failed to install $tool_name with pip.${NC}"
        fi
    fi
}

# Function to install a tool with go
install_go_tool() {
    local tool_name=$1
    local go_path=${2:-"github.com/$tool_name/$tool_name"}
    
    echo -e "${YELLOW}Installing $tool_name with Go...${NC}"
    if which $tool_name > /dev/null 2>&1; then
        echo -e "${GREEN}$tool_name is already installed.${NC}"
    else
        go install $go_path@latest
        if which $tool_name > /dev/null 2>&1; then
            echo -e "${GREEN}$tool_name installed successfully.${NC}"
        else
            echo -e "${RED}Failed to install $tool_name with Go. Make sure Go is installed and GOPATH is set correctly.${NC}"
        fi
    fi
}

# Function to clone and install a tool from GitHub
install_github_tool() {
    local tool_name=$1
    local repo_url=$2
    local install_cmd=$3
    
    echo -e "${YELLOW}Installing $tool_name from GitHub...${NC}"
    if which $tool_name > /dev/null 2>&1; then
        echo -e "${GREEN}$tool_name is already installed.${NC}"
    else
        local temp_dir=$(mktemp -d)
        git clone $repo_url $temp_dir
        cd $temp_dir
        eval $install_cmd
        cd - > /dev/null
        rm -rf $temp_dir
        
        if which $tool_name > /dev/null 2>&1; then
            echo -e "${GREEN}$tool_name installed successfully.${NC}"
        else
            echo -e "${RED}Failed to install $tool_name from GitHub.${NC}"
        fi
    fi
}

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    echo -e "${RED}This script requires sudo privileges. Please run with sudo or as root.${NC}"
    exit 1
fi

# Update package lists
print_section "Updating Package Lists"
sudo apt-get update

# Install basic dependencies
print_section "Installing Basic Dependencies"
sudo apt-get install -y build-essential git curl wget python3 python3-pip python3-dev libssl-dev libffi-dev golang

# Make sure Go binaries are in PATH
if ! grep -q "export PATH=\$PATH:\$HOME/go/bin" ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:$HOME/go/bin
fi

# Network & Reconnaissance Tools
print_section "Installing Network & Reconnaissance Tools"
install_apt_tool nmap
install_apt_tool masscan
install_github_tool rustscan "https://github.com/RustScan/RustScan" "cargo install rustscan"
install_go_tool amass "github.com/owasp-amass/amass/v3/..."
install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool nuclei "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
install_apt_tool fierce
install_apt_tool dnsenum
install_pip_tool autorecon
install_apt_tool theharvester
install_apt_tool responder
install_pip_tool netexec
install_github_tool "enum4linux-ng" "https://github.com/cddmp/enum4linux-ng" "pip3 install -r requirements.txt && sudo ln -sf $(pwd)/enum4linux-ng.py /usr/local/bin/enum4linux-ng"

# Web Application Security Tools
print_section "Installing Web Application Security Tools"
install_go_tool gobuster "github.com/OJ/gobuster/v3"
install_go_tool feroxbuster "github.com/epi052/feroxbuster"
install_github_tool dirsearch "https://github.com/maurosoria/dirsearch" "pip3 install -r requirements.txt && sudo ln -sf $(pwd)/dirsearch.py /usr/local/bin/dirsearch"
install_go_tool ffuf "github.com/ffuf/ffuf"
install_apt_tool dirb
install_go_tool httpx "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool katana "github.com/projectdiscovery/katana/cmd/katana"
install_apt_tool nikto
install_apt_tool sqlmap
install_github_tool wpscan "https://github.com/wpscanteam/wpscan" "gem install wpscan"
install_go_tool arjun "github.com/projectdiscovery/arjun/cmd/arjun"
install_go_tool paramspider "github.com/devanshbatham/paramspider"
install_go_tool dalfox "github.com/hahwul/dalfox/v2"
install_apt_tool wafw00f

# Password & Authentication Tools
print_section "Installing Password & Authentication Tools"
install_apt_tool hydra
install_apt_tool john
install_apt_tool hashcat
install_apt_tool medusa
install_apt_tool patator
install_pip_tool crackmapexec
install_github_tool "evil-winrm" "https://github.com/Hackplayers/evil-winrm" "gem install evil-winrm"
install_apt_tool hash-identifier
install_apt_tool ophcrack

# Binary Analysis & Reverse Engineering Tools
print_section "Installing Binary Analysis & Reverse Engineering Tools"
install_apt_tool gdb
install_apt_tool radare2
install_apt_tool binwalk
# Ghidra requires manual installation due to its size and Java dependencies
echo -e "${YELLOW}Ghidra requires manual installation. Please download from https://ghidra-sre.org/${NC}"
install_apt_tool checksec
install_apt_tool binutils # For strings and objdump
# Volatility3 requires specific installation
install_pip_tool volatility3
install_apt_tool foremost
install_apt_tool steghide
install_apt_tool exiftool

# Verify installations
print_section "Verifying Installations"
echo -e "${YELLOW}Network & Reconnaissance Tools:${NC}"
which nmap masscan rustscan amass subfinder nuclei fierce dnsenum autorecon theharvester responder netexec enum4linux-ng

echo -e "\n${YELLOW}Web Application Security Tools:${NC}"
which gobuster feroxbuster dirsearch ffuf dirb httpx katana nikto sqlmap wpscan arjun paramspider dalfox wafw00f

echo -e "\n${YELLOW}Password & Authentication Tools:${NC}"
which hydra john hashcat medusa patator crackmapexec evil-winrm hash-identifier ophcrack

echo -e "\n${YELLOW}Binary Analysis & Reverse Engineering Tools:${NC}"
which gdb radare2 binwalk checksec strings objdump volatility3 foremost steghide exiftool

# Final message
print_section "Installation Complete"
echo -e "${GREEN}Security tools installation completed.${NC}"
echo -e "${YELLOW}Note: Some tools may require additional configuration or manual installation.${NC}"
echo -e "${YELLOW}Please check the verification output above to ensure all tools were installed correctly.${NC}"
echo -e "\n${BLUE}To add Go binaries to your PATH permanently, you may need to restart your terminal or run:${NC}"
echo -e "source ~/.bashrc"