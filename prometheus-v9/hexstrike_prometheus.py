#!/usr/bin/env python3
"""
HexStrike Prometheus - Filtered MCP Client for AutoGen Integration

🚀 Prometheus Edition - Essential Security Tools Only
Optimized for AutoGen with <128 tools (OpenAI limit compliant)

Excluded Categories:
❌ Forensics Tools (volatility, binwalk, foremost, etc.)
❌ Cloud Security Tools (prowler, scout-suite, k8s, etc.)  
❌ Wireless Tools (aircrack, wifite, etc.)
❌ OSINT Tools (reconnaissance workflows, etc.)

Included Categories:
✅ Core Network Scanning (nmap, masscan, rustscan)
✅ Web Application Security (gobuster, nuclei, sqlmap, nikto)
✅ Exploitation Tools (metasploit, msfvenom)
✅ Password Attacks (hydra, john, hashcat)
✅ Network Penetration (netexec, enum4linux, smbmap)
✅ File Operations (create, modify, delete, list)
✅ Binary Analysis (basic tools only)
✅ Payload Generation

Architecture: Filtered MCP Client for AI agent communication with HexStrike server
Framework: FastMCP integration for tool orchestration
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import time
from datetime import datetime

from mcp.server.fastmcp import FastMCP

class HexStrikeColors:
    """Enhanced color palette matching the server's ModernVisualEngine.COLORS"""

    # Basic colors (for backward compatibility)
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Core enhanced colors
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Enhanced reddish tones and highlighting colors
    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    ROSE_RED = '\033[38;5;167m'
    BURGUNDY = '\033[38;5;52m'
    SCARLET = '\033[38;5;197m'
    RUBY = '\033[38;5;161m'

    # Highlighting colors
    HIGHLIGHT_RED = '\033[48;5;196m\033[38;5;15m'  # Red background, white text
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m'  # Yellow background, black text
    HIGHLIGHT_GREEN = '\033[48;5;46m\033[38;5;16m'  # Green background, black text
    HIGHLIGHT_BLUE = '\033[48;5;51m\033[38;5;16m'  # Blue background, black text
    HIGHLIGHT_PURPLE = '\033[48;5;129m\033[38;5;15m'  # Purple background, white text

    # Status colors with reddish tones
    SUCCESS = '\033[38;5;46m'  # Bright green
    WARNING = '\033[38;5;208m'  # Orange
    ERROR = '\033[38;5;196m'  # Bright red
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'  # Red background, white bold text
    INFO = '\033[38;5;51m'  # Cyan
    DEBUG = '\033[38;5;240m'  # Gray

    # Vulnerability severity colors
    VULN_CRITICAL = '\033[48;5;124m\033[38;5;15m\033[1m'  # Dark red background
    VULN_HIGH = '\033[38;5;196m\033[1m'  # Bright red bold
    VULN_MEDIUM = '\033[38;5;208m\033[1m'  # Orange bold
    VULN_LOW = '\033[38;5;226m'  # Yellow
    VULN_INFO = '\033[38;5;51m'  # Cyan

    # Tool status colors
    TOOL_RUNNING = '\033[38;5;46m\033[5m'  # Blinking green
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'  # Bold green
    TOOL_FAILED = '\033[38;5;196m\033[1m'  # Bold red
    TOOL_TIMEOUT = '\033[38;5;208m\033[1m'  # Bold orange
    TOOL_RECOVERY = '\033[38;5;129m\033[1m'  # Bold purple

# Backward compatibility alias
Colors = HexStrikeColors

class ColoredFormatter(logging.Formatter):
    """Enhanced formatter with colors and emojis for MCP client - matches server styling"""

    COLORS = {
        'DEBUG': HexStrikeColors.DEBUG,
        'INFO': HexStrikeColors.SUCCESS,
        'WARNING': HexStrikeColors.WARNING,
        'ERROR': HexStrikeColors.ERROR,
        'CRITICAL': HexStrikeColors.CRITICAL
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, HexStrikeColors.BRIGHT_WHITE)

        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{HexStrikeColors.RESET}"
        return super().format(record)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[🔥 HexStrike Prometheus] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

# Apply colored formatter
for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike Prometheus] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_HEXSTRIKE_SERVER = "http://192.168.7.117:8888"  # Default HexStrike server URL
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests
MAX_RETRIES = 3  # Maximum number of retries for connection attempts

class HexStrikeClient:
    """Enhanced client for communicating with the HexStrike AI API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the HexStrike AI Client

        Args:
            server_url: URL of the HexStrike AI API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

        # Try to connect to server with retries
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to HexStrike AI API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                # First try a direct connection test before using the health endpoint
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"🎯 Successfully connected to HexStrike AI API Server at {server_url}")
                    logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                    logger.info(f"📊 Server version: {health_check.get('version', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"🔌 Connection refused to {server_url}. Make sure the HexStrike AI server is running.")
                    time.sleep(2)  # Wait before retrying
                except Exception as e:
                    logger.warning(f"⚠️  Connection test failed: {str(e)}")
                    time.sleep(2)  # Wait before retrying
            except Exception as e:
                logger.warning(f"❌ Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)  # Wait before retrying

        if not connected:
            error_msg = f"Failed to establish connection to HexStrike AI API Server at {server_url} after {MAX_RETRIES} attempts"
            logger.error(error_msg)
            # We'll continue anyway to allow the MCP server to start, but tools will likely fail

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Response data as dictionary
        """
        try:
            url = f"{self.server_url}/{endpoint}"
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            return {"success": False, "error": f"Request timed out after {self.timeout} seconds", "timeout": True}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Connection error - server may be down", "connection_error": True}
        except requests.exceptions.HTTPError as e:
            return {"success": False, "error": f"HTTP error: {e.response.status_code}", "http_error": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def safe_post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with enhanced error handling and recovery.

        Args:
            endpoint: API endpoint path (without leading slash)
            data: Data to send in POST request

        Returns:
            Response data as dictionary with enhanced error information
        """
        try:
            url = f"{self.server_url}/{endpoint}"
            response = self.session.post(url, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            return {"success": False, "error": f"Request timed out after {self.timeout} seconds", "timeout": True}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Connection error - server may be down", "connection_error": True}
        except requests.exceptions.HTTPError as e:
            return {"success": False, "error": f"HTTP error: {e.response.status_code}", "http_error": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

# Global client instance
hexstrike_client = None

# Initialize FastMCP
mcp = FastMCP("HexStrike Prometheus - Essential Security Tools")

@mcp.tool()
def health_check() -> Dict[str, Any]:
    """
    Check the health status of the HexStrike AI API Server.
    
    Returns:
        Server health information
    """
    logger.info("🏥 Checking HexStrike AI server health")
    result = hexstrike_client.safe_get("health")
    
    # Check if we got a successful response or if the server responded at all
    if result.get("status") == "healthy" or result.get("success") or "version" in result:
        logger.info("✅ HexStrike AI server is healthy")
        # Ensure we return a success indicator
        result["success"] = True
    else:
        logger.error("❌ HexStrike AI server health check failed")
        # Add success=False if not present
        if "success" not in result:
            result["success"] = False
    
    return result

# ============================================================================
# CORE NETWORK SCANNING TOOLS
# ============================================================================

@mcp.tool()
def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute an enhanced Nmap scan against a target with real-time logging.

    Args:
        target: The IP address or hostname to scan
        scan_type: Scan type (e.g., -sV for version detection, -sC for scripts)
        ports: Comma-separated list of ports or port ranges
        additional_args: Additional Nmap arguments

    Returns:
        Scan results with enhanced telemetry
    """
    data = {
        "target": target,
        "scan_type": scan_type,
        "ports": ports,
        "additional_args": additional_args
    }
    logger.info(f"{HexStrikeColors.FIRE_RED}🔍 Initiating Nmap scan: {target}{HexStrikeColors.RESET}")

    # Use enhanced error handling by default
    data["use_recovery"] = True
    result = hexstrike_client.safe_post("api/tools/nmap", data)

    if result.get("success"):
        logger.info(f"{HexStrikeColors.SUCCESS}✅ Nmap scan completed successfully for {target}{HexStrikeColors.RESET}")

        # Check for recovery information
        if result.get("recovery_info", {}).get("recovery_applied"):
            recovery_info = result["recovery_info"]
            attempts = recovery_info.get("attempts_made", 1)
            logger.info(f"{HexStrikeColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {HexStrikeColors.RESET}")
    else:
        logger.error(f"{HexStrikeColors.ERROR}❌ Nmap scan failed for {target}{HexStrikeColors.RESET}")

        # Check for human escalation
        if result.get("human_escalation"):
            logger.error(f"{HexStrikeColors.CRITICAL} HUMAN ESCALATION REQUIRED {HexStrikeColors.RESET}")

    return result

@mcp.tool()
def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Gobuster to find directories, DNS subdomains, or virtual hosts with enhanced logging.

    Args:
        url: The target URL
        mode: Scan mode (dir, dns, fuzz, vhost)
        wordlist: Path to wordlist file
        additional_args: Additional Gobuster arguments

    Returns:
        Scan results with enhanced telemetry
    """
    data = {
        "url": url,
        "mode": mode,
        "wordlist": wordlist,
        "additional_args": additional_args
    }
    logger.info(f"{HexStrikeColors.CRIMSON}📁 Starting Gobuster {mode} scan: {url}{HexStrikeColors.RESET}")

    # Use enhanced error handling by default
    data["use_recovery"] = True
    result = hexstrike_client.safe_post("api/tools/gobuster", data)

    if result.get("success"):
        logger.info(f"{HexStrikeColors.SUCCESS}✅ Gobuster scan completed for {url}{HexStrikeColors.RESET}")

        # Check for recovery information
        if result.get("recovery_info", {}).get("recovery_applied"):
            recovery_info = result["recovery_info"]
            attempts = recovery_info.get("attempts_made", 1)
            logger.info(f"{HexStrikeColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {HexStrikeColors.RESET}")
    else:
        logger.error(f"{HexStrikeColors.ERROR}❌ Gobuster scan failed for {url}{HexStrikeColors.RESET}")

        # Check for alternative tool suggestion
        if result.get("alternative_tool_suggested"):
            alt_tool = result["alternative_tool_suggested"]
            logger.info(f"{HexStrikeColors.HIGHLIGHT_BLUE} Alternative tool suggested: {alt_tool} {HexStrikeColors.RESET}")

    return result

@mcp.tool()
def nuclei_scan(target: str, severity: str = "", tags: str = "", template: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Nuclei vulnerability scanner with enhanced logging and real-time progress.

    Args:
        target: The target URL or IP
        severity: Filter by severity (critical,high,medium,low,info)
        tags: Filter by tags (e.g. cve,rce,lfi)
        template: Custom template path
        additional_args: Additional Nuclei arguments

    Returns:
        Vulnerability scan results with enhanced telemetry
    """
    data = {
        "target": target,
        "severity": severity,
        "tags": tags,
        "template": template,
        "additional_args": additional_args
    }
    logger.info(f"{HexStrikeColors.SCARLET}🧨 Starting Nuclei vulnerability scan: {target}{HexStrikeColors.RESET}")

    # Use enhanced error handling by default
    data["use_recovery"] = True
    result = hexstrike_client.safe_post("api/tools/nuclei", data)

    if result.get("success"):
        logger.info(f"{HexStrikeColors.SUCCESS}✅ Nuclei scan completed for {target}{HexStrikeColors.RESET}")

        # Check for recovery information
        if result.get("recovery_info", {}).get("recovery_applied"):
            recovery_info = result["recovery_info"]
            attempts = recovery_info.get("attempts_made", 1)
            logger.info(f"{HexStrikeColors.HIGHLIGHT_YELLOW} Recovery applied: {attempts} attempts made {HexStrikeColors.RESET}")
    else:
        logger.error(f"{HexStrikeColors.ERROR}❌ Nuclei scan failed for {target}{HexStrikeColors.RESET}")

    return result

# ============================================================================
# FILE OPERATIONS & PAYLOAD GENERATION
# ============================================================================

@mcp.tool()
def create_file(file_path: str, content: str, encoding: str = "utf-8") -> Dict[str, Any]:
    """
    Create a file with specified content on the HexStrike server.

    Args:
        file_path: Path where the file should be created
        content: Content to write to the file
        encoding: File encoding (default: utf-8)

    Returns:
        File creation result
    """
    data = {
        "file_path": file_path,
        "content": content,
        "encoding": encoding
    }
    logger.info(f"📝 Creating file: {file_path}")
    result = hexstrike_client.safe_post("api/files/create", data)

    if result.get("success"):
        logger.info(f"✅ File created successfully: {file_path}")
    else:
        logger.error(f"❌ Failed to create file: {file_path}")

    return result

@mcp.tool()
def modify_file(file_path: str, content: str, encoding: str = "utf-8") -> Dict[str, Any]:
    """
    Modify an existing file on the HexStrike server.

    Args:
        file_path: Path to the file to modify
        content: New content for the file
        encoding: File encoding (default: utf-8)

    Returns:
        File modification result
    """
    data = {
        "file_path": file_path,
        "content": content,
        "encoding": encoding
    }
    logger.info(f"✏️  Modifying file: {file_path}")
    result = hexstrike_client.safe_post("api/files/modify", data)

    if result.get("success"):
        logger.info(f"✅ File modified successfully: {file_path}")
    else:
        logger.error(f"❌ Failed to modify file: {file_path}")

    return result

@mcp.tool()
def delete_file(file_path: str) -> Dict[str, Any]:
    """
    Delete a file or directory on the HexStrike server.

    Args:
        file_path: Path to the file or directory to delete

    Returns:
        Deletion result
    """
    data = {"file_path": file_path}
    logger.info(f"🗑️  Deleting file: {file_path}")
    result = hexstrike_client.safe_post("api/files/delete", data)

    if result.get("success"):
        logger.info(f"✅ File deleted successfully: {file_path}")
    else:
        logger.error(f"❌ Failed to delete file: {file_path}")

    return result

@mcp.tool()
def list_files(directory: str = "/tmp", pattern: str = "*") -> Dict[str, Any]:
    """
    List files in a directory on the HexStrike server.

    Args:
        directory: Directory to list files from
        pattern: File pattern to match (supports wildcards)

    Returns:
        List of files and directories
    """
    data = {
        "directory": directory,
        "pattern": pattern
    }
    logger.info(f"📂 Listing files in: {directory}")
    result = hexstrike_client.safe_post("api/files/list", data)

    if result.get("success"):
        file_count = len(result.get("files", []))
        logger.info(f"✅ Found {file_count} files in {directory}")
    else:
        logger.error(f"❌ Failed to list files in: {directory}")

    return result

@mcp.tool()
def generate_payload(payload_type: str = "reverse_shell", target_ip: str = "", target_port: int = 4444, 
                    format: str = "python", additional_options: str = "") -> Dict[str, Any]:
    """
    Generate large payloads for testing and exploitation with enhanced options.

    Args:
        payload_type: Type of payload (reverse_shell, bind_shell, web_shell, etc.)
        target_ip: Target IP address for connection back
        target_port: Target port for connection
        format: Payload format (python, bash, powershell, php, etc.)
        additional_options: Additional payload generation options

    Returns:
        Generated payload with metadata
    """
    data = {
        "payload_type": payload_type,
        "target_ip": target_ip,
        "target_port": target_port,
        "format": format,
        "additional_options": additional_options
    }
    logger.info(f"🎯 Generating {payload_type} payload in {format} format")
    result = hexstrike_client.safe_post("api/payloads/generate", data)

    if result.get("success"):
        logger.info(f"✅ Payload generated successfully")
    else:
        logger.error(f"❌ Payload generation failed")

    return result

# ============================================================================
# WEB APPLICATION SECURITY TOOLS
# ============================================================================

@mcp.tool()
def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Dirb for directory brute forcing with enhanced logging.

    Args:
        url: Target URL to scan
        wordlist: Path to wordlist file
        additional_args: Additional Dirb arguments

    Returns:
        Directory brute force results
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "additional_args": additional_args
    }
    logger.info(f"📁 Starting Dirb directory scan: {url}")
    result = hexstrike_client.safe_post("api/tools/dirb", data)

    if result.get("success"):
        logger.info(f"✅ Dirb scan completed for {url}")
    else:
        logger.error(f"❌ Dirb scan failed for {url}")

    return result

# @mcp.tool()
# def nikto_scan(target: str, port: int = 80, ssl: bool = False, additional_args: str = "") -> Dict[str, Any]:
#     """
#     Execute Nikto web vulnerability scanner with enhanced logging.

#     Args:
#         target: Target hostname or IP
#         port: Target port
#         ssl: Use SSL/HTTPS
#         additional_args: Additional Nikto arguments

#     Returns:
#         Web vulnerability scan results
#     """
#     data = {
#         "target": target,
#         "port": port,
#         "ssl": ssl,
#         "additional_args": additional_args
#     }
#     logger.info(f"🕷️  Starting Nikto web scan: {target}:{port}")
#     result = hexstrike_client.safe_post("api/tools/nikto", data)

#     if result.get("success"):
#         logger.info(f"✅ Nikto scan completed for {target}")
#     else:
#         logger.error(f"❌ Nikto scan failed for {target}")

#     return result

@mcp.tool()
def sqlmap_scan(target: str, data: str = "", cookie: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute SQLMap for SQL injection testing with enhanced logging.

    Args:
        target: Target URL
        data: POST data for testing
        cookie: Cookie header for authentication
        additional_args: Additional SQLMap arguments

    Returns:
        SQL injection test results
    """
    data_payload = {
        "target": target,
        "data": data,
        "cookie": cookie,
        "additional_args": additional_args
    }
    logger.info(f"💉 Starting SQLMap scan: {target}")
    result = hexstrike_client.safe_post("api/tools/sqlmap", data_payload)

    if result.get("success"):
        logger.info(f"✅ SQLMap scan completed for {target}")
    else:
        logger.error(f"❌ SQLMap scan failed for {target}")

    return result

# ============================================================================
# EXPLOITATION TOOLS
# ============================================================================

@mcp.tool()
def metasploit_run(exploit: str, target: str, payload: str = "", options: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute a Metasploit module with enhanced logging.

    Args:
        exploit: Metasploit exploit module to use
        target: Target IP or hostname
        payload: Payload to use with the exploit
        options: Additional module options
        additional_args: Additional Metasploit arguments

    Returns:
        Exploitation results
    """
    data = {
        "exploit": exploit,
        "target": target,
        "payload": payload,
        "options": options,
        "additional_args": additional_args
    }
    logger.info(f"💥 Executing Metasploit exploit: {exploit} against {target}")
    result = hexstrike_client.safe_post("api/tools/metasploit", data)

    if result.get("success"):
        logger.info(f"✅ Metasploit execution completed")
    else:
        logger.error(f"❌ Metasploit execution failed")

    return result

@mcp.tool()
def msfvenom_generate(payload: str, lhost: str = "", lport: int = 4444, format: str = "exe", 
                     output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute MSFVenom for payload generation with enhanced logging.

    Args:
        payload: MSFVenom payload to generate
        lhost: Local host for reverse connections
        lport: Local port for reverse connections
        format: Output format (exe, elf, raw, etc.)
        output_file: Output file path
        additional_args: Additional MSFVenom arguments

    Returns:
        Payload generation results
    """
    data = {
        "payload": payload,
        "lhost": lhost,
        "lport": lport,
        "format": format,
        "output_file": output_file,
        "additional_args": additional_args
    }
    logger.info(f"🎯 Generating MSFVenom payload: {payload}")
    result = hexstrike_client.safe_post("api/tools/msfvenom", data)

    if result.get("success"):
        logger.info(f"✅ MSFVenom payload generated successfully")
    else:
        logger.error(f"❌ MSFVenom payload generation failed")

    return result

# ============================================================================
# PASSWORD ATTACK TOOLS  
# ============================================================================

@mcp.tool()
def hydra_attack(target: str, service: str, username: str = "", password: str = "", 
                userlist: str = "", passlist: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Hydra for password brute forcing with enhanced logging.

    Args:
        target: Target IP or hostname
        service: Service to attack (ssh, ftp, http, etc.)
        username: Single username to test
        password: Single password to test
        userlist: Path to username list
        passlist: Path to password list
        additional_args: Additional Hydra arguments

    Returns:
        Password attack results
    """
    data = {
        "target": target,
        "service": service,
        "username": username,
        "password": password,
        "userlist": userlist,
        "passlist": passlist,
        "additional_args": additional_args
    }
    logger.info(f"🔓 Starting Hydra attack on {service} service: {target}")
    result = hexstrike_client.safe_post("api/tools/hydra", data)

    if result.get("success"):
        logger.info(f"✅ Hydra attack completed")
    else:
        logger.error(f"❌ Hydra attack failed")

    return result

@mcp.tool()
def john_crack(hash_file: str, wordlist: str = "", format: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute John the Ripper for password cracking with enhanced logging.

    Args:
        hash_file: Path to file containing password hashes
        wordlist: Path to wordlist file
        format: Hash format (if known)
        additional_args: Additional John arguments

    Returns:
        Password cracking results
    """
    data = {
        "hash_file": hash_file,
        "wordlist": wordlist,
        "format": format,
        "additional_args": additional_args
    }
    logger.info(f"🔨 Starting John the Ripper password cracking")
    result = hexstrike_client.safe_post("api/tools/john", data)

    if result.get("success"):
        logger.info(f"✅ John the Ripper completed")
    else:
        logger.error(f"❌ John the Ripper failed")

    return result

@mcp.tool()
def hashcat_crack(hash_file: str, attack_mode: int = 0, wordlist: str = "", 
                 hash_type: int = 0, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Hashcat for advanced password cracking with enhanced logging.

    Args:
        hash_file: Path to file containing password hashes
        attack_mode: Hashcat attack mode (0=dictionary, 3=brute-force, etc.)
        wordlist: Path to wordlist file
        hash_type: Hash type number
        additional_args: Additional Hashcat arguments

    Returns:
        Advanced password cracking results
    """
    data = {
        "hash_file": hash_file,
        "attack_mode": attack_mode,
        "wordlist": wordlist,
        "hash_type": hash_type,
        "additional_args": additional_args
    }
    logger.info(f"⚡ Starting Hashcat password cracking")
    result = hexstrike_client.safe_post("api/tools/hashcat", data)

    if result.get("success"):
        logger.info(f"✅ Hashcat completed")
    else:
        logger.error(f"❌ Hashcat failed")

    return result

# ============================================================================
# NETWORK PENETRATION TESTING TOOLS
# ============================================================================

@mcp.tool()
def enum4linux_scan(target: str, username: str = "", password: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Enum4linux for SMB enumeration with enhanced logging.

    Args:
        target: Target IP address
        username: Username for authenticated enumeration
        password: Password for authenticated enumeration
        additional_args: Additional Enum4linux arguments

    Returns:
        SMB enumeration results
    """
    data = {
        "target": target,
        "username": username,
        "password": password,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Enum4linux SMB enumeration: {target}")
    result = hexstrike_client.safe_post("api/tools/enum4linux", data)

    if result.get("success"):
        logger.info(f"✅ Enum4linux scan completed for {target}")
    else:
        logger.error(f"❌ Enum4linux scan failed for {target}")

    return result

@mcp.tool()
def ffuf_scan(url: str, wordlist: str, method: str = "GET", data: str = "", 
             headers: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute FFuf for web fuzzing with enhanced logging.

    Args:
        url: Target URL with FUZZ keyword
        wordlist: Path to wordlist file
        method: HTTP method to use
        data: POST data (if applicable)
        headers: Additional HTTP headers
        additional_args: Additional FFuf arguments

    Returns:
        Web fuzzing results
    """
    data_payload = {
        "url": url,
        "wordlist": wordlist,
        "method": method,
        "data": data,
        "headers": headers,
        "additional_args": additional_args
    }
    logger.info(f"🎯 Starting FFuf fuzzing: {url}")
    result = hexstrike_client.safe_post("api/tools/ffuf", data_payload)

    if result.get("success"):
        logger.info(f"✅ FFuf scan completed")
    else:
        logger.error(f"❌ FFuf scan failed")

    return result

@mcp.tool()
def netexec_scan(target: str, protocol: str = "smb", username: str = "", password: str = "", 
                domain: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute NetExec (formerly CrackMapExec) for network enumeration and exploitation.

    Args:
        target: Target IP, range, or hostname
        protocol: Protocol to use (smb, ssh, winrm, etc.)
        username: Username for authentication
        password: Password for authentication
        domain: Domain for authentication
        additional_args: Additional NetExec arguments

    Returns:
        Network enumeration and exploitation results
    """
    data = {
        "target": target,
        "protocol": protocol,
        "username": username,
        "password": password,
        "domain": domain,
        "additional_args": additional_args
    }
    logger.info(f"🌐 Starting NetExec {protocol} scan: {target}")
    result = hexstrike_client.safe_post("api/tools/netexec", data)

    if result.get("success"):
        logger.info(f"✅ NetExec scan completed for {target}")
    else:
        logger.error(f"❌ NetExec scan failed for {target}")

    return result

# ============================================================================
# ENHANCED SCANNING TOOLS
# ============================================================================

@mcp.tool()
def amass_scan(domain: str, brute: bool = False, passive: bool = True, 
              wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Amass for subdomain enumeration with enhanced logging.

    Args:
        domain: Target domain to enumerate
        brute: Enable brute force enumeration
        passive: Enable passive enumeration
        wordlist: Custom wordlist for brute forcing
        additional_args: Additional Amass arguments

    Returns:
        Subdomain enumeration results
    """
    data = {
        "domain": domain,
        "brute": brute,
        "passive": passive,
        "wordlist": wordlist,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Amass subdomain enumeration: {domain}")
    result = hexstrike_client.safe_post("api/tools/amass", data)

    if result.get("success"):
        logger.info(f"✅ Amass enumeration completed for {domain}")
    else:
        logger.error(f"❌ Amass enumeration failed for {domain}")

    return result

@mcp.tool()
def subfinder_scan(domain: str, sources: str = "", silent: bool = False, 
                  additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Subfinder for passive subdomain enumeration with enhanced logging.

    Args:
        domain: Target domain to enumerate
        sources: Comma-separated list of sources to use
        silent: Enable silent mode
        additional_args: Additional Subfinder arguments

    Returns:
        Passive subdomain enumeration results
    """
    data = {
        "domain": domain,
        "sources": sources,
        "silent": silent,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Subfinder passive enumeration: {domain}")
    result = hexstrike_client.safe_post("api/tools/subfinder", data)

    if result.get("success"):
        logger.info(f"✅ Subfinder enumeration completed for {domain}")
    else:
        logger.error(f"❌ Subfinder enumeration failed for {domain}")

    return result

@mcp.tool()
def smbmap_scan(host: str, username: str = "", password: str = "", domain: str = "", 
               additional_args: str = "") -> Dict[str, Any]:
    """
    Execute SMBMap for SMB share enumeration with enhanced logging.

    Args:
        host: Target hostname or IP
        username: Username for authentication
        password: Password for authentication  
        domain: Domain for authentication
        additional_args: Additional SMBMap arguments

    Returns:
        SMB share enumeration results
    """
    data = {
        "host": host,
        "username": username,
        "password": password,
        "domain": domain,
        "additional_args": additional_args
    }
    logger.info(f"📂 Starting SMBMap enumeration: {host}")
    result = hexstrike_client.safe_post("api/tools/smbmap", data)

    if result.get("success"):
        logger.info(f"✅ SMBMap enumeration completed for {host}")
    else:
        logger.error(f"❌ SMBMap enumeration failed for {host}")

    return result

@mcp.tool()
def rustscan_fast_scan(target: str, ports: str = "1-65535", ulimit: int = 5000, 
                      additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Rustscan for ultra-fast port scanning with enhanced logging.

    Args:
        target: Target IP or hostname
        ports: Port range or list (default: all ports)
        ulimit: Ulimit value for speed
        additional_args: Additional Rustscan arguments

    Returns:
        Ultra-fast port scan results
    """
    data = {
        "target": target,
        "ports": ports,
        "ulimit": ulimit,
        "additional_args": additional_args
    }
    logger.info(f"⚡ Starting Rustscan fast port scan: {target}")
    result = hexstrike_client.safe_post("api/tools/rustscan", data)

    if result.get("success"):
        logger.info(f"✅ Rustscan completed for {target}")
    else:
        logger.error(f"❌ Rustscan failed for {target}")

    return result

@mcp.tool()
def masscan_high_speed(target: str, ports: str = "1-65535", rate: int = 1000, 
                      additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Masscan for high-speed Internet-scale port scanning.

    Args:
        target: Target IP, range, or subnet
        ports: Port range to scan
        rate: Packets per second rate
        additional_args: Additional Masscan arguments

    Returns:
        High-speed port scan results
    """
    data = {
        "target": target,
        "ports": ports,
        "rate": rate,
        "additional_args": additional_args
    }
    logger.info(f"🚀 Starting Masscan high-speed scan: {target}")
    result = hexstrike_client.safe_post("api/tools/masscan", data)

    if result.get("success"):
        logger.info(f"✅ Masscan completed for {target}")
    else:
        logger.error(f"❌ Masscan failed for {target}")

    return result

@mcp.tool()
def wpscan_analyze(url: str, enumerate: str = "ap,at,cb,dbe", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute WPScan for WordPress vulnerability scanning with enhanced logging.

    Args:
        url: Target WordPress URL
        enumerate: What to enumerate (ap=All Plugins, at=All Themes, cb=Config Backups, dbe=Db Exports)
        additional_args: Additional WPScan arguments

    Returns:
        WordPress vulnerability scan results
    """
    data = {
        "url": url,
        "enumerate": enumerate,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting WPScan analysis: {url}")
    result = hexstrike_client.safe_post("api/tools/wpscan", data)

    if result.get("success"):
        logger.info(f"✅ WPScan analysis completed for {url}")
    else:
        logger.error(f"❌ WPScan analysis failed for {url}")

    return result

@mcp.tool()
def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                    extensions: str = "php,html,js,txt", threads: int = 50, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Feroxbuster for recursive content discovery with enhanced logging.

    Args:
        url: Target URL
        wordlist: Wordlist file to use
        extensions: File extensions to search for
        threads: Number of concurrent threads
        additional_args: Additional Feroxbuster arguments

    Returns:
        Recursive content discovery results
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "extensions": extensions,
        "threads": threads,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Feroxbuster recursive scan: {url}")
    result = hexstrike_client.safe_post("api/tools/feroxbuster", data)

    if result.get("success"):
        logger.info(f"✅ Feroxbuster scan completed for {url}")
    else:
        logger.error(f"❌ Feroxbuster scan failed for {url}")

    return result

@mcp.tool()
def dirsearch_scan(url: str, wordlist: str = "", extensions: str = "php,html,js,txt,asp,aspx,jsp", 
                  threads: int = 30, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Dirsearch for advanced directory and file discovery with enhanced logging.

    Args:
        url: Target URL
        wordlist: Custom wordlist (uses built-in if empty)
        extensions: File extensions to search for
        threads: Number of threads
        additional_args: Additional Dirsearch arguments

    Returns:
        Advanced directory and file discovery results
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "extensions": extensions,
        "threads": threads,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Dirsearch scan: {url}")
    result = hexstrike_client.safe_post("api/tools/dirsearch", data)

    if result.get("success"):
        logger.info(f"✅ Dirsearch scan completed for {url}")
    else:
        logger.error(f"❌ Dirsearch scan failed for {url}")

    return result

@mcp.tool()
def httpx_probe(target: str, ports: str = "80,443,8080,8443", follow_redirects: bool = True, 
               title: bool = True, tech_detect: bool = True, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute httpx for fast HTTP probing and technology detection with enhanced logging.

    Args:
        target: Target URL, domain, or file with targets
        ports: Comma-separated list of ports to probe
        follow_redirects: Follow HTTP redirects
        title: Extract page titles
        tech_detect: Detect technologies
        additional_args: Additional httpx arguments

    Returns:
        HTTP probing and technology detection results
    """
    data = {
        "target": target,
        "ports": ports,
        "follow_redirects": follow_redirects,
        "title": title,
        "tech_detect": tech_detect,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting httpx probe: {target}")
    result = hexstrike_client.safe_post("api/tools/httpx", data)

    if result.get("success"):
        logger.info(f"✅ httpx probe completed for {target}")
    else:
        logger.error(f"❌ httpx probe failed for {target}")

    return result

@mcp.tool()
def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
              hide_codes: str = "404", payload_type: str = "file", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Wfuzz for web application fuzzing with enhanced logging.

    Args:
        url: Target URL with FUZZ keyword
        wordlist: Wordlist file to use
        hide_codes: HTTP status codes to hide
        payload_type: Payload type (file, range, list, etc.)
        additional_args: Additional Wfuzz arguments

    Returns:
        Web application fuzzing results
    """
    data = {
        "url": url,
        "wordlist": wordlist,
        "hide_codes": hide_codes,
        "payload_type": payload_type,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Wfuzz scan: {url}")
    result = hexstrike_client.safe_post("api/tools/wfuzz", data)

    if result.get("success"):
        logger.info(f"✅ Wfuzz scan completed")
    else:
        logger.error(f"❌ Wfuzz scan failed")

    return result

@mcp.tool()
def arjun_scan(url: str, methods: str = "GET,POST", wordlist: str = "", 
              delay: int = 0, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Arjun for parameter discovery with enhanced logging.

    Args:
        url: Target URL
        methods: HTTP methods to test (GET,POST,etc.)
        wordlist: Custom parameter wordlist
        delay: Delay between requests in seconds
        additional_args: Additional Arjun arguments

    Returns:
        Parameter discovery results
    """
    data = {
        "url": url,
        "methods": methods,
        "wordlist": wordlist,
        "delay": delay,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Arjun parameter discovery: {url}")
    result = hexstrike_client.safe_post("api/tools/arjun", data)

    if result.get("success"):
        logger.info(f"✅ Arjun parameter discovery completed")
    else:
        logger.error(f"❌ Arjun parameter discovery failed")

    return result

@mcp.tool()
def waybackurls_discovery(domain: str, no_subs: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute waybackurls for discovering URLs from Wayback Machine with enhanced logging.

    Args:
        domain: Target domain
        no_subs: Don't include subdomains
        additional_args: Additional waybackurls arguments

    Returns:
        Wayback Machine URL discovery results
    """
    data = {
        "domain": domain,
        "no_subs": no_subs,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting waybackurls discovery: {domain}")
    result = hexstrike_client.safe_post("api/tools/waybackurls", data)

    if result.get("success"):
        logger.info(f"✅ waybackurls discovery completed for {domain}")
    else:
        logger.error(f"❌ waybackurls discovery failed for {domain}")

    return result

@mcp.tool()
def gau_discovery(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan", 
                 blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute gau (Get All URLs) for comprehensive URL discovery with enhanced logging.

    Args:
        domain: Target domain
        providers: Data providers to use
        blacklist: File extensions to exclude
        additional_args: Additional gau arguments

    Returns:
        Comprehensive URL discovery results
    """
    data = {
        "domain": domain,
        "providers": providers,
        "blacklist": blacklist,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting gau URL discovery: {domain}")
    result = hexstrike_client.safe_post("api/tools/gau", data)

    if result.get("success"):
        logger.info(f"✅ gau URL discovery completed for {domain}")
    else:
        logger.error(f"❌ gau URL discovery failed for {domain}")

    return result

@mcp.tool()
def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, 
                   linkfinder: bool = True, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute hakrawler for web crawling and endpoint discovery with enhanced logging.

    Args:
        url: Target URL to crawl
        depth: Crawling depth
        forms: Include form discovery
        linkfinder: Use linkfinder for JS endpoint discovery
        additional_args: Additional hakrawler arguments

    Returns:
        Web crawling and endpoint discovery results
    """
    data = {
        "url": url,
        "depth": depth,
        "forms": forms,
        "linkfinder": linkfinder,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting hakrawler crawl: {url}")
    result = hexstrike_client.safe_post("api/tools/hakrawler", data)

    if result.get("success"):
        logger.info(f"✅ hakrawler crawl completed for {url}")
    else:
        logger.error(f"❌ hakrawler crawl failed for {url}")

    return result

@mcp.tool()
def paramspider_discovery(domain: str, exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf", 
                         level: str = "high", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute ParamSpider for parameter mining from web archives with enhanced logging.

    Args:
        domain: Target domain
        exclude: File extensions to exclude
        level: Mining level (high, medium, low)
        additional_args: Additional ParamSpider arguments

    Returns:
        Parameter mining results from web archives
    """
    data = {
        "domain": domain,
        "exclude": exclude,
        "level": level,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting ParamSpider parameter mining: {domain}")
    result = hexstrike_client.safe_post("api/tools/paramspider", data)

    if result.get("success"):
        logger.info(f"✅ ParamSpider mining completed for {domain}")
    else:
        logger.error(f"❌ ParamSpider mining failed for {domain}")

    return result

@mcp.tool()
def katana_crawl(url: str, depth: int = 3, js_crawling: bool = True, 
                form_extraction: bool = True, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Katana for next-generation web crawling with enhanced logging.

    Args:
        url: Target URL to crawl
        depth: Maximum crawling depth
        js_crawling: Enable JavaScript crawling
        form_extraction: Extract forms
        additional_args: Additional Katana arguments

    Returns:
        Next-generation web crawling results
    """
    data = {
        "url": url,
        "depth": depth,
        "js_crawling": js_crawling,
        "form_extraction": form_extraction,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Katana crawl: {url}")
    result = hexstrike_client.safe_post("api/tools/katana", data)

    if result.get("success"):
        logger.info(f"✅ Katana crawl completed for {url}")
    else:
        logger.error(f"❌ Katana crawl failed for {url}")

    return result

# ============================================================================
# XSS AND INJECTION TESTING TOOLS
# ============================================================================

@mcp.tool()
def dalfox_xss_scan(url: str, data: str = "", cookie: str = "", 
                   blind: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging.

    Args:
        url: Target URL to scan
        data: POST data for testing
        cookie: Cookie header for authentication
        blind: Enable blind XSS testing
        additional_args: Additional Dalfox arguments

    Returns:
        Advanced XSS vulnerability scan results
    """
    data_payload = {
        "url": url,
        "data": data,
        "cookie": cookie,
        "blind": blind,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Dalfox XSS scan: {url}")
    result = hexstrike_client.safe_post("api/tools/dalfox", data_payload)

    if result.get("success"):
        logger.info(f"✅ Dalfox XSS scan completed")
    else:
        logger.error(f"❌ Dalfox XSS scan failed")

    return result

@mcp.tool()
def commix_injection_scan(url: str, data: str = "", cookie: str = "", 
                         technique: str = "classic,eval-based,time-based,file-based", 
                         additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Commix for command injection testing with enhanced logging.

    Args:
        url: Target URL to test
        data: POST data for testing
        cookie: Cookie header for authentication
        technique: Injection techniques to use
        additional_args: Additional Commix arguments

    Returns:
        Command injection testing results
    """
    data_payload = {
        "url": url,
        "data": data,
        "cookie": cookie,
        "technique": technique,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Commix injection scan: {url}")
    result = hexstrike_client.safe_post("api/tools/commix", data_payload)

    if result.get("success"):
        logger.info(f"✅ Commix injection scan completed")
    else:
        logger.error(f"❌ Commix injection scan failed")

    return result

# ============================================================================
# SHELL INTERACTION AND COMMAND EXECUTION
# ============================================================================

@mcp.tool()
def execute_command(command: str, timeout: int = 30, shell: bool = True) -> Dict[str, Any]:
    """
    Execute a system command on the HexStrike server with enhanced logging.

    Args:
        command: Command to execute
        timeout: Command timeout in seconds
        shell: Execute in shell context

    Returns:
        Command execution results
    """
    data = {
        "command": command,
        "timeout": timeout,
        "shell": shell
    }
    logger.info(f"💻 Executing command: {command[:50]}...")
    result = hexstrike_client.safe_post("api/system/execute", data)

    if result.get("success"):
        logger.info(f"✅ Command executed successfully")
    else:
        logger.error(f"❌ Command execution failed")

    return result

@mcp.tool()
def reverse_shell_listener(port: int = 4444, interface: str = "0.0.0.0", 
                          shell_type: str = "bash") -> Dict[str, Any]:
    """
    Start a reverse shell listener on the HexStrike server.

    Args:
        port: Port to listen on
        interface: Interface to bind to
        shell_type: Type of shell to expect (bash, sh, cmd, powershell)

    Returns:
        Reverse shell listener status
    """
    data = {
        "port": port,
        "interface": interface,
        "shell_type": shell_type
    }
    logger.info(f"🔗 Starting reverse shell listener on {interface}:{port}")
    result = hexstrike_client.safe_post("api/shells/listener", data)

    if result.get("success"):
        logger.info(f"✅ Reverse shell listener started")
    else:
        logger.error(f"❌ Failed to start reverse shell listener")

    return result

@mcp.tool()
def bind_shell_connect(target: str, port: int, shell_type: str = "bash") -> Dict[str, Any]:
    """
    Connect to a bind shell on a target system.

    Args:
        target: Target IP or hostname
        port: Port to connect to
        shell_type: Type of shell (bash, sh, cmd, powershell)

    Returns:
        Bind shell connection status
    """
    data = {
        "target": target,
        "port": port,
        "shell_type": shell_type
    }
    logger.info(f"🔗 Connecting to bind shell: {target}:{port}")
    result = hexstrike_client.safe_post("api/shells/bind", data)

    if result.get("success"):
        logger.info(f"✅ Connected to bind shell")
    else:
        logger.error(f"❌ Failed to connect to bind shell")

    return result

# ============================================================================
# BASIC LINUX TOOLING AND FILE OPERATIONS
# ============================================================================

@mcp.tool()
def read_file_content(file_path: str, lines: int = 0, encoding: str = "utf-8") -> Dict[str, Any]:
    """
    Read content from a file on the HexStrike server.

    Args:
        file_path: Path to the file to read
        lines: Number of lines to read (0 = all)
        encoding: File encoding

    Returns:
        File content
    """
    data = {
        "file_path": file_path,
        "lines": lines,
        "encoding": encoding
    }
    logger.info(f"📖 Reading file: {file_path}")
    result = hexstrike_client.safe_post("api/files/read", data)

    if result.get("success"):
        logger.info(f"✅ File read successfully")
    else:
        logger.error(f"❌ Failed to read file")

    return result

@mcp.tool()
def find_files(directory: str = "/", name_pattern: str = "", 
              file_type: str = "f", max_depth: int = 5) -> Dict[str, Any]:
    """
    Find files matching criteria on the HexStrike server.

    Args:
        directory: Directory to search in
        name_pattern: File name pattern (supports wildcards)
        file_type: File type (f=file, d=directory, l=symlink)
        max_depth: Maximum search depth

    Returns:
        List of matching files
    """
    data = {
        "directory": directory,
        "name_pattern": name_pattern,
        "file_type": file_type,
        "max_depth": max_depth
    }
    logger.info(f"🔍 Finding files in {directory} matching {name_pattern}")
    result = hexstrike_client.safe_post("api/files/find", data)

    if result.get("success"):
        file_count = len(result.get("files", []))
        logger.info(f"✅ Found {file_count} matching files")
    else:
        logger.error(f"❌ File search failed")

    return result

@mcp.tool()
def grep_search(pattern: str, file_path: str = "", directory: str = "", 
               recursive: bool = True, ignore_case: bool = False) -> Dict[str, Any]:
    """
    Search for patterns in files using grep on the HexStrike server.

    Args:
        pattern: Pattern to search for
        file_path: Specific file to search in
        directory: Directory to search in
        recursive: Search recursively
        ignore_case: Ignore case in search

    Returns:
        Grep search results
    """
    data = {
        "pattern": pattern,
        "file_path": file_path,
        "directory": directory,
        "recursive": recursive,
        "ignore_case": ignore_case
    }
    logger.info(f"🔍 Searching for pattern: {pattern}")
    result = hexstrike_client.safe_post("api/system/grep", data)

    if result.get("success"):
        logger.info(f"✅ Grep search completed")
    else:
        logger.error(f"❌ Grep search failed")

    return result

@mcp.tool()
def download_file(url: str, output_path: str = "", timeout: int = 60) -> Dict[str, Any]:
    """
    Download a file from a URL to the HexStrike server.

    Args:
        url: URL to download from
        output_path: Local path to save file (auto-generated if empty)
        timeout: Download timeout in seconds

    Returns:
        Download result
    """
    data = {
        "url": url,
        "output_path": output_path,
        "timeout": timeout
    }
    logger.info(f"⬇️ Downloading file from: {url}")
    result = hexstrike_client.safe_post("api/files/download", data)

    if result.get("success"):
        logger.info(f"✅ File downloaded successfully")
    else:
        logger.error(f"❌ File download failed")

    return result

@mcp.tool()
def upload_file(file_content: str, remote_path: str, encoding: str = "utf-8") -> Dict[str, Any]:
    """
    Upload file content to the HexStrike server.

    Args:
        file_content: Content to upload
        remote_path: Remote path to save the file
        encoding: File encoding

    Returns:
        Upload result
    """
    data = {
        "file_content": file_content,
        "remote_path": remote_path,
        "encoding": encoding
    }
    logger.info(f"⬆️ Uploading file to: {remote_path}")
    result = hexstrike_client.safe_post("api/files/upload", data)

    if result.get("success"):
        logger.info(f"✅ File uploaded successfully")
    else:
        logger.error(f"❌ File upload failed")

    return result

@mcp.tool()
def base64_encode(input_string: str) -> Dict[str, Any]:
    """
    Encode a string to base64.

    Args:
        input_string: String to encode

    Returns:
        Base64 encoded string
    """
    data = {"input_string": input_string}
    logger.info(f"🔐 Encoding string to base64")
    result = hexstrike_client.safe_post("api/utils/base64encode", data)

    if result.get("success"):
        logger.info(f"✅ Base64 encoding completed")
    else:
        logger.error(f"❌ Base64 encoding failed")

    return result

@mcp.tool()
def base64_decode(encoded_string: str) -> Dict[str, Any]:
    """
    Decode a base64 string.

    Args:
        encoded_string: Base64 string to decode

    Returns:
        Decoded string
    """
    data = {"encoded_string": encoded_string}
    logger.info(f"🔓 Decoding base64 string")
    result = hexstrike_client.safe_post("api/utils/base64decode", data)

    if result.get("success"):
        logger.info(f"✅ Base64 decoding completed")
    else:
        logger.error(f"❌ Base64 decoding failed")

    return result

@mcp.tool()
def url_encode(input_string: str) -> Dict[str, Any]:
    """
    URL encode a string.

    Args:
        input_string: String to URL encode

    Returns:
        URL encoded string
    """
    data = {"input_string": input_string}
    logger.info(f"🔗 URL encoding string")
    result = hexstrike_client.safe_post("api/utils/urlencode", data)

    if result.get("success"):
        logger.info(f"✅ URL encoding completed")
    else:
        logger.error(f"❌ URL encoding failed")

    return result

@mcp.tool()
def url_decode(encoded_string: str) -> Dict[str, Any]:
    """
    URL decode a string.

    Args:
        encoded_string: URL encoded string to decode

    Returns:
        Decoded string
    """
    data = {"encoded_string": encoded_string}
    logger.info(f"🔗 URL decoding string")
    result = hexstrike_client.safe_post("api/utils/urldecode", data)

    if result.get("success"):
        logger.info(f"✅ URL decoding completed")
    else:
        logger.error(f"❌ URL decoding failed")

    return result

# ============================================================================
# ADVANCED WEB TESTING TOOLS
# ============================================================================

@mcp.tool()
def burpsuite_scan(url: str, scan_type: str = "crawl_and_audit", 
                  login_url: str = "", credentials: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute Burp Suite-style web application scan with enhanced logging.

    Args:
        url: Target URL to scan
        scan_type: Type of scan (crawl_and_audit, crawl_only, audit_only)
        login_url: URL for authentication
        credentials: Login credentials (username:password)
        additional_args: Additional scan arguments

    Returns:
        Comprehensive web application scan results
    """
    data = {
        "url": url,
        "scan_type": scan_type,
        "login_url": login_url,
        "credentials": credentials,
        "additional_args": additional_args
    }
    logger.info(f"🔍 Starting Burp Suite-style scan: {url}")
    result = hexstrike_client.safe_post("api/tools/burpsuite", data)

    if result.get("success"):
        logger.info(f"✅ Burp Suite scan completed")
    else:
        logger.error(f"❌ Burp Suite scan failed")

    return result

@mcp.tool()
def jwt_analyzer(token: str, wordlist: str = "", crack_secret: bool = False) -> Dict[str, Any]:
    """
    Analyze and test JWT tokens for vulnerabilities.

    Args:
        token: JWT token to analyze
        wordlist: Wordlist for secret cracking
        crack_secret: Attempt to crack JWT secret

    Returns:
        JWT analysis and vulnerability results
    """
    data = {
        "token": token,
        "wordlist": wordlist,
        "crack_secret": crack_secret
    }
    logger.info(f"🔍 Analyzing JWT token")
    result = hexstrike_client.safe_post("api/tools/jwt", data)

    if result.get("success"):
        logger.info(f"✅ JWT analysis completed")
    else:
        logger.error(f"❌ JWT analysis failed")

    return result

@mcp.tool()
def install_python_package(package_name: str, version: str = "", use_pip3: bool = True) -> Dict[str, Any]:
    """
    Install a Python package in a virtual environment on the HexStrike server.

    Args:
        package_name: Name of the Python package to install
        version: Specific version to install (optional)
        use_pip3: Use pip3 instead of pip

    Returns:
        Package installation result
    """
    data = {
        "package_name": package_name,
        "version": version,
        "use_pip3": use_pip3
    }
    logger.info(f"📦 Installing Python package: {package_name}")
    result = hexstrike_client.safe_post("api/python/install", data)

    if result.get("success"):
        logger.info(f"✅ Package installed successfully: {package_name}")
    else:
        logger.error(f"❌ Failed to install package: {package_name}")

    return result

@mcp.tool()
def execute_python_script(script_content: str, script_args: str = "", timeout: int = 300) -> Dict[str, Any]:
    """
    Execute a Python script in a virtual environment on the HexStrike server.

    Args:
        script_content: Python script content to execute
        script_args: Command line arguments for the script
        timeout: Execution timeout in seconds

    Returns:
        Script execution result
    """
    data = {
        "script_content": script_content,
        "script_args": script_args,
        "timeout": timeout
    }
    logger.info(f"🐍 Executing Python script")
    result = hexstrike_client.safe_post("api/python/execute", data)

    if result.get("success"):
        logger.info(f"✅ Python script executed successfully")
    else:
        logger.error(f"❌ Python script execution failed")

    return result

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point for the HexStrike Prometheus MCP client"""
    global hexstrike_client
    
    parser = argparse.ArgumentParser(description="HexStrike Prometheus - Filtered MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_HEXSTRIKE_SERVER,
                       help=f"HexStrike server URL (default: {DEFAULT_HEXSTRIKE_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                       help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize the HexStrike client
    hexstrike_client = HexStrikeClient(args.server, args.timeout)
    
    logger.info("🚀 Starting HexStrike Prometheus MCP Client v1.0")
    logger.info(f"🔗 Connecting to: {args.server}")
    
    # Check server connection
    health_result = hexstrike_client.safe_get("health")
    if health_result.get("success"):
        logger.info(f"🎯 Successfully connected to HexStrike AI API server at {args.server}")
        logger.info(f"🏥 Server health status: {health_result.get('status', 'unknown')}")
        logger.info(f"📊 Version: {health_result.get('version', 'unknown')}")
    else:
        logger.warning(f"⚠️  Could not verify server health, but continuing anyway")
    
    logger.info("🚀 Starting HexStrike Prometheus MCP server")
    logger.info("🤖 Ready to serve AI agents with essential cybersecurity capabilities")
    logger.info("📊 Tool count optimized for OpenAI API compatibility (<128 tools)")
    
    # Run the MCP server
    mcp.run()

if __name__ == "__main__":
    main()
