#!/usr/bin/env python3
"""
HexStrike AI MCP - Execution & Credential Access Specialist
MITRE ATT&CK Tactics: Execution (TA0002) & Credential Access (TA0006)

Focused on code execution and credential harvesting operations.
"""

import asyncio
import json
import subprocess
import sys
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP("HexStrike Execution & Credential Access Specialist")

class ExecutionCredentialEngine:
    """Enhanced execution and credential access engine."""
    
    def __init__(self):
        self.executions_performed = 0
        self.credentials_harvested = 0
        self.successful_cracks = 0
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute system command with error handling."""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=600
            )
            
            return {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Command timed out", "command": command}
        except Exception as e:
            return {"error": str(e), "command": command}

# Global execution and credential engine instance
exec_cred_engine = ExecutionCredentialEngine()

# ============================================================================
# EXECUTION TOOLS - MITRE ATT&CK TA0002
# ============================================================================

@mcp.tool()
def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
    """
    Execute Metasploit modules for exploitation and post-exploitation.
    
    Args:
        module: Metasploit module path
        options: Module options dictionary
    
    Returns:
        Metasploit execution results
    """
    # Build msfconsole command
    commands = [f"use {module}"]
    
    for key, value in options.items():
        commands.append(f"set {key} {value}")
    
    commands.append("run")
    commands.append("exit")
    
    msfconsole_script = "; ".join(commands)
    command = f"msfconsole -q -x '{msfconsole_script}'"
    
    exec_cred_engine.executions_performed += 1
    result = exec_cred_engine.execute_command(command)
    
    return {
        "tool": "metasploit",
        "module": module,
        "options": options,
        "command_executed": command,
        "result": result,
        "tactic": "execution",
        "technique": "T1059.001 - Command and Scripting Interpreter: PowerShell"
    }

@mcp.tool()
def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Execute system commands for various operations.
    
    Args:
        command: System command to execute
        use_cache: Whether to use command caching
    
    Returns:
        Command execution results
    """
    exec_cred_engine.executions_performed += 1
    result = exec_cred_engine.execute_command(command)
    
    return {
        "tool": "command_executor",
        "command_executed": command,
        "use_cache": use_cache,
        "result": result,
        "tactic": "execution",
        "technique": "T1059 - Command and Scripting Interpreter"
    }

@mcp.tool()
def http_repeater(request_spec: dict) -> Dict[str, Any]:
    """
    HTTP request manipulation and replay for web application testing.
    
    Args:
        request_spec: HTTP request specification dictionary
    
    Returns:
        HTTP request execution results
    """
    method = request_spec.get("method", "GET")
    url = request_spec.get("url", "")
    headers = request_spec.get("headers", {})
    data = request_spec.get("data", "")
    
    # Build curl command
    header_args = []
    for key, value in headers.items():
        header_args.append(f"-H '{key}: {value}'")
    
    if method.upper() == "POST" and data:
        command = f"curl -X {method} {' '.join(header_args)} -d '{data}' '{url}'"
    else:
        command = f"curl -X {method} {' '.join(header_args)} '{url}'"
    
    exec_cred_engine.executions_performed += 1
    result = exec_cred_engine.execute_command(command)
    
    return {
        "tool": "http_repeater",
        "request_spec": request_spec,
        "command_executed": command,
        "result": result,
        "tactic": "execution",
        "technique": "T1071.001 - Application Layer Protocol: Web Protocols"
    }

# ============================================================================
# CREDENTIAL ACCESS TOOLS - MITRE ATT&CK TA0006
# ============================================================================

@mcp.tool()
def hashcat_crack(hash_file: str, hash_type: str, attack_mode: str = "0", wordlist: str = "/usr/share/wordlists/rockyou.txt", mask: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Password hash cracking using Hashcat.
    
    Args:
        hash_file: File containing password hashes
        hash_type: Hash type identifier (e.g., 1000 for NTLM)
        attack_mode: Attack mode (0=dictionary, 3=mask, etc.)
        wordlist: Wordlist file for dictionary attacks
        mask: Mask for mask attacks
        additional_args: Additional Hashcat arguments
    
    Returns:
        Hash cracking results
    """
    if attack_mode == "3" and mask:
        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file} '{mask}' {additional_args}"
    else:
        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file} {wordlist} {additional_args}"
    
    exec_cred_engine.executions_performed += 1
    result = exec_cred_engine.execute_command(command)
    
    # Check for successful cracks
    if result.get("success") and "Cracked" in result.get("stdout", ""):
        exec_cred_engine.successful_cracks += 1
        exec_cred_engine.credentials_harvested += 1
    
    return {
        "tool": "hashcat",
        "hash_file": hash_file,
        "hash_type": hash_type,
        "attack_mode": attack_mode,
        "wordlist": wordlist,
        "mask": mask,
        "command_executed": command,
        "result": result,
        "tactic": "credential_access",
        "technique": "T1110.002 - Brute Force: Password Cracking"
    }

@mcp.tool()
def jwt_analyzer(jwt_token: str, target_url: str = "") -> Dict[str, Any]:
    """
    JWT token security analysis and manipulation.
    
    Args:
        jwt_token: JWT token to analyze
        target_url: Target URL for testing
    
    Returns:
        JWT analysis results and security findings
    """
    # Decode JWT header and payload
    try:
        import base64
        import json as json_lib
        
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return {
                "tool": "jwt_analyzer",
                "error": "Invalid JWT format",
                "tactic": "credential_access"
            }
        
        # Decode header
        header_padding = '=' * (4 - len(parts[0]) % 4)
        header = json_lib.loads(base64.urlsafe_b64decode(parts[0] + header_padding))
        
        # Decode payload
        payload_padding = '=' * (4 - len(parts[1]) % 4)
        payload = json_lib.loads(base64.urlsafe_b64decode(parts[1] + payload_padding))
        
        # Security analysis
        security_issues = []
        
        if header.get("alg") == "none":
            security_issues.append("Algorithm set to 'none' - signature bypass possible")
        
        if "exp" not in payload:
            security_issues.append("No expiration time set")
        
        if payload.get("iss") == "":
            security_issues.append("Empty issuer field")
        
        exec_cred_engine.credentials_harvested += 1
        
        return {
            "tool": "jwt_analyzer",
            "jwt_token": jwt_token[:50] + "...",
            "header": header,
            "payload": payload,
            "security_issues": security_issues,
            "target_url": target_url,
            "tactic": "credential_access",
            "technique": "T1552.001 - Unsecured Credentials: Credentials In Files"
        }
        
    except Exception as e:
        return {
            "tool": "jwt_analyzer",
            "jwt_token": jwt_token[:50] + "...",
            "error": str(e),
            "tactic": "credential_access"
        }

@mcp.tool()
def credential_harvester(target_type: str, target_path: str = "", search_patterns: str = "") -> Dict[str, Any]:
    """
    Harvest credentials from various sources.
    
    Args:
        target_type: Type of target (file, directory, memory, registry)
        target_path: Path to target location
        search_patterns: Patterns to search for credentials
    
    Returns:
        Credential harvesting results
    """
    patterns = search_patterns.split(",") if search_patterns else [
        "password", "passwd", "pwd", "secret", "key", "token", "api_key"
    ]
    
    if target_type == "file":
        commands = []
        for pattern in patterns:
            commands.append(f"grep -i '{pattern}' '{target_path}' 2>/dev/null")
        command = " && ".join(commands)
    elif target_type == "directory":
        command = f"find '{target_path}' -type f -exec grep -l -i 'password\\|secret\\|key' {{}} \\; 2>/dev/null"
    else:
        command = f"strings '{target_path}' | grep -i 'password\\|secret\\|key'"
    
    exec_cred_engine.executions_performed += 1
    result = exec_cred_engine.execute_command(command)
    
    # Count potential credentials found
    if result.get("success") and result.get("stdout"):
        lines = result.get("stdout", "").split("\n")
        credential_count = len([line for line in lines if line.strip()])
        exec_cred_engine.credentials_harvested += credential_count
    
    return {
        "tool": "credential_harvester",
        "target_type": target_type,
        "target_path": target_path,
        "search_patterns": patterns,
        "command_executed": command,
        "result": result,
        "tactic": "credential_access",
        "technique": "T1552 - Unsecured Credentials"
    }

@mcp.tool()
def mimikatz_execution(module: str, parameters: str = "") -> Dict[str, Any]:
    """
    Simulate Mimikatz-style credential extraction (for educational purposes).
    
    Args:
        module: Mimikatz module to execute
        parameters: Module parameters
    
    Returns:
        Simulated credential extraction results
    """
    # Simulate Mimikatz execution (educational simulation only)
    simulated_results = {
        "sekurlsa::logonpasswords": "Simulated logon password extraction",
        "sekurlsa::tickets": "Simulated Kerberos ticket extraction",
        "lsadump::sam": "Simulated SAM database dump",
        "crypto::capi": "Simulated CAPI key extraction"
    }
    
    result_text = simulated_results.get(module, f"Simulated execution of {module}")
    
    exec_cred_engine.executions_performed += 1
    exec_cred_engine.credentials_harvested += 1
    
    return {
        "tool": "mimikatz_simulator",
        "module": module,
        "parameters": parameters,
        "simulated_result": result_text,
        "note": "This is a simulation for educational purposes only",
        "tactic": "credential_access",
        "technique": "T1003.001 - OS Credential Dumping: LSASS Memory"
    }

@mcp.tool()
def browser_credential_extraction(browser: str = "chrome", profile_path: str = "") -> Dict[str, Any]:
    """
    Extract stored credentials from web browsers.
    
    Args:
        browser: Browser type (chrome, firefox, edge)
        profile_path: Path to browser profile
    
    Returns:
        Browser credential extraction results
    """
    if browser.lower() == "chrome":
        default_paths = [
            "~/.config/google-chrome/Default/Login Data",
            "~/Library/Application Support/Google/Chrome/Default/Login Data",
            "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data"
        ]
    elif browser.lower() == "firefox":
        default_paths = [
            "~/.mozilla/firefox/*/logins.json",
            "~/Library/Application Support/Firefox/Profiles/*/logins.json"
        ]
    else:
        default_paths = [profile_path] if profile_path else []
    
    search_path = profile_path if profile_path else default_paths[0]
    command = f"file '{search_path}' 2>/dev/null || echo 'Path not found'"
    
    exec_cred_engine.executions_performed += 1
    result = exec_cred_engine.execute_command(command)
    
    return {
        "tool": "browser_credential_extractor",
        "browser": browser,
        "profile_path": search_path,
        "default_paths": default_paths,
        "command_executed": command,
        "result": result,
        "note": "Actual credential extraction requires appropriate permissions and tools",
        "tactic": "credential_access",
        "technique": "T1555.003 - Credentials from Password Stores: Credentials from Web Browsers"
    }

@mcp.tool()
def get_execution_credential_stats() -> Dict[str, Any]:
    """
    Get execution and credential access statistics.
    
    Returns:
        Current execution and credential access statistics
    """
    return {
        "tool": "exec_cred_stats",
        "executions_performed": exec_cred_engine.executions_performed,
        "credentials_harvested": exec_cred_engine.credentials_harvested,
        "successful_cracks": exec_cred_engine.successful_cracks,
        "success_rate": f"{(exec_cred_engine.successful_cracks / max(1, exec_cred_engine.executions_performed)) * 100:.2f}%",
        "tactics": ["execution", "credential_access"],
        "status": "active"
    }

if __name__ == "__main__":
    mcp.run()
