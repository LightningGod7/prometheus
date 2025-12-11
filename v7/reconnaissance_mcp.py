#!/usr/bin/env python3
"""
HexStrike AI MCP - Reconnaissance Specialist
MITRE ATT&CK Tactic: Reconnaissance (TA0043)

Focused on information gathering and target enumeration.
"""

import asyncio
import json
import subprocess
import sys
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP("HexStrike Reconnaissance Specialist")

class ReconnaissanceEngine:
    """Enhanced reconnaissance engine with caching and telemetry."""
    
    def __init__(self):
        self.cache = {}
        self.stats = {"scans_performed": 0, "targets_discovered": 0}
    
    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        """Execute system command with caching and error handling."""
        if use_cache and command in self.cache:
            return self.cache[command]
        
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=300
            )
            
            output_data = {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
            
            if use_cache:
                self.cache[command] = output_data
            
            self.stats["scans_performed"] += 1
            return output_data
            
        except subprocess.TimeoutExpired:
            return {"error": "Command timed out", "command": command}
        except Exception as e:
            return {"error": str(e), "command": command}

# Global reconnaissance engine instance
recon_engine = ReconnaissanceEngine()

# ============================================================================
# RECONNAISSANCE TOOLS - MITRE ATT&CK TA0043
# ============================================================================

@mcp.tool()
def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Execute enhanced Nmap scan for network reconnaissance.
    
    Args:
        target: IP address or hostname to scan
        scan_type: Scan type (-sV, -sC, -sS, etc.)
        ports: Port specification (80,443 or 1-1000)
        additional_args: Additional Nmap arguments
    
    Returns:
        Structured scan results with service detection
    """
    port_arg = f"-p {ports}" if ports else ""
    command = f"nmap {scan_type} {port_arg} {additional_args} {target}"
    
    result = recon_engine.execute_command(command)
    
    if result.get("success"):
        recon_engine.stats["targets_discovered"] += 1
    
    return {
        "tool": "nmap",
        "target": target,
        "scan_type": scan_type,
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance",
        "technique": "T1595.001 - Active Scanning: Scanning IP Blocks"
    }

@mcp.tool()
def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
    """
    Directory and subdomain enumeration using Gobuster.
    
    Args:
        url: Target URL to scan
        mode: Scan mode (dir, dns, vhost)
        wordlist: Wordlist file path
        additional_args: Additional Gobuster arguments
    
    Returns:
        Directory/subdomain enumeration results
    """
    command = f"gobuster {mode} -u {url} -w {wordlist} {additional_args}"
    result = recon_engine.execute_command(command)
    
    return {
        "tool": "gobuster",
        "target": url,
        "mode": mode,
        "wordlist": wordlist,
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance", 
        "technique": "T1595.003 - Active Scanning: Wordlist Scanning"
    }

@mcp.tool()
def nuclei_scan(target: str, severity: str = "", tags: str = "", template: str = "", additional_args: str = "") -> Dict[str, Any]:
    """
    Vulnerability scanning using Nuclei templates.
    
    Args:
        target: Target URL or IP to scan
        severity: Filter by severity (critical, high, medium, low)
        tags: Filter by tags (cve, oast, tech)
        template: Specific template to use
        additional_args: Additional Nuclei arguments
    
    Returns:
        Vulnerability scan results
    """
    severity_arg = f"-severity {severity}" if severity else ""
    tags_arg = f"-tags {tags}" if tags else ""
    template_arg = f"-t {template}" if template else ""
    
    command = f"nuclei -target {target} {severity_arg} {tags_arg} {template_arg} {additional_args}"
    result = recon_engine.execute_command(command)
    
    return {
        "tool": "nuclei",
        "target": target,
        "severity": severity,
        "tags": tags,
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance",
        "technique": "T1595.002 - Active Scanning: Vulnerability Scanning"
    }

@mcp.tool()
def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", mode: str = "directory", match_codes: str = "200,204,301,302,307,401,403", additional_args: str = "") -> Dict[str, Any]:
    """
    Fast web fuzzer for content discovery.
    
    Args:
        url: Target URL with FUZZ keyword
        wordlist: Wordlist file path
        mode: Fuzzing mode (directory, parameter, subdomain)
        match_codes: HTTP status codes to match
        additional_args: Additional ffuf arguments
    
    Returns:
        Web content discovery results
    """
    if "FUZZ" not in url:
        url = f"{url}/FUZZ"
    
    command = f"ffuf -w {wordlist} -u {url} -mc {match_codes} {additional_args}"
    result = recon_engine.execute_command(command)
    
    return {
        "tool": "ffuf",
        "target": url,
        "wordlist": wordlist,
        "mode": mode,
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance",
        "technique": "T1595.003 - Active Scanning: Wordlist Scanning"
    }

@mcp.tool()
def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", threads: int = 10, additional_args: str = "") -> Dict[str, Any]:
    """
    Recursive content discovery using Feroxbuster.
    
    Args:
        url: Target URL to scan
        wordlist: Wordlist file path
        threads: Number of concurrent threads
        additional_args: Additional Feroxbuster arguments
    
    Returns:
        Recursive directory enumeration results
    """
    command = f"feroxbuster -u {url} -w {wordlist} -t {threads} {additional_args}"
    result = recon_engine.execute_command(command)
    
    return {
        "tool": "feroxbuster",
        "target": url,
        "wordlist": wordlist,
        "threads": threads,
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance",
        "technique": "T1595.003 - Active Scanning: Wordlist Scanning"
    }

@mcp.tool()
def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, robots: bool = True, sitemap: bool = True, wayback: bool = False, additional_args: str = "") -> Dict[str, Any]:
    """
    Web application crawling and URL discovery.
    
    Args:
        url: Target URL to crawl
        depth: Crawling depth
        forms: Include forms in crawling
        robots: Check robots.txt
        sitemap: Check sitemap.xml
        wayback: Use Wayback Machine
        additional_args: Additional Hakrawler arguments
    
    Returns:
        Web crawling and URL discovery results
    """
    args = []
    if forms: args.append("-forms")
    if robots: args.append("-robots")
    if sitemap: args.append("-sitemap")
    if wayback: args.append("-wayback")
    
    command = f"echo '{url}' | hakrawler -depth {depth} {' '.join(args)} {additional_args}"
    result = recon_engine.execute_command(command)
    
    return {
        "tool": "hakrawler",
        "target": url,
        "depth": depth,
        "options": {"forms": forms, "robots": robots, "sitemap": sitemap, "wayback": wayback},
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance",
        "technique": "T1593.001 - Search Open Websites/Domains: Social Media"
    }

@mcp.tool()
def paramspider_discovery(domain: str, exclude: str = "", output_file: str = "", level: int = 2, additional_args: str = "") -> Dict[str, Any]:
    """
    Parameter discovery from web archives.
    
    Args:
        domain: Target domain to analyze
        exclude: Extensions to exclude
        output_file: Output file path
        level: Discovery level (1-3)
        additional_args: Additional ParamSpider arguments
    
    Returns:
        Parameter discovery results from web archives
    """
    exclude_arg = f"--exclude {exclude}" if exclude else ""
    output_arg = f"-o {output_file}" if output_file else ""
    
    command = f"paramspider -d {domain} --level {level} {exclude_arg} {output_arg} {additional_args}"
    result = recon_engine.execute_command(command)
    
    return {
        "tool": "paramspider",
        "target": domain,
        "level": level,
        "exclude": exclude,
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance",
        "technique": "T1593.002 - Search Open Websites/Domains: Search Engines"
    }

@mcp.tool()
def monitor_cve_feeds(hours: int = 24, severity_filter: str = "HIGH,CRITICAL", keywords: str = "") -> Dict[str, Any]:
    """
    Monitor CVE feeds for recent vulnerabilities.
    
    Args:
        hours: Time window for monitoring (hours)
        severity_filter: Severity levels to include
        keywords: Keywords to filter CVEs
    
    Returns:
        Recent CVE intelligence data
    """
    # Simulate CVE monitoring (in real implementation, this would query actual CVE feeds)
    command = f"curl -s 'https://cve.circl.lu/api/last/{hours}' | jq '.'"
    result = recon_engine.execute_command(command)
    
    return {
        "tool": "cve_monitor",
        "timeframe_hours": hours,
        "severity_filter": severity_filter,
        "keywords": keywords,
        "command_executed": command,
        "result": result,
        "tactic": "reconnaissance",
        "technique": "T1595.002 - Active Scanning: Vulnerability Scanning"
    }

@mcp.tool()
def get_reconnaissance_stats() -> Dict[str, Any]:
    """
    Get reconnaissance engine statistics and metrics.
    
    Returns:
        Current reconnaissance statistics
    """
    return {
        "tool": "recon_stats",
        "statistics": recon_engine.stats,
        "cache_size": len(recon_engine.cache),
        "tactic": "reconnaissance",
        "status": "active"
    }

@mcp.tool()
def clear_reconnaissance_cache() -> Dict[str, Any]:
    """
    Clear reconnaissance cache and reset statistics.
    
    Returns:
        Cache clearing confirmation
    """
    cache_size = len(recon_engine.cache)
    recon_engine.cache.clear()
    recon_engine.stats = {"scans_performed": 0, "targets_discovered": 0}
    
    return {
        "tool": "cache_clear",
        "cleared_entries": cache_size,
        "status": "cache_cleared",
        "tactic": "reconnaissance"
    }

if __name__ == "__main__":
    mcp.run()
