#!/usr/bin/env python3
"""
HexStrike AI MCP - System Monitoring Specialist
Support Function: System Health & Process Management

Focused on monitoring system health, managing processes, and maintaining operational status.
"""

import asyncio
import json
import subprocess
import sys
import psutil
import time
from typing import Any, Dict, Optional
from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP("HexStrike System Monitoring Specialist")

class SystemMonitoringEngine:
    """Enhanced system monitoring engine for operational oversight."""
    
    def __init__(self):
        self.monitoring_active = True
        self.process_registry = {}
        self.health_checks_performed = 0
        self.alerts_generated = 0
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute system command with error handling."""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30
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

# Global system monitoring engine instance
monitor_engine = SystemMonitoringEngine()

# ============================================================================
# SYSTEM MONITORING & HEALTH TOOLS
# ============================================================================

@mcp.tool()
def server_health() -> Dict[str, Any]:
    """
    Comprehensive system health monitoring.
    
    Returns:
        System health metrics and status
    """
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_available = memory.available / (1024**3)  # GB
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        disk_free = disk.free / (1024**3)  # GB
        
        # Network statistics
        network = psutil.net_io_counters()
        
        # Load average (Unix-like systems)
        try:
            load_avg = psutil.getloadavg()
        except AttributeError:
            load_avg = [0, 0, 0]  # Windows doesn't have load average
        
        monitor_engine.health_checks_performed += 1
        
        # Determine health status
        health_status = "healthy"
        alerts = []
        
        if cpu_percent > 90:
            health_status = "critical"
            alerts.append("High CPU usage detected")
        elif cpu_percent > 70:
            health_status = "warning"
            alerts.append("Elevated CPU usage")
        
        if memory_percent > 90:
            health_status = "critical"
            alerts.append("High memory usage detected")
        elif memory_percent > 80:
            health_status = "warning"
            alerts.append("Elevated memory usage")
        
        if disk_percent > 95:
            health_status = "critical"
            alerts.append("Disk space critically low")
        elif disk_percent > 85:
            health_status = "warning"
            alerts.append("Disk space running low")
        
        monitor_engine.alerts_generated += len(alerts)
        
        return {
            "tool": "health_monitor",
            "status": health_status,
            "timestamp": time.time(),
            "metrics": {
                "cpu": {
                    "usage_percent": cpu_percent,
                    "core_count": cpu_count,
                    "load_average": load_avg
                },
                "memory": {
                    "usage_percent": memory_percent,
                    "available_gb": round(memory_available, 2),
                    "total_gb": round(memory.total / (1024**3), 2)
                },
                "disk": {
                    "usage_percent": round(disk_percent, 2),
                    "free_gb": round(disk_free, 2),
                    "total_gb": round(disk.total / (1024**3), 2)
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                }
            },
            "alerts": alerts,
            "support_function": "system_monitoring"
        }
        
    except Exception as e:
        return {
            "tool": "health_monitor",
            "error": str(e),
            "status": "error",
            "support_function": "system_monitoring"
        }

@mcp.tool()
def get_cache_stats() -> Dict[str, Any]:
    """
    Get system cache statistics and performance metrics.
    
    Returns:
        Cache performance statistics
    """
    try:
        # Simulate cache statistics (in real implementation, this would query actual cache systems)
        cache_stats = {
            "hit_rate": 85.7,
            "miss_rate": 14.3,
            "total_requests": 10000,
            "cache_size_mb": 512,
            "evictions": 150,
            "memory_usage_percent": 67.3
        }
        
        return {
            "tool": "cache_monitor",
            "statistics": cache_stats,
            "status": "active",
            "timestamp": time.time(),
            "support_function": "system_monitoring"
        }
        
    except Exception as e:
        return {
            "tool": "cache_monitor",
            "error": str(e),
            "status": "error",
            "support_function": "system_monitoring"
        }

@mcp.tool()
def clear_cache() -> Dict[str, Any]:
    """
    Clear system caches and temporary data.
    
    Returns:
        Cache clearing results
    """
    try:
        # Clear system caches
        commands = [
            "sync",  # Sync filesystem
            "echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || echo 'Cache clear attempted'",
            "find /tmp -type f -atime +1 -delete 2>/dev/null || echo 'Temp cleanup attempted'"
        ]
        
        results = []
        for cmd in commands:
            result = monitor_engine.execute_command(cmd)
            results.append(result)
        
        return {
            "tool": "cache_cleaner",
            "operations": len(commands),
            "results": results,
            "status": "completed",
            "timestamp": time.time(),
            "support_function": "system_monitoring"
        }
        
    except Exception as e:
        return {
            "tool": "cache_cleaner",
            "error": str(e),
            "status": "error",
            "support_function": "system_monitoring"
        }

@mcp.tool()
def get_telemetry() -> Dict[str, Any]:
    """
    Comprehensive system telemetry collection.
    
    Returns:
        System telemetry data
    """
    try:
        # Process information
        process_count = len(psutil.pids())
        
        # Boot time
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        # Users
        users = psutil.users()
        
        # Sensors (if available)
        try:
            temps = psutil.sensors_temperatures()
            fans = psutil.sensors_fans()
        except AttributeError:
            temps = {}
            fans = {}
        
        telemetry = {
            "system": {
                "uptime_seconds": uptime,
                "boot_time": boot_time,
                "process_count": process_count,
                "user_sessions": len(users)
            },
            "performance": {
                "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                "memory_stats": psutil.virtual_memory()._asdict(),
                "disk_io": psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                "network_io": psutil.net_io_counters()._asdict()
            },
            "sensors": {
                "temperatures": temps,
                "fans": fans
            }
        }
        
        return {
            "tool": "telemetry_collector",
            "telemetry": telemetry,
            "collection_time": time.time(),
            "status": "success",
            "support_function": "system_monitoring"
        }
        
    except Exception as e:
        return {
            "tool": "telemetry_collector",
            "error": str(e),
            "status": "error",
            "support_function": "system_monitoring"
        }

# ============================================================================
# PROCESS MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def list_active_processes() -> Dict[str, Any]:
    """
    List all active processes with detailed information.
    
    Returns:
        Active process listing
    """
    try:
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
            try:
                proc_info = proc.info
                proc_info['cpu_percent'] = proc.cpu_percent()
                proc_info['memory_percent'] = proc.memory_percent()
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        
        return {
            "tool": "process_lister",
            "process_count": len(processes),
            "processes": processes[:50],  # Limit to top 50 processes
            "timestamp": time.time(),
            "support_function": "process_management"
        }
        
    except Exception as e:
        return {
            "tool": "process_lister",
            "error": str(e),
            "support_function": "process_management"
        }

@mcp.tool()
def get_process_status(pid: int) -> Dict[str, Any]:
    """
    Get detailed status information for a specific process.
    
    Args:
        pid: Process ID to query
    
    Returns:
        Detailed process status information
    """
    try:
        proc = psutil.Process(pid)
        
        status_info = {
            "pid": pid,
            "name": proc.name(),
            "status": proc.status(),
            "cpu_percent": proc.cpu_percent(),
            "memory_percent": proc.memory_percent(),
            "memory_info": proc.memory_info()._asdict(),
            "create_time": proc.create_time(),
            "num_threads": proc.num_threads(),
            "cmdline": proc.cmdline(),
            "cwd": proc.cwd() if hasattr(proc, 'cwd') else None,
            "connections": len(proc.connections()) if hasattr(proc, 'connections') else 0
        }
        
        return {
            "tool": "process_status",
            "process_info": status_info,
            "timestamp": time.time(),
            "support_function": "process_management"
        }
        
    except psutil.NoSuchProcess:
        return {
            "tool": "process_status",
            "error": f"Process {pid} not found",
            "support_function": "process_management"
        }
    except psutil.AccessDenied:
        return {
            "tool": "process_status",
            "error": f"Access denied to process {pid}",
            "support_function": "process_management"
        }
    except Exception as e:
        return {
            "tool": "process_status",
            "error": str(e),
            "support_function": "process_management"
        }

@mcp.tool()
def terminate_process(pid: int) -> Dict[str, Any]:
    """
    Terminate a specific process.
    
    Args:
        pid: Process ID to terminate
    
    Returns:
        Process termination result
    """
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        
        proc.terminate()
        
        # Wait for termination
        try:
            proc.wait(timeout=5)
            status = "terminated"
        except psutil.TimeoutExpired:
            proc.kill()
            status = "killed"
        
        return {
            "tool": "process_terminator",
            "pid": pid,
            "process_name": proc_name,
            "status": status,
            "timestamp": time.time(),
            "support_function": "process_management"
        }
        
    except psutil.NoSuchProcess:
        return {
            "tool": "process_terminator",
            "error": f"Process {pid} not found",
            "support_function": "process_management"
        }
    except psutil.AccessDenied:
        return {
            "tool": "process_terminator",
            "error": f"Access denied to terminate process {pid}",
            "support_function": "process_management"
        }
    except Exception as e:
        return {
            "tool": "process_terminator",
            "error": str(e),
            "support_function": "process_management"
        }

@mcp.tool()
def get_process_dashboard() -> Dict[str, Any]:
    """
    Get comprehensive process management dashboard.
    
    Returns:
        Process management dashboard data
    """
    try:
        # Top CPU processes
        cpu_processes = []
        memory_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = proc.info
                proc_info['cpu_percent'] = proc.cpu_percent()
                proc_info['memory_percent'] = proc.memory_percent()
                
                cpu_processes.append(proc_info)
                memory_processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort and limit
        cpu_processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        memory_processes.sort(key=lambda x: x.get('memory_percent', 0), reverse=True)
        
        dashboard = {
            "summary": {
                "total_processes": len(psutil.pids()),
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
            },
            "top_cpu_processes": cpu_processes[:10],
            "top_memory_processes": memory_processes[:10],
            "system_stats": {
                "uptime": time.time() - psutil.boot_time(),
                "users": len(psutil.users()),
                "network_connections": len(psutil.net_connections()) if hasattr(psutil, 'net_connections') else 0
            }
        }
        
        return {
            "tool": "process_dashboard",
            "dashboard": dashboard,
            "timestamp": time.time(),
            "support_function": "process_management"
        }
        
    except Exception as e:
        return {
            "tool": "process_dashboard",
            "error": str(e),
            "support_function": "process_management"
        }

@mcp.tool()
def get_monitoring_stats() -> Dict[str, Any]:
    """
    Get system monitoring statistics and metrics.
    
    Returns:
        Current monitoring statistics
    """
    return {
        "tool": "monitoring_stats",
        "health_checks_performed": monitor_engine.health_checks_performed,
        "alerts_generated": monitor_engine.alerts_generated,
        "monitoring_active": monitor_engine.monitoring_active,
        "process_registry_size": len(monitor_engine.process_registry),
        "support_function": "system_monitoring",
        "status": "active"
    }

if __name__ == "__main__":
    mcp.run()
