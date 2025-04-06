"""
Utility Functions - Miscellaneous helper functions
"""
import os
import socket
import subprocess
import ipaddress
import platform
import re
from ping3 import ping

def get_platform_system():
    """Get the operating system platform"""
    return platform.system()

def ping_host(host):
    """Ping a host and return the response time"""
    try:
        response_time = ping(host)
        return response_time
    except:
        return None

def ping_range(network, mask, tries=1):
    """Ping all hosts in a network range"""
    try:
        subnet = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
        results = []
        
        for ip in subnet.hosts():
            ip_str = str(ip)
            for i in range(tries):
                response = ping(ip_str)
                if response:
                    results.append({"ip": ip_str, "latency": response})
                    break
        
        return results
    except Exception as e:
        print(f"Error pinging range: {e}")
        return []

def traceroute(host, max_hops=30, timeout=2):
    """Perform a traceroute to a host"""
    if get_platform_system() == "Windows":
        return traceroute_windows(host, max_hops, timeout)
    else:
        return traceroute_linux(host, max_hops, timeout)

def traceroute_linux(host, max_hops=30, timeout=2):
    """Perform a traceroute to a host on Linux"""
    try:
        output = subprocess.check_output(
            ["traceroute", "-I", "-n", "-m", str(max_hops), "-w", str(timeout), host],
            stderr=subprocess.STDOUT, text=True
        )
        
        lines = output.strip().split("\n")[1:]  # Skip header line
        results = []
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                hop_num = parts[0]
                
                if "*" in parts[1]:
                    results.append({
                        "hop": hop_num, 
                        "ip": "*", 
                        "avg_rtt": "", 
                        "min_rtt": "", 
                        "max_rtt": ""
                    })
                else:
                    ip = parts[1]
                    rtts = []
                    
                    for i in range(2, min(5, len(parts))):
                        if parts[i] != "*":
                            try:
                                rtt = float(parts[i].replace("ms", ""))
                                rtts.append(rtt)
                            except:
                                pass
                    
                    if rtts:
                        results.append({
                            "hop": hop_num,
                            "ip": ip,
                            "avg_rtt": sum(rtts) / len(rtts),
                            "min_rtt": min(rtts),
                            "max_rtt": max(rtts)
                        })
                    else:
                        results.append({
                            "hop": hop_num,
                            "ip": ip,
                            "avg_rtt": "",
                            "min_rtt": "",
                            "max_rtt": ""
                        })
        
        return results
    except Exception as e:
        print(f"Error in traceroute: {e}")
        return []

def traceroute_windows(host, max_hops=30, timeout=2):
    """Perform a traceroute to a host on Windows"""
    try:
        output = subprocess.check_output(
            ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout * 1000), host],
            stderr=subprocess.STDOUT, text=True
        )
        
        lines = output.strip().split("\n")[3:-2]  # Skip header and footer
        results = []
        
        for line in lines:
            match = re.search(r'^\s*(\d+)\s+(?:(<|\*)|\d+\s+ms\s+\d+\s+ms\s+\d+\s+ms)\s+(.+)$', line)
            if match:
                hop_num = match.group(1)
                
                if "<" in match.group(2) or "*" in match.group(2):
                    results.append({
                        "hop": hop_num, 
                        "ip": "*", 
                        "avg_rtt": "", 
                        "min_rtt": "", 
                        "max_rtt": ""
                    })
                else:
                    ip = match.group(3).strip()
                    rtts = []
                    
                    # Extract RTTs from the line
                    rtt_matches = re.findall(r'(\d+)\s+ms', line)
                    for rtt_str in rtt_matches:
                        try:
                            rtt = float(rtt_str)
                            rtts.append(rtt)
                        except:
                            pass
                    
                    if rtts:
                        results.append({
                            "hop": hop_num,
                            "ip": ip,
                            "avg_rtt": sum(rtts) / len(rtts),
                            "min_rtt": min(rtts),
                            "max_rtt": max(rtts)
                        })
                    else:
                        results.append({
                            "hop": hop_num,
                            "ip": ip,
                            "avg_rtt": "",
                            "min_rtt": "",
                            "max_rtt": ""
                        })
        
        return results
    except Exception as e:
        print(f"Error in traceroute: {e}")
        return []

def get_ip_from_peer(peer_data, default="127.0.0.1"):
    """Extract IP address from peer data"""
    try:
        if not peer_data:
            return default
            
        if "allowed_ip" in peer_data:
            allowed_ip = peer_data["allowed_ip"]
            if allowed_ip and "/" in allowed_ip:
                return allowed_ip.split("/")[0]
                
        return default
    except Exception as e:
        print(f"Error getting IP from peer: {e}")
        return default 