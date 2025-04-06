"""
Configuration Manager - Handles configuration file operations
"""
import os
import configparser

# Constants
DASHBOARD_CONF_PATH = '/etc/wireguard-dashboard/wg-dashboard.ini'

def get_dashboard_conf():
    """Get dashboard configuration"""
    config = configparser.ConfigParser(strict=False)
    
    # Create default config if it doesn't exist
    if not os.path.exists(DASHBOARD_CONF_PATH):
        os.makedirs(os.path.dirname(DASHBOARD_CONF_PATH), exist_ok=True)
        config.add_section("Account")
        config.set("Account", "username", "admin")
        config.set("Account", "password", "admin")
        
        config.add_section("Server")
        config.set("Server", "wg_conf_path", "/etc/wireguard")
        config.set("Server", "app_ip", "0.0.0.0")
        config.set("Server", "app_port", "10086")
        config.set("Server", "dashboard_refresh_interval", "60000")
        config.set("Server", "dashboard_sort", "status")
        
        config.add_section("Peers")
        config.set("Peers", "peer_global_dns", "1.1.1.1, 8.8.8.8")
        config.set("Peers", "remote_endpoint", "auto")
        config.set("Peers", "endpoint_public_ip", "auto")
        config.set("Peers", "peer_mtu", "1420")
        config.set("Peers", "peer_keep_alive", "21")
        
        config.write(open(DASHBOARD_CONF_PATH, "w"))
    else:
        config.read(DASHBOARD_CONF_PATH)
    
    return config

def save_dashboard_config(config):
    """Save dashboard configuration"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(DASHBOARD_CONF_PATH), exist_ok=True)
        
        # Write config to file
        with open(DASHBOARD_CONF_PATH, "w") as config_file:
            config.write(config_file)
        
        return True
    except Exception as e:
        print(f"Error saving dashboard config: {e}")
        return False 