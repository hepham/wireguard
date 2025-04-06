"""
Server Configuration Module - Handles server-specific configuration functions
"""
import os
import json
import socket
import subprocess
import configparser

from .config import get_dashboard_conf, save_dashboard_config
from .redis_manager import get_redis_client
from .wireguard import (
    WG_CONF_PATH, DEFAULT_DNS, DEFAULT_ENDPOINT, save_wireguard_config, gen_private_key
)

def save_server_setting(request_data, config_name):
    """Save server settings"""
    status_code = 400
    result = {}
    msg = "Configuration updated and restart Wireguard"
    r = get_redis_client()
    if not r:
        return {"error": "Redis connection not available"}, 500

    config = get_dashboard_conf()

    try:
        port = int(request_data["port"])
        if not 0 < port <= 65535:
            msg = "Invalid port number must be 1-65535"
            result = {"error": msg}
            return result, status_code
    except:
        port = 51820

    try:
        endpoint = request_data["endpoint"]
        if len(endpoint.strip()) == 0:
            msg = f"Invalid endpoint"
            result = {"error": msg}
            return result, status_code
    except:
        endpoint = config.get("Peers", "remote_endpoint", fallback=DEFAULT_ENDPOINT)

    try:
        remote_endpoint = request_data["remote_endpoint"]
        if len(remote_endpoint.strip()) == 0:
            msg = f"Invalid remote endpoint"
            result = {"error": msg}
            return result, status_code

    except:
        remote_endpoint = config.get("Peers", "remote_endpoint", fallback=DEFAULT_ENDPOINT)

    try:
        private_key = request_data["private_key"]
        if len(private_key.strip()) == 0:
            msg = f"invalid private_key"
            result = {"error": msg}
            return result, status_code
    except:
        conf_file = open(f"{WG_CONF_PATH}/{config_name}.conf")
        lines = conf_file.readlines()
        private_key = [line for line in lines if "PrivateKey" in line][0].split()[2].strip()
        conf_file.close()
        if not private_key:
            private_key = gen_private_key()

    try:
        available_range = request_data["address_range"]
        try:
            socket.inet_aton(available_range.split("/")[0])
            if not (0 <= int(available_range.split("/")[1]) <= 32):
                msg = f"Invalid address CIDR range"
                result = {"error": msg}
                return result, status_code
        except socket.error:
            msg = f"Invalid address range"
            result = {"error": msg}
            return result, status_code
    except:
        conf_file = open(f"{WG_CONF_PATH}/{config_name}.conf")
        lines = conf_file.readlines()
        available_range = [line for line in lines if "Address" in line][0].split()[2].strip()
        conf_file.close()
        if not available_range:
            available_range = "10.66.66.1/24"

    try:
        DNS = request_data["DNS"]
        try:
            for ip in DNS.split(","):
                socket.inet_aton(ip)
        except socket.error:
            msg = f"Invalid DNS range"
            result = {"error": msg}
            return result, status_code
    except:
        DNS = DEFAULT_DNS

    try:
        # Get redis peer
        peers = []
        for key in r.scan_iter(f"{config_name}_peer:*"):
            peers.append(r.get(key).decode('utf-8'))

        peer_string = ""
        for key in peers:
            peer = json.loads(key)
            if "public_key" in peer and len(peer["public_key"]) >= 43:
                peer_string += f"\n[Peer]\n"
                peer_string += f"PublicKey = {peer['public_key']}\n"
                peer_string += f"AllowedIPs = {peer['allowed_ip']}\n"
                if "preshared_key" in peer and len(peer["preshared_key"]) >= 44:
                    peer_string += f"PresharedKey = {peer['preshared_key']}\n"

        try:
            config.set("Peers", "remote_endpoint", remote_endpoint)
            config.set("Peers", "peer_mtu", request_data["mtu"])
        except Exception as e:
            print(f"Failed to update config: {str(e)}")

        save_dashboard_config(config)

        # Save to file
        with open(f"{WG_CONF_PATH}/{config_name}.conf.tmp", "w") as conf_file:
            conf_file.write(f"""[Interface]
PrivateKey = {private_key}
Address = {available_range}
ListenPort = {port}
DNS = {DNS}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {endpoint} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {endpoint} -j MASQUERADE
# SaveConfig = true
# PersistentKeepalive = 25
{peer_string}
""")

        # Ensure directory exists
        os.makedirs(os.path.dirname(f"{WG_CONF_PATH}/{config_name}.conf"), exist_ok=True)
        
        # Move temporary file to final location
        os.replace(f"{WG_CONF_PATH}/{config_name}.conf.tmp", f"{WG_CONF_PATH}/{config_name}.conf")
        
        # Use wg-quick save with locking mechanism instead of direct subprocess call
        if not save_wireguard_config(config_name):
            raise Exception("Failed to save WireGuard configuration")
        
        result = {"success": True, "message": msg}
        status_code = 200

    except Exception as e:
        print(f"Error saving server settings: {str(e)}")
        result = {"error": str(e)}
        status_code = 500

    return result, status_code 