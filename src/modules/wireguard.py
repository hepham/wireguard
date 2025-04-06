"""
WireGuard Manager - Handles WireGuard configuration and operations
"""
import os
import subprocess
import tempfile
import configparser
import socket
import fcntl
import errno
import contextlib
from datetime import datetime

# Constants
WG_CONF_PATH = '/etc/wireguard'
DEFAULT_ENDPOINT = 'eth0'
DEFAULT_DNS = '1.1.1.1, 8.8.8.8'
DEFAULT_ENDPOINT_ALLOWED_IP = '0.0.0.0/0'
BASE_IP = '10.66.66'

# Create a context manager for file locking
@contextlib.contextmanager
def file_lock(lock_file):
    """Context manager for file-based locking to prevent concurrent access"""
    lock_path = f"/tmp/wg_dashboard_{lock_file}.lock"
    try:
        # Open lock file
        with open(lock_path, 'w') as f:
            try:
                # Try to acquire an exclusive lock (non-blocking)
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # We got the lock, yield control back to the context
                yield
            except IOError as e:
                # Resource temporarily unavailable - another process has the lock
                if e.errno == errno.EAGAIN:
                    print(f"[WARNING] Another process is saving the {lock_file} configuration. Waiting for lock...")
                    # Try again but block until we get the lock
                    fcntl.flock(f, fcntl.LOCK_EX)
                    yield
                else:
                    # Some other kind of IO error occurred
                    raise
            finally:
                # Release the lock
                fcntl.flock(f, fcntl.LOCK_UN)
    except IOError as e:
        print(f"[ERROR] Failed to obtain lock for {lock_file}: {str(e)}")
        # Still yield control, even if we couldn't get a lock
        yield
    finally:
        # Clean up the lock file if possible
        try:
            os.remove(lock_path)
        except:
            pass

def save_wireguard_config(config_name):
    """Save WireGuard configuration with file locking to prevent race conditions"""
    with file_lock(config_name):
        try:
            # Make sure the directory exists
            os.makedirs('/etc/wireguard', exist_ok=True)
            
            # Save configuration
            result = subprocess.check_output(['wg-quick', 'save', config_name], stderr=subprocess.STDOUT)
            print(f"[INFO] Configuration saved for {config_name}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to save configuration for {config_name}: {e.output.decode()}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error saving configuration for {config_name}: {str(e)}")
            return False

def get_conf_status(config_name):
    """Check if a WireGuard configuration is running"""
    try:
        wg_show = subprocess.check_output(f"wg show {config_name}", shell=True, stderr=subprocess.DEVNULL)
        return "running"
    except:
        return "stopped"

def get_conf_peer_key(config_name):
    """Get all peer keys from a configuration"""
    try:
        peer_key = subprocess.check_output("wg show " + config_name + " peers", shell=True)
        peer_key = peer_key.decode("UTF-8").split()
        return peer_key
    except Exception:
        return f"{config_name} is not running."

def get_conf_pub_key(config_name):
    """Get configuration public key"""
    conf = configparser.ConfigParser(strict=False)
    conf.read(f"{WG_CONF_PATH}/{config_name}.conf")
    pri = conf.get("Interface", "PrivateKey")
    pub = subprocess.check_output("echo '" + pri + "' | wg pubkey", shell=True)
    conf.clear()
    return pub.decode().strip("\n")

def get_conf_listen_port(config_name):
    """Get configuration listen port"""
    conf = configparser.ConfigParser(strict=False)
    conf.read(f"{WG_CONF_PATH}/{config_name}.conf")
    port = ""
    try:
        port = conf.get("Interface", "ListenPort")
    except:
        if get_conf_status(config_name) == "running":
            port = subprocess.check_output("wg show "+config_name+" listen-port", shell=True)
            port = port.decode("UTF-8")
    conf.clear()
    return port

def get_conf_data(config_name):
    """Get configuration data"""
    if get_conf_status(config_name) == "stopped":
        return "Your need to turn on " + config_name + " first."

    data = {}
    try:
        output = subprocess.check_output("wg show " + config_name + " dump", shell=True)
        lines = output.decode("UTF-8").splitlines()
        
        # First line is server info
        server_info = lines[0].split()
        data["server"] = {
            "private_key": server_info[0] if len(server_info) > 0 else "",
            "public_key": server_info[1] if len(server_info) > 1 else "",
            "listen_port": server_info[2] if len(server_info) > 2 else "",
            "fw_mark": server_info[3] if len(server_info) > 3 else ""
        }
        
        # Rest are peer info
        peers = []
        for i in range(1, len(lines)):
            peer_info = lines[i].split()
            if len(peer_info) >= 4:
                peer = {
                    "public_key": peer_info[0],
                    "preshared_key": peer_info[1],
                    "endpoint": peer_info[2],
                    "allowed_ips": peer_info[3],
                    "latest_handshake": peer_info[4] if len(peer_info) > 4 else "",
                    "transfer_rx": peer_info[5] if len(peer_info) > 5 else "",
                    "transfer_tx": peer_info[6] if len(peer_info) > 6 else "",
                    "persistent_keepalive": peer_info[7] if len(peer_info) > 7 else ""
                }
                peers.append(peer)
        
        data["peers"] = peers
        return data
    
    except subprocess.CalledProcessError:
        return config_name + " is not running."

def gen_private_key():
    """Generate WireGuard private key with unique temp files to prevent race conditions"""
    # Create unique temporary files
    private_file = tempfile.NamedTemporaryFile(delete=False)
    public_file = tempfile.NamedTemporaryFile(delete=False)
    
    try:
        # Close files so they can be used by shell commands
        private_file.close()
        public_file.close()
        
        # Generate keys using the unique temporary filenames
        subprocess.check_output(f'wg genkey > {private_file.name} && wg pubkey < {private_file.name} > {public_file.name}', 
                                shell=True)
        
        # Read the keys
        with open(private_file.name, 'r') as f:
            private_key = f.readline().strip()
            
        with open(public_file.name, 'r') as f:
            public_key = f.readline().strip()
            
        # Return the data
        return {"private_key": private_key, "public_key": public_key}
    
    finally:
        # Make sure to clean up the temp files even if there's an error
        try:
            os.unlink(private_file.name)
        except:
            pass
            
        try:
            os.unlink(public_file.name)
        except:
            pass

def gen_public_key(private_key):
    """Generate WireGuard public key from private key with unique temp files"""
    # Create unique temporary files
    private_file = tempfile.NamedTemporaryFile(delete=False)
    public_file = tempfile.NamedTemporaryFile(delete=False)
    
    try:
        # Write private key to file
        with open(private_file.name, 'w') as f:
            f.write(private_key)
        
        # Generate public key
        try:
            subprocess.check_output(f'wg pubkey < {private_file.name} > {public_file.name}', 
                                   shell=True)
            
            # Read public key
            with open(public_file.name, 'r') as f:
                public_key = f.readline().strip()
                
            return {"status": 'success', "msg": "", "data": public_key}
        except subprocess.CalledProcessError as exc:
            return {"status": 'failed', "msg": "Key is not the correct length or format", "data": ""}
    
    finally:
        # Clean up temporary files
        try:
            os.unlink(private_file.name)
        except:
            pass
            
        try:
            os.unlink(public_file.name)
        except:
            pass

def check_IP_with_range(ip_range):
    """Check if an IP with CIDR range is valid"""
    try:
        if ip_range.count('/') != 1:
            return False
        ip = ip_range.split('/')[0]
        cidr = int(ip_range.split('/')[1])
        if cidr < 0 or cidr > 32:
            return False
        socket.inet_aton(ip)
        return True
    except:
        return False

def check_DNS(dns):
    """Check if DNS address is valid"""
    if len(dns) == 0:
        return True
    
    dns_list = [x.strip() for x in dns.split(',')]
    for dns in dns_list:
        try:
            socket.inet_aton(dns)
        except:
            return False
    return True

def checkKeyMatch(private_key, id, config_name):
    """Check if private key matches the public key"""
    # Generate public key from private key
    pubkey = gen_public_key(private_key)
    if pubkey['status'] == 'failed':
        return pubkey
    
    # Check if generated public key matches the ID
    if id != pubkey['data']:
        return {"status": "failed", "msg": "Private key does not match this client."}
    
    return {"status": "success", "msg": ""}

def check_repeat_allowed_IP(public_key, allowed_ip, config_name):
    """Check if there's an IP conflict with other peers"""
    # Skip empty allowed IPs
    if allowed_ip == "" or allowed_ip == '""':
        return {"status": "success", "msg": ""}
    
    # Check if allowed IP is valid
    if not check_IP_with_range(allowed_ip):
        return {"status": "failed", "msg": "Allowed IPs format is not correct."}
    
    # Check for conflicts with other peers
    conf_data = get_conf_data(config_name)
    if type(conf_data) == str:
        return {"status": "failed", "msg": conf_data}
    
    for peer in conf_data["peers"]:
        if peer["public_key"] != public_key and peer["allowed_ips"] == allowed_ip:
            return {"status": "failed", "msg": "This Allowed IPs already exists."}
    
    return {"status": "success", "msg": ""}

def cleanup_inactive_peers(config_name=None):
    """Remove inactive peers from WireGuard"""
    try:
        # Check if Wireguard is running 
        configs = []
        
        # If config_name is specified, only use that config
        if config_name:
            if get_conf_status(config_name) == "running":
                configs.append(config_name)
        else:
            # Otherwise process all running configs
            conf_dir = os.listdir(WG_CONF_PATH)
            for conf in conf_dir:
                if conf.endswith('.conf'):
                    name = conf.split('.')[0]
                    if get_conf_status(name) == "running":
                        configs.append(name)
        
        for config in configs:
            peers_removed = False
            
            # Get peers that haven't had a handshake in over 3 days (259200 seconds)
            try:
                output = subprocess.check_output(['wg', 'show', config, 'latest-handshakes'], 
                                               stderr=subprocess.DEVNULL)
                
                lines = output.decode('utf-8').strip().split('\n')
                current_time = int(datetime.now().timestamp())
                
                for line in lines:
                    if not line.strip():
                        continue
                        
                    parts = line.split()
                    if len(parts) >= 2:
                        peer_key = parts[0]
                        last_handshake = int(parts[1])
                        
                        # If handshake was more than 3 days ago, remove peer
                        if last_handshake > 0 and (current_time - last_handshake) > 259200:
                            print(f"Removing inactive peer {peer_key} from {config}")
                            subprocess.call(['wg', 'set', config, 'peer', peer_key, 'remove'], 
                                          stderr=subprocess.DEVNULL)
                            peers_removed = True
                
                # Only save if peers were actually removed
                if peers_removed:
                    if not save_wireguard_config(config):
                        print(f"Failed to save configuration after removing inactive peers for {config}")
                        
            except subprocess.CalledProcessError:
                print(f"Failed to check or remove inactive peers for {config}")
                
    except Exception as e:
        print(f"Error in cleanup_inactive_peers: {str(e)}")
        return False
        
    return True 