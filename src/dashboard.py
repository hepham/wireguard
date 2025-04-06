import os
from flask import Flask, request, render_template, redirect, url_for, session, abort, jsonify, make_response
import subprocess
from datetime import datetime, date, time, timedelta
import time
from operator import itemgetter
import secrets
import hashlib
import json, urllib.request
import configparser
import re
import threading
# PIP installed library
import ifcfg
from flask_qrcode import QRcode
# Replace TinyDB with Redis
import redis
from icmplib import ping, multiping, traceroute, resolve, Host, Hop
# Dashboard Version
dashboard_version = 'v2.3.1'
# Dashboard Config Name
dashboard_conf = 'wg-dashboard.ini'
# Upgrade Required
update = ""
DEFAULT_DNS="1.1.1.1"
DEFAULT_ENDPOINT_ALLOWED_IP="0.0.0.0/0"
BASE_IP = "10.66.66"  # Phần IP cố định
INACTIVE_DAYS = 30  # Number of days after which a peer is considered inactive
# DEFAULT=
# Flask App Configuration
app = Flask("WGDashboard")
# Enable QR Code Generator
QRcode(app)

app.secret_key = secrets.token_urlsafe(16)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Redis configuration
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # Set this if your Redis server requires authentication
REDIS_PREFIX = 'wireguard:'
import fcntl
import errno
import contextlib

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
# Redis connection with retry
def get_redis_client(max_retries=3, retry_delay=1):
    """Get Redis client with retry mechanism"""
    for attempt in range(max_retries):
        try:
            #print(f"[DEBUG] Connecting to Redis (attempt {attempt+1}/{max_retries}): {REDIS_HOST}:{REDIS_PORT}")
            r = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                password=REDIS_PASSWORD,
                decode_responses=True  # Automatically decode responses to strings
            )
            # Test connection
            ping_result = r.ping()
            #print(f"[DEBUG] Redis connection successful, ping result: {ping_result}")
            return r
        except redis.exceptions.ConnectionError as e:
            print(f"[ERROR] Error connecting to Redis: {e}")
            if attempt < max_retries - 1:
                #print(f"[DEBUG] Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print(f"[ERROR] All {max_retries} connection attempts to Redis failed")
        except Exception as e:
            print(f"[ERROR] Unexpected error connecting to Redis: {str(e)}")
            import traceback
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
            if attempt < max_retries - 1:
                print(f"[DEBUG] Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print(f"[ERROR] All {max_retries} connection attempts to Redis failed")
    return None

# Redis key helpers
def get_peers_set_key(config_name):
    """Get Redis key for peers set"""
    return f"{REDIS_PREFIX}{config_name}:peers"

def get_peer_key(config_name, peer_id):
    """Get Redis key for a peer"""
    return f"{REDIS_PREFIX}{config_name}:peer:{peer_id}"

def get_last_seen_key(config_name, peer_id):
    """Get Redis key for peer's last seen timestamp"""
    return f"{REDIS_PREFIX}{config_name}:lastseen:{peer_id}"

# Redis data operations
def save_peer_to_redis(config_name, peer_id, peer_data):
    """Save peer data to Redis"""
    r = get_redis_client()
    if not r:
        print(f"[ERROR] Redis connection failed when saving peer: {peer_id} for config: {config_name}")
        return False
    
    try:
        # Add peer ID to set of peers for this config
        peers_set_key = get_peers_set_key(config_name)
        # print(f"[DEBUG] Adding peer {peer_id} to set: {peers_set_key}")
        r.sadd(peers_set_key, peer_id)
        
        # Save peer data as hash
        peer_key = get_peer_key(config_name, peer_id)
        
        # Convert all values to strings for Redis
        string_data = {k: str(v) for k, v in peer_data.items()}
        
        # Save to Redis
        # print(f"[DEBUG] Saving peer data to key: {peer_key} with {len(string_data)} fields")
        r.hset(peer_key, mapping=string_data)
        
        # Update last seen
        update_peer_last_seen(config_name, peer_id)
        
        # Force save to disk for critical operations
        r.save()
        
        return True
    except Exception as e:
        print(f"[ERROR] Error saving peer to Redis: {str(e)}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return False

def update_peer_last_seen(config_name, peer_id):
    """Update the last seen timestamp for a peer"""
    r = get_redis_client()
    if not r:
        return False
    
    try:
        # Set last seen timestamp
        last_seen_key = get_last_seen_key(config_name, peer_id)
        r.set(last_seen_key, int(time.time()))
        return True
    except Exception as e:
        print(f"Error updating last seen: {str(e)}")
        return False

def get_all_peers_from_redis(config_name):
    """Get all peers for a config from Redis"""
    r = get_redis_client()
    if not r:
        print(f"[ERROR] Redis connection failed for config: {config_name}")
        return []
    
    peers = []
    try:
        # Get all peer IDs for this config
        peers_set_key = get_peers_set_key(config_name)
        #print(f"[DEBUG] Fetching peers with key: {peers_set_key}")
        peer_ids = r.smembers(peers_set_key)
        
        if not peer_ids:
            #print(f"[DEBUG] No peer IDs found for config: {config_name}")
            return []
            
        #print(f"[DEBUG] Found {len(peer_ids)} peer IDs: {peer_ids}")
        
        # Get data for each peer
        for peer_id in peer_ids:
            peer_key = get_peer_key(config_name, peer_id)
            #print(f"[DEBUG] Fetching peer data with key: {peer_key}")
            peer_data = r.hgetall(peer_key)
            
            if not peer_data:
                #print(f"[DEBUG] No data found for peer_id: {peer_id}")
                continue
                
            # print(f"[DEBUG] Found data for peer_id: {peer_id}, keys: {peer_data.keys()}")
            
            # Add ID to the data
            peer_data['id'] = peer_id
            peers.append(peer_data)
        
        #print(f"[DEBUG] Returning {len(peers)} peers for config: {config_name}")
        return peers
    except Exception as e:
        print(f"[ERROR] Error getting peers from Redis: {str(e)}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return []

def get_peer_from_redis(config_name, peer_id):
    """Get a single peer's data from Redis"""
    r = get_redis_client()
    if not r:
        return None
        
    try:
        # Get peer data
        peer_key = get_peer_key(config_name, peer_id)
        peer_data = r.hgetall(peer_key)
        
        if not peer_data:
            return None
            
        # Add ID to the data
        peer_data['id'] = peer_id
        return peer_data
    except Exception as e:
        print(f"Error getting peer from Redis: {str(e)}")
        return None

def delete_peer_from_redis(config_name, peer_id):
    """Delete a peer from Redis"""
    r = get_redis_client()
    if not r:
        return False
    
    try:
        # Remove peer from set
        peers_set_key = get_peers_set_key(config_name)
        r.srem(peers_set_key, peer_id)
        
        # Delete peer data
        peer_key = get_peer_key(config_name, peer_id)
        r.delete(peer_key)
        
        # Delete last seen data
        last_seen_key = get_last_seen_key(config_name, peer_id)
        r.delete(last_seen_key)
        
        # Force save to disk for critical operations
        r.save()
        
        return True
    except Exception as e:
        print(f"Error deleting peer from Redis: {str(e)}")
        return False

# Define a global variable to track last update time for each config
last_db_update = {}

def should_update_db(config_name):
    """Check if we should update the database for this config"""
    global last_db_update
    
    # Initialize if not exists
    if config_name not in last_db_update:
        last_db_update[config_name] = 0
        
    current_time = int(time.time())
    
    # If it's been more than 3 seconds since last update, do it
    if current_time - last_db_update.get(config_name, 0) > 3:
        last_db_update[config_name] = current_time
        return True
    return False

def search_peers_in_redis(config_name, search_term=None, sort_field=None):
    """Search for peers in Redis with optional filtering and sorting"""
    peers = get_all_peers_from_redis(config_name)
    
    # Filter by search term if provided
    if search_term:
        search_term = search_term.lower()
        peers = [p for p in peers if search_term in p.get('name', '').lower()]
    
    # Sort if specified
    if sort_field and peers:
        peers.sort(key=lambda p: p.get(sort_field, ''))
    
    return peers

def cleanup_inactive_peers(config_name='wg0', threshold=180):
    """Xóa các peer không hoạt động trong 3 phút"""
    try:
        # Lấy danh sách peer hiện tại từ WireGuard
        dump = subprocess.check_output(
            ['wg', 'show', config_name, 'dump'],
            text=True
        )
        
        # Parse thông tin handshake
        active_peers = {}
        for line in dump.split('\n')[1:]:  # Bỏ qua dòng đầu tiên
            if line:
                parts = line.split('\t')
                pubkey = parts[0]
                last_handshake = int(parts[4])
                active_peers[pubkey] = last_handshake

        # Get Redis connection
        r = get_redis_client()
        if not r:
            print("Redis connection not available")
            return

        # Get all peer IDs for this config
        peers_key = get_peers_set_key(config_name)
        peer_ids = r.smembers(peers_key)
        current_time = int(time.time())
        
        peers_removed = False

        for peer_id in peer_ids:
            handshake_time = active_peers.get(peer_id, 0)

            # Kiểm tra thời gian không hoạt động
            if handshake_time == 0 or (current_time - handshake_time) > threshold:
                try:
                    # Xóa khỏi WireGuard
                    subprocess.check_call([
                        'wg', 'set', 
                        config_name, 
                        'peer', 
                        peer_id, 
                        'remove'
                    ])
                    
                    # Xóa khỏi Redis
                    delete_peer_from_redis(config_name, peer_id)
                    peers_removed = True
                    
                except Exception as e:
                    print(f"error delete peer {peer_id}: {str(e)}")

        # Lưu cấu hình only if peers were actually removed
        if peers_removed:
            save_wireguard_config(config_name)

    except Exception as e:
        print(f"error cleanup: {str(e)}")

# Get latest handshake from all peers of a configuration
def get_latest_handshake(config_name):
    # Get latest handshakes
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " latest-handshakes", shell=True)
    except Exception:
        return "stopped"
    
    r = get_redis_client()
    if not r:
        return "redis not available"
    
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    now = datetime.now()
    b = timedelta(minutes=2)
    
    for i in range(int(len(data_usage) / 2)):
        public_key = data_usage[count]
        handshake_time = int(data_usage[count + 1])
        
        minus = now - datetime.fromtimestamp(handshake_time)
        if minus < b:
            status = "running"
        else:
            status = "stopped"
        
        # Get peer key
        peer_key = get_peer_key(config_name, public_key)
        
        # Update handshake and status
        if handshake_time > 0:
            r.hset(peer_key, "latest_handshake", str(minus).split(".")[0])
            r.hset(peer_key, "status", status)
        else:
            r.hset(peer_key, "latest_handshake", "(None)")
            r.hset(peer_key, "status", status)
        
        count += 2

# Get transfer from all peers of a configuration
def get_transfer(config_name):
    # Get transfer
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " transfer", shell=True)
    except Exception:
        return "stopped"
    
    r = get_redis_client()
    if not r:
        return "redis not available"
    
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    
    for i in range(int(len(data_usage) / 3)):
        public_key = data_usage[count]
        peer_key = get_peer_key(config_name, public_key)
        
        # Check if peer exists
        if not r.exists(peer_key):
            count += 3
            continue
        
        # Get current values
        status = r.hget(peer_key, "status")
        traffic_str = r.hget(peer_key, "traffic") or "[]"
        try:
            traffic = json.loads(traffic_str)
        except:
            traffic = []
        
        total_sent = float(r.hget(peer_key, "total_sent") or 0)
        total_receive = float(r.hget(peer_key, "total_receive") or 0)
        
        cur_total_sent = round(int(data_usage[count + 2]) / (1024 ** 3), 4)
        cur_total_receive = round(int(data_usage[count + 1]) / (1024 ** 3), 4)
        
        if status == "running":
            if total_sent <= cur_total_sent and total_receive <= cur_total_receive:
                total_sent = cur_total_sent
                total_receive = cur_total_receive
            else:
                now = datetime.now()
                ctime = now.strftime("%d/%m/%Y %H:%M:%S")
                traffic.append({
                    "time": ctime,
                    "total_receive": round(total_receive, 4),
                    "total_sent": round(total_sent, 4),
                    "total_data": round(total_receive + total_sent, 4)
                })
                total_sent = 0
                total_receive = 0
            
            # Update Redis
            r.hset(peer_key, "traffic", json.dumps(traffic))
            r.hset(peer_key, "total_receive", round(total_receive, 4))
            r.hset(peer_key, "total_sent", round(total_sent, 4))
            r.hset(peer_key, "total_data", round(total_receive + total_sent, 4))
        
        count += 3

# Get endpoint from all peers of a configuration
def get_endpoint(config_name):
    # Get endpoint
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " endpoints", shell=True)
    except Exception:
        return "stopped"
    
    r = get_redis_client()
    if not r:
        return "redis not available"
    
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    
    for i in range(int(len(data_usage) / 2)):
        public_key = data_usage[count]
        endpoint = data_usage[count + 1]
        
        # Update endpoint
        peer_key = get_peer_key(config_name, public_key)
        r.hset(peer_key, "endpoint", endpoint)
        
        count += 2

# Get allowed ips from all peers of a configuration
def get_allowed_ip(config_name, conf_peer_data):
    # Get allowed ip
    r = get_redis_client()
    if not r:
        return
    
    for peer in conf_peer_data["Peers"]:
        if "PublicKey" in peer:
            public_key = peer["PublicKey"]
            allowed_ips = peer.get('AllowedIPs', '(None)')
            
            # Update allowed IP
            peer_key = get_peer_key(config_name, public_key)
            r.hset(peer_key, "allowed_ip", allowed_ips)

"""
Helper Functions
"""
# Regex Match
def regex_match(regex, text):
    pattern = re.compile(regex)
    return pattern.search(text) is not None

# Check IP format (IPv4 only now)
# TODO: Add IPv6 support
def check_IP(ip):
    return regex_match("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}", ip)

# Clean IP
def clean_IP(ip):
    return ip.replace(' ', '')

# Clean IP with range
def clean_IP_with_range(ip):
    return clean_IP(ip).split(',')

# Check IP with range (IPv4 only now)
# TODO: Add IPv6 support
def check_IP_with_range(ip):
    return regex_match("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|\/)){4}(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|" +
                    "18|19|20|21|22|23|24|25|26|27|28|29|30|31|32)(,|$)", ip)

# Check allowed ips list
def check_Allowed_IPs(ip):
    ip = clean_IP_with_range(ip)
    for i in ip:
        if not check_IP_with_range(i): return False
    return True

# Check DNS
def check_DNS(dns):
    dns = dns.replace(' ','').split(',')
    status = True
    for i in dns:
        if not (regex_match("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}", i) or regex_match("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z]{0,61}[a-z]",i)):
            return False
    return True

# Check remote endpoint (Both IPv4 address and valid hostname)
# TODO: Add IPv6 support
def check_remote_endpoint(address):
    return (regex_match("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}", address) or regex_match("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z]{0,61}[a-z]",address))


"""
Dashboard Configuration Related
"""
# Read / Write Dashboard Config File
def get_dashboard_conf():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    return config
def set_dashboard_conf(config):
    config.write(open(dashboard_conf, "w"))

"""
Configuration Related
"""
# Get all keys from a configuration
def get_conf_peer_key(config_name):
    try:
        peer_key = subprocess.check_output("wg show " + config_name + " peers", shell=True)
        peer_key = peer_key.decode("UTF-8").split()
        return peer_key
    except Exception:
        return config_name + " is not running."

# Get numbers of connected peer of a configuration
def get_conf_running_peer_number(config_name):
    running = 0
    # Get latest handshakes
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " latest-handshakes", shell=True)
    except Exception:
        return "stopped"
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    now = datetime.now()
    b = timedelta(minutes=2)
    for i in range(int(len(data_usage) / 2)):
        minus = now - datetime.fromtimestamp(int(data_usage[count + 1]))
        if minus < b:
            running += 1
        count += 2
    return running

# Read [Interface] section from configuration file
def read_conf_file_interface(config_name):
    conf_location = wg_conf_path + "/" + config_name + ".conf"
    f = open(conf_location, 'r')
    file = f.read().split("\n")
    data = {}
    peers_start = 0
    for i in range(len(file)):
        if not regex_match("#(.*)", file[i]):
            if len(file[i]) > 0:
                if file[i] != "[Interface]":
                    tmp = re.split(r'\s*=\s*', file[i], 1)
                    if len(tmp) == 2:
                        data[tmp[0]] = tmp[1]
    f.close()
    return data

# Read the whole configuration file
def read_conf_file(config_name):
    conf_location = wg_conf_path + "/" + config_name + ".conf"
    f = open(conf_location, 'r')
    file = f.read().split("\n")
    
    # Parse thành dict chứa Interface và Peers
    conf_peer_data = {
        "Interface": {},
        "Peers": []
    }
    peers_start = 0
    for i in range(len(file)):
        if not regex_match("#(.*)", file[i]):
            if file[i] == "[Peer]":
                peers_start = i
                break
            else:
                if len(file[i]) > 0:
                    if file[i] != "[Interface]":
                        tmp = re.split(r'\s*=\s*', file[i], 1)
                        if len(tmp) == 2:
                            conf_peer_data['Interface'][tmp[0]] = tmp[1]
    conf_peers = file[peers_start:]
    peer = -1
    for i in conf_peers:
        if not regex_match("#(.*)", i):
            if i == "[Peer]":
                peer += 1
                conf_peer_data["Peers"].append({})
            elif peer > -1:
                if len(i) > 0:
                    tmp = re.split('\s*=\s*', i, 1)
                    if len(tmp) == 2:
                        conf_peer_data["Peers"][peer][tmp[0]] = tmp[1]

    f.close()
    return conf_peer_data

# Get latest handshake from all peers of a configuration
def get_latest_handshake(config_name, db, peers):
    # Get latest handshakes
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " latest-handshakes", shell=True)
    except Exception:
        return "stopped"
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    now = datetime.now()
    b = timedelta(minutes=2)
    for i in range(int(len(data_usage) / 2)):
        minus = now - datetime.fromtimestamp(int(data_usage[count + 1]))
        if minus < b:
            status = "running"
        else:
            status = "stopped"
        if int(data_usage[count + 1]) > 0:
            db.update({"latest_handshake": str(minus).split(".")[0], "status": status},
                      peers.id == data_usage[count])
        else:
            db.update({"latest_handshake": "(None)", "status": status}, peers.id == data_usage[count])
        count += 2

# Get transfer from all peers of a configuration
def get_transfer(config_name, db, peers):
    # Get transfer
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " transfer", shell=True)
    except Exception:
        return "stopped"
    
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    for i in range(int(len(data_usage) / 3)):
        cur_i = db.search(peers.id == data_usage[count])
        
        # Kiểm tra và khởi tạo giá trị mặc định
        total_sent = cur_i[0].get('total_sent', 0)  # Sử dụng get để lấy giá trị hoặc 0 nếu không tồn tại
        total_receive = cur_i[0].get('total_receive', 0)  # Tương tự cho total_receive
        traffic = cur_i[0].get('traffic', [])  # Khởi tạo traffic là danh sách rỗng nếu không tồn tại
        
        cur_total_sent = round(int(data_usage[count + 2]) / (1024 ** 3), 4)
        cur_total_receive = round(int(data_usage[count + 1]) / (1024 ** 3), 4)
        
        if cur_i[0]["status"] == "running":
            if total_sent <= cur_total_sent and total_receive <= cur_total_receive:
                total_sent = cur_total_sent
                total_receive = cur_total_receive
            else:
                now = datetime.now()
                ctime = now.strftime("%d/%m/%Y %H:%M:%S")
                traffic.append({
                    "time": ctime,
                    "total_receive": round(total_receive, 4),
                    "total_sent": round(total_sent, 4),
                    "total_data": round(total_receive + total_sent, 4)
                })
                total_sent = 0
                total_receive = 0
            
            db.update({
                "traffic": traffic,
                "total_receive": round(total_receive, 4),
                "total_sent": round(total_sent, 4),
                "total_data": round(total_receive + total_sent, 4)
            }, peers.id == data_usage[count])

        count += 3

# Get endpoint from all peers of a configuration
def get_endpoint(config_name, db, peers):
    # Get endpoint
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " endpoints", shell=True)
    except Exception:
        return "stopped"
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    for i in range(int(len(data_usage) / 2)):
        db.update({"endpoint": data_usage[count + 1]}, peers.id == data_usage[count])
        count += 2

# Get allowed ips from all peers of a configuration
def get_allowed_ip(config_name, db, peers, conf_peer_data):
    # Get allowed ip
    for i in conf_peer_data["Peers"]:
        db.update({"allowed_ip": i.get('AllowedIPs', '(None)')}, peers.id == i["PublicKey"])

# Look for new peers from WireGuard
def get_all_peers_data(config_name):
    """Get all peers data and synchronize with WireGuard"""
    # Get Redis connection
    r = get_redis_client()
    if not r:
        print("Redis connection not available")
        return []
    
    # Get WireGuard status
    conf_status = get_conf_status(config_name)
    if conf_status == "stopped":
        # Return peers from Redis if WireGuard is stopped
        return get_all_peers_from_redis(config_name)
    
    # Get peers from WireGuard directly instead of using get_wireguard_peers
    wg_peers = []
    try:
        # Get all public keys
        keys = get_conf_peer_key(config_name)
        if not isinstance(keys, list):
            return get_all_peers_from_redis(config_name)
        
        # Get dump from wireguard for handshake and transfer data
        try:
            dump_output = subprocess.check_output(
                f"wg show {config_name} dump", 
                shell=True
            ).decode('utf-8').strip().split("\n")
            
            # Skip header
            if len(dump_output) > 0:
                dump_output = dump_output[1:]
                
            # Process dump
            dump = {}
            for line in dump_output:
                peer_info = line.split("\t")
                if len(peer_info) >= 6:
                    peer_id = peer_info[0]
                    
                    # Parse handshake - convert to timestamp if possible
                    handshake = peer_info[4]
                    if handshake == "0":
                        handshake = "Never"
                    
                    dump[peer_id] = {
                        "latest_handshake": handshake,
                        "transfer_rx": peer_info[5],
                        "transfer_tx": peer_info[6]
                    }
        except Exception as e:
            print(f"Error getting dump data: {str(e)}")
            dump = {}
        
        # Process each peer
        for key in keys:
            peer = {"id": key}
            
            # Get allowed IPs
            try:
                allowed_ips = subprocess.check_output(
                    f"wg show {config_name} allowed-ips | grep {key}",
                    shell=True
                ).decode('utf-8').strip()
                
                if allowed_ips:
                    parts = allowed_ips.split("\t")
                    if len(parts) > 1:
                        peer["allowed_ip"] = parts[1].split(",")[0]
            except:
                peer["allowed_ip"] = ""
            
            # Get handshake and transfer data from dump
            if key in dump:
                peer_dump = dump[key]
                peer["latest_handshake"] = peer_dump.get("latest_handshake", "Never")
                peer["transfer_rx"] = peer_dump.get("transfer_rx", "0")
                peer["transfer_tx"] = peer_dump.get("transfer_tx", "0")
            else:
                peer["latest_handshake"] = "Never"
                peer["transfer_rx"] = "0"
                peer["transfer_tx"] = "0"
            
            wg_peers.append(peer)
    except Exception as e:
        print(f"Error getting peers from WireGuard: {str(e)}")
        return get_all_peers_from_redis(config_name)
    
    # Get peers from Redis
    redis_peers = get_all_peers_from_redis(config_name)
    redis_peers_dict = {peer['id']: peer for peer in redis_peers}
    
    # Update Redis with WireGuard data
    for wg_peer in wg_peers:
        peer_id = wg_peer['id']
        
        # Check if peer exists in Redis
        if peer_id in redis_peers_dict:
            # Update existing peer
            redis_peer = redis_peers_dict[peer_id]
            
            # Update fields from WireGuard
            update_data = {
                'latest_handshake': wg_peer.get('latest_handshake', ''),
                'allowed_ip': wg_peer.get('allowed_ip', ''),
                'transfer_rx': wg_peer.get('transfer_rx', '0'),
                'transfer_tx': wg_peer.get('transfer_tx', '0')
            }
            
            # Update peer data in Redis
            peer_key = get_peer_key(config_name, peer_id)
            r.hset(peer_key, mapping=update_data)
            
            # Update last seen if handshake is recent
            if wg_peer.get('latest_handshake', '') and wg_peer.get('latest_handshake', '') != 'Never':
                update_peer_last_seen(config_name, peer_id)
        else:
            # New peer found in WireGuard but not in Redis
            new_peer = {
                'name': f'Peer_{peer_id[:8]}',
                'allowed_ip': wg_peer.get('allowed_ip', ''),
                'DNS': DEFAULT_DNS,
                'endpoint_allowed_ip': DEFAULT_ENDPOINT_ALLOWED_IP,
                'private_key': '',
                'mtu': '',
                'keepalive': '',
                'latest_handshake': wg_peer.get('latest_handshake', ''),
                'transfer_rx': wg_peer.get('transfer_rx', '0'),
                'transfer_tx': wg_peer.get('transfer_tx', '0'),
                'created_at': datetime.now().isoformat()
            }
            
            # Save new peer to Redis
            save_peer_to_redis(config_name, peer_id, new_peer)
            
            # Add to local dictionary for the return value
            redis_peers_dict[peer_id] = new_peer
            redis_peers_dict[peer_id]['id'] = peer_id
    
    # Return all peers
    return list(redis_peers_dict.values())

# Search for peers
def get_peers(config_name, search="", sort="name"):
    """Get all peers with optional search and sorting"""
    # Get Redis connection
    r = get_redis_client()
    if not r:
        print("Redis connection not available")
        return []
    
    # Update peer data
    if should_update_db(config_name):
        get_all_peers_data(config_name)
    
    # Get all peers from Redis
    peers = get_all_peers_from_redis(config_name)
    
    # Apply search filter if provided
    if search:
        filtered_peers = []
        search = search.lower()
        for peer in peers:
            if (search in peer.get('name', '').lower() or 
                search in peer.get('allowed_ip', '').lower() or
                search in peer.get('id', '').lower()):
                filtered_peers.append(peer)
        peers = filtered_peers
    
    # Apply sorting
    if sort == "name":
        peers.sort(key=lambda x: x.get('name', '').lower())
    elif sort == "allowed_ip":
        # Convert IP to tuple of integers for proper sorting
        def ip_key(peer):
            try:
                ip = peer.get('allowed_ip', '0.0.0.0/0').split('/')[0]
                return tuple(int(n) for n in ip.split('.'))
            except:
                return (0, 0, 0, 0)
        peers.sort(key=ip_key)
    elif sort == "latest_handshake":
        # Sort by handshake time (newest first)
        def handshake_key(peer):
            try:
                if peer.get('latest_handshake', '') == 'Never':
                    return 0
                return int(peer.get('latest_handshake', 0))
            except:
                return 0
        peers.sort(key=handshake_key, reverse=True)
    elif sort == "transfer_rx":
        peers.sort(key=lambda x: int(x.get('transfer_rx', 0)), reverse=True)
    elif sort == "transfer_tx":
        peers.sort(key=lambda x: int(x.get('transfer_tx', 0)), reverse=True)
    
    return peers

# Get configuration total data
def get_conf_total_data(config_name):
    """Get total data usage for a configuration from Redis"""
    r = get_redis_client()
    if not r:
        return [0, 0, 0]
    
    upload_total = 0
    download_total = 0
    
    # Get all peers for this config
    peers = get_all_peers_from_redis(config_name)
    
    for peer in peers:
        upload_total += float(peer.get('total_sent', 0))
        download_total += float(peer.get('total_receive', 0))
        
        # Add traffic from history
        for traffic_entry in peer.get('traffic', []):
            upload_total += float(traffic_entry.get('total_sent', 0))
            download_total += float(traffic_entry.get('total_receive', 0))
    
    total = round(upload_total + download_total, 4)
    upload_total = round(upload_total, 4)
    download_total = round(download_total, 4)
    
    return [total, upload_total, download_total]

"""
Frontend Related Functions
"""
# Get configuration public key
def get_conf_pub_key(config_name):
    conf = configparser.ConfigParser(strict=False)
    conf.read(wg_conf_path + "/" + config_name + ".conf")
    pri = conf.get("Interface", "PrivateKey")
    pub = subprocess.check_output("echo '" + pri + "' | wg pubkey", shell=True)
    conf.clear()
    return pub.decode().strip("\n")

# Get configuration listen port
def get_conf_listen_port(config_name):
    conf = configparser.ConfigParser(strict=False)
    conf.read(wg_conf_path + "/" + config_name + ".conf")
    port = ""
    try:
        port = conf.get("Interface", "ListenPort")
    except:
        if get_conf_status(config_name) == "running":
            port = subprocess.check_output("wg show "+config_name+" listen-port", shell=True)
            port = port.decode("UTF-8")
    conf.clear()
    return port

# Get configuration status
def get_conf_status(config_name):
    ifconfig = dict(ifcfg.interfaces().items())
    if config_name in ifconfig.keys():
        return "running"
    else:
        return "stopped"

# Get all configuration as a list
def get_conf_list():
    conf = []
    for i in os.listdir(wg_conf_path):
        if regex_match("^(.{1,}).(conf)$", i):
            i = i.replace('.conf', '')
            temp = {"conf": i, "status": get_conf_status(i), "public_key": get_conf_pub_key(i)}
            if temp['status'] == "running":
                temp['checked'] = 'checked'
            else:
                temp['checked'] = ""
            conf.append(temp)
    if len(conf) > 0:
        conf = sorted(conf, key=itemgetter('conf'))
    return conf

# Generate private key
def gen_private_key():
    """Generate WireGuard private key with unique temp files to prevent race conditions"""
    import tempfile
    import os
    
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

# Generate public key
def gen_public_key(private_key):
    """Generate WireGuard public key from private key with unique temp files"""
    import tempfile
    import os
    
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

# Check if private key and public key match
def checkKeyMatch(private_key, public_key, config_name):
    """Check if private and public keys match using Redis"""
    result = gen_public_key(private_key)
    if result['status'] == 'failed':
        return result
    else:
        # Get Redis connection
        r = get_redis_client()
        if not r:
            return {'status': 'failed', 'msg': 'Redis connection not available'}
            
        # Check if peer exists
        peer_key = get_peer_key(config_name, public_key)
        if not r.exists(peer_key):
            return {'status': 'failed', 'msg': 'Peer not found in database'}
            
        # Check if keys match
        if result['data'] != public_key:
            return {'status': 'failed', 'msg': 'Private key does not match with the public key.'}
        else:
            return {'status': 'success'}

# Check if there is repeated allowed IP
def check_repeat_allowed_IP(public_key, ip, config_name):
    """Check if an allowed IP is already in use by another peer"""
    r = get_redis_client()
    if not r:
        return {'status': 'failed', 'msg': 'Redis connection not available'}
    
    # Check if the peer exists
    peer_key = get_peer_key(config_name, public_key)
    if not r.exists(peer_key):
        return {'status': 'failed', 'msg': 'Peer does not exist'}
    
    # Get all peers and check for IP conflict
    peers = get_all_peers_from_redis(config_name)
    for peer in peers:
        if peer.get('id') != public_key and peer.get('allowed_ip') == ip:
            return {'status': 'failed', 'msg': "Allowed IP already taken by another peer."}
    
    return {'status': 'success'}


"""
Flask Functions
"""

# Before request
@app.before_request
def auth_req():
    conf = configparser.ConfigParser(strict=False)
    conf.read(dashboard_conf)
    req = conf.get("Server", "auth_req")
    session['update'] = update
    session['dashboard_version'] = dashboard_version
    if req == "true":
        if '/static/' not in request.path and \
                request.endpoint != "signin" and \
                request.endpoint != "signout" and \
                request.endpoint != "auth" and \
                "username" not in session:
            print("User not loggedin - Attemped access: " + str(request.endpoint))
            if request.endpoint != "index":
                session['message'] = "You need to sign in first!"
            else:
                session['message'] = ""
            return redirect(url_for("signin"))
    else:
        if request.endpoint in ['signin', 'signout', 'auth', 'settings', 'update_acct', 'update_pwd',
                                'update_app_ip_port', 'update_wg_conf_path']:
            return redirect(url_for("index"))

"""
Sign In / Sign Out
"""
#Sign In
@app.route('/signin', methods=['GET'])
def signin():
    message = ""
    if "message" in session:
        message = session['message']
        session.pop("message")
    return render_template('signin.html', message=message)

#Sign Out
@app.route('/signout', methods=['GET'])
def signout():
    if "username" in session:
        session.pop("username")
    message = "Sign out successfully!"
    return render_template('signin.html', message=message)

# Authentication
@app.route('/auth', methods=['POST'])
def auth():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    password = hashlib.sha256(request.form['password'].encode())
    if password.hexdigest() == config["Account"]["password"] and request.form['username'] == config["Account"][
        "username"]:
        session['username'] = request.form['username']
        config.clear()
        return redirect(url_for("index"))
    else:
        session['message'] = "Username or Password is incorrect."
        config.clear()
        return redirect(url_for("signin"))

"""
Index Page Related
"""
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', conf=get_conf_list())

"""
Setting Page Related
"""
# Setting Page
@app.route('/settings', methods=['GET'])
def settings():
    message = ""
    status = ""
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    if "message" in session and "message_status" in session:
        message = session['message']
        status = session['message_status']
        session.pop("message")
        session.pop("message_status")
    required_auth = config.get("Server", "auth_req")
    return render_template('settings.html', conf=get_conf_list(), message=message, status=status,
                           app_ip=config.get("Server", "app_ip"), app_port=config.get("Server", "app_port"),
                           required_auth=required_auth, wg_conf_path=config.get("Server", "wg_conf_path"),
                           peer_global_DNS=config.get("Peers", "peer_global_DNS"),
                           peer_endpoint_allowed_ip=config.get("Peers", "peer_endpoint_allowed_ip"),
                           peer_mtu=config.get("Peers", "peer_mtu"),
                           peer_keepalive=config.get("Peers","peer_keep_alive"),
                           peer_remote_endpoint=config.get("Peers","remote_endpoint"))

# Update account username
@app.route('/update_acct', methods=['POST'])
def update_acct():
    if len(request.form['username']) == 0:
        session['message'] = "Username cannot be empty."
        session['message_status'] = "danger"
        return redirect(url_for("settings"))
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    config.set("Account", "username", request.form['username'])
    try:
        config.write(open(dashboard_conf, "w"))
        session['message'] = "Username update successfully!"
        session['message_status'] = "success"
        session['username'] = request.form['username']
        config.clear()
        return redirect(url_for("settings"))
    except Exception:
        session['message'] = "Username update failed."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))

# Update peer default settting
@app.route('/update_peer_default_config', methods=['POST'])
def update_peer_default_config():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    if len(request.form['peer_endpoint_allowed_ip']) == 0 or \
            len(request.form['peer_global_DNS']) == 0 or \
            len(request.form['peer_remote_endpoint']) == 0:
        session['message'] = "Please fill in all required boxes."
        session['message_status'] = "danger"
        return redirect(url_for("settings"))
    # Check DNS Format
    DNS = request.form['peer_global_DNS']
    if not check_DNS(DNS):
        session['message'] = "Peer DNS Format Incorrect."
        session['message_status'] = "danger"
        return redirect(url_for("settings"))
    DNS = DNS.replace(" ","").split(',')
    DNS = ",".join(DNS)

    # Check Endpoint Allowed IPs
    ip = request.form['peer_endpoint_allowed_ip']
    if not check_Allowed_IPs(ip):
        session['message'] = "Peer Endpoint Allowed IPs Format Incorrect. Example: 192.168.1.1/32 or 192.168.1.1/32,192.168.1.2/32"
        session['message_status'] = "danger"
        return redirect(url_for("settings"))
    # Check MTU Format
    if len(request.form['peer_mtu']) > 0:
        try:
            mtu = int(request.form['peer_mtu'])
        except:
            session['message'] = "MTU format is incorrect."
            session['message_status'] = "danger"
            return redirect(url_for("settings"))
    # Check keepalive Format
    if len(request.form['peer_keep_alive']) > 0:
        try:
            mtu = int(request.form['peer_keep_alive'])
        except:
            session['message'] = "Persistent keepalive format is incorrect."
            session['message_status'] = "danger"
            return redirect(url_for("settings"))
    # Check peer remote endpoint
    if not check_remote_endpoint(request.form['peer_remote_endpoint']):
        session[
            'message'] = "Peer Remote Endpoint format is incorrect. It can only be a valid IP address or valid domain (without http:// or https://). "
        session['message_status'] = "danger"
        return redirect(url_for("settings"))

    config.set("Peers", "remote_endpoint", request.form['peer_remote_endpoint'])
    config.set("Peers", "peer_keep_alive", request.form['peer_keep_alive'])
    config.set("Peers", "peer_mtu", request.form['peer_mtu'])
    config.set("Peers", "peer_endpoint_allowed_ip", ','.join(clean_IP_with_range(ip)))
    config.set("Peers", "peer_global_DNS", DNS)


    try:
        config.write(open(dashboard_conf, "w"))
        session['message'] = "Peer Default Settings update successfully!"
        session['message_status'] = "success"
        config.clear()
        return redirect(url_for("settings"))
    except Exception:
        session['message'] = "Peer Default Settings update failed."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))

# Update dashboard password
@app.route('/update_pwd', methods=['POST'])
def update_pwd():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    if hashlib.sha256(request.form['currentpass'].encode()).hexdigest() == config.get("Account", "password"):
        if hashlib.sha256(request.form['newpass'].encode()).hexdigest() == hashlib.sha256(
                request.form['repnewpass'].encode()).hexdigest():
            config.set("Account", "password", hashlib.sha256(request.form['repnewpass'].encode()).hexdigest())
            try:
                config.write(open(dashboard_conf, "w"))
                session['message'] = "Password update successfully!"
                session['message_status'] = "success"
                config.clear()
                return redirect(url_for("settings"))
            except Exception:
                session['message'] = "Password update failed"
                session['message_status'] = "danger"
                config.clear()
                return redirect(url_for("settings"))
        else:
            session['message'] = "Your New Password does not match."
            session['message_status'] = "danger"
            config.clear()
            return redirect(url_for("settings"))
    else:
        session['message'] = "Your Password does not match."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))

# Update dashboard IP and port
@app.route('/update_app_ip_port', methods=['POST'])
def update_app_ip_port():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    config.set("Server", "app_ip", request.form['app_ip'])
    config.set("Server", "app_port", request.form['app_port'])
    config.write(open(dashboard_conf, "w"))
    config.clear()
    os.system('bash wgd.sh restart')

# Update WireGuard configuration file path
@app.route('/update_wg_conf_path', methods=['POST'])
def update_wg_conf_path():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    config.set("Server", "wg_conf_path", request.form['wg_conf_path'])
    config.write(open(dashboard_conf, "w"))
    session['message'] = "WireGuard Configuration Path Update Successfully!"
    session['message_status'] = "success"
    config.clear()
    os.system('bash wgd.sh restart')

"""
Configuration Page Related
"""
# Update configuration sorting
@app.route('/update_dashboard_sort', methods=['POST'])
def update_dashbaord_sort():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    data = request.get_json()
    sort_tag = ['name', 'status', 'allowed_ip']
    if data['sort'] in sort_tag:
        config.set("Server", "dashboard_sort", data['sort'])
    else:
        config.set("Server", "dashboard_sort", 'status')
    config.write(open(dashboard_conf, "w"))
    config.clear()
    return "true"

# Update configuration refresh interval
@app.route('/update_dashboard_refresh_interval', methods=['POST'])
def update_dashboard_refresh_interval():
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    config.set("Server", "dashboard_refresh_interval", str(request.form['interval']))
    config.write(open(dashboard_conf, "w"))
    config.clear()
    return "true"

# Configuration Page
@app.route('/configuration/<config_name>', methods=['GET'])
def conf(config_name):
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    conf_data = {
        "name": config_name,
        "status": get_conf_status(config_name),
        "checked": ""
    }
    if conf_data['status'] == "stopped":
        conf_data['checked'] = "nope"
    else:
        conf_data['checked'] = "checked"
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    config_list = get_conf_list()
    if config_name not in [conf['conf'] for conf in config_list]:
        return render_template('index.html', conf=get_conf_list())
    return render_template('configuration.html', conf=get_conf_list(), conf_data=conf_data,
                           dashboard_refresh_interval=int(config.get("Server", "dashboard_refresh_interval")),
                           DNS=config.get("Peers", "peer_global_DNS"),
                           endpoint_allowed_ip=config.get("Peers", "peer_endpoint_allowed_ip"),
                           title=config_name,
                           mtu=config.get("Peers","peer_MTU"),
                           keep_alive=config.get("Peers","peer_keep_alive"))

# Get configuration details
@app.route('/get_conf/<config_name>', methods=['GET'])
def get_conf(config_name):
    """Get configuration details for a specific config"""
    config_interface = read_conf_file_interface(config_name)
    search = request.args.get('search', '')
    
    # Parse the search query
    search = urllib.parse.unquote(search)
    
    # Get configuration details
    config = get_dashboard_conf()
    sort = config.get("Server", "dashboard_sort", fallback="name")
    peer_display_mode = config.get("Peers", "peer_display_mode", fallback="table")
    
    # Get address
    if "Address" not in config_interface:
        conf_address = "N/A"
    else:
        conf_address = config_interface['Address']
    
    # Get peer data
    peer_data = get_peers(config_name, search, sort)
    
    # Get total data transfer - returns [total, upload_total, download_total]
    total_data = get_conf_total_data(config_name)
    
    # Build conf_data structure like before
    conf_data = {
        "peer_data": peer_data,
        "name": config_name,
        "status": get_conf_status(config_name),
        "total_data_usage": total_data,
        "public_key": get_conf_pub_key(config_name),
        "listen_port": get_conf_listen_port(config_name),
        "running_peer": get_conf_running_peer_number(config_name),
        "conf_address": conf_address,
        "total_rx": total_data[2],  # download_total
        "total_tx": total_data[1]   # upload_total
    }
    
    # Add checked status for UI
    if conf_data['status'] == "stopped":
        conf_data['checked'] = "nope"
    else:
        conf_data['checked'] = "checked"
    
    # Render the template like before
    return render_template('get_conf.html', conf_data=conf_data, 
                          wg_ip=config.get("Peers", "remote_endpoint"), 
                          sort_tag=sort,
                          dashboard_refresh_interval=int(config.get("Server", "dashboard_refresh_interval")), 
                          peer_display_mode=peer_display_mode)

# Turn on / off a configuration
@app.route('/switch/<config_name>', methods=['GET'])
def switch(config_name):
    if "username" not in session:
        print("not loggedin")
        return redirect(url_for("signin"))
    status = get_conf_status(config_name)
    if status == "running":
        try:
            status = subprocess.check_output("wg-quick down " + config_name, shell=True)
        except Exception:
            return redirect('/')
    elif status == "stopped":
        try:
            status = subprocess.check_output("wg-quick up " + config_name, shell=True)
        except Exception:
            return redirect('/')

    return redirect(request.referrer)

# Add peer
@app.route('/add_peer/<config_name>', methods=['POST'])
def add_peer(config_name):
    """Add a new peer to WireGuard and Redis"""
    if get_conf_status(config_name) == "stopped":
        return "Your need to turn on " + config_name + " first."
    
    data = request.get_json()
    name = data['name']
    DNS = data['DNS']
    allowed_ip = data['allowed_ip']
    endpoint_allowed_ip = data['endpoint_allowed_ip']
    
    # Validate data
    if not check_IP(allowed_ip):
        return "Allowed IP format is incorrect."
    
    if not check_IP_with_range(endpoint_allowed_ip):
        return "Endpoint Allowed IPs format is incorrect."
    
    if not check_DNS(DNS):
        return "DNS format is incorrect."
    
    if len(data['MTU']) != 0:
        try:
            mtu = int(data['MTU'])
        except:
            return "MTU format is not correct."
    
    if len(data['keep_alive']) != 0:
        try:
            keep_alive = int(data['keep_alive'])
        except:
            return "Persistent Keepalive format is not correct."
    
    # Check IP availability
    r = get_redis_client()
    if not r:
        return "Redis connection not available"
    
    # Check for IP conflicts
    peers = get_all_peers_from_redis(config_name)
    for peer in peers:
        if peer.get('allowed_ip') == allowed_ip:
            return "Allowed IP already taken by another peer."
    
    # Get server details
    pub_conf_key = get_conf_pub_key(config_name)
    
    # Create new keys
    private_key = subprocess.check_output('wg genkey', shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f'echo "{private_key}" | wg pubkey', shell=True).decode('utf-8').strip()
    
    try:
        # Add to WireGuard
        status = subprocess.check_output(f'wg set {config_name} peer {public_key} allowed-ips {allowed_ip}',
                                        shell=True, stderr=subprocess.STDOUT)
        
        # Save configuration with locking
        if not save_wireguard_config(config_name):
            return "Failed to save WireGuard configuration"
        
        # Save to Redis
        peer_data = {
            "name": name,
            "private_key": private_key,
            "allowed_ip": allowed_ip,
            "DNS": DNS,
            "endpoint_allowed_ip": endpoint_allowed_ip,
            "mtu": data['MTU'],
            "keepalive": data['keep_alive'],
            "created_at": datetime.now().isoformat()
        }
        
        save_peer_to_redis(config_name, public_key, peer_data)
        
        # Force persistence
        r.save()
        
        # Return new peer info
        return jsonify({
            "status": "success",
            "peer_id": public_key,
            "private_key": private_key
        })
    except subprocess.CalledProcessError as exc:
        return exc.output.decode("UTF-8").strip()

# Remove peer
@app.route('/remove_peer/<config_name>', methods=['POST'])
def remove_peer(config_name):
    """Remove a peer from WireGuard and Redis"""
    if get_conf_status(config_name) == "stopped":
        return "Your need to turn on " + config_name + " first."
    
    data = request.get_json()
    delete_key = data['peer_id']
    keys = get_conf_peer_key(config_name)
    
    if type(keys) != list:
        return config_name + " is not running."
    
    if delete_key not in keys:
        return "This key does not exist"
    
    # Get Redis connection
    r = get_redis_client()
    if not r:
        return "Redis connection not available"
    
    try:
        # Remove from WireGuard
        status = subprocess.check_output("wg set " + config_name + " peer " + delete_key + " remove", shell=True,
                                        stderr=subprocess.STDOUT)
        
        # Save configuration with locking
        if not save_wireguard_config(config_name):
            return "Failed to save WireGuard configuration"
        
        # Remove from Redis
        delete_peer_from_redis(config_name, delete_key)
        
        # Force persistence
        r.save()
        
        return "true"
    except subprocess.CalledProcessError as exc:
        return exc.output.strip()

# Save peer settings
@app.route('/save_peer_setting/<config_name>', methods=['POST'])
def save_peer_setting(config_name):
    """Save peer settings to Redis"""
    data = request.get_json()
    id = data['id']
    name = data['name']
    private_key = data['private_key']
    DNS = data['DNS']
    allowed_ip = data['allowed_ip']
    endpoint_allowed_ip = data['endpoint_allowed_ip']
    
    # Get Redis connection
    r = get_redis_client()
    if not r:
        return jsonify({"status": "failed", "msg": "Redis connection not available"})
    
    # Check if peer exists
    peer_key = get_peer_key(config_name, id)
    if not r.exists(peer_key):
        return jsonify({"status": "failed", "msg": "This peer does not exist."})
    
    # Validate data
    if not check_IP_with_range(endpoint_allowed_ip):
        return jsonify({"status": "failed", "msg": "Endpoint Allowed IPs format is incorrect."})
    
    if not check_DNS(DNS):
        return jsonify({"status": "failed", "msg": "DNS format is incorrect."})
    
    if len(data['MTU']) != 0:
        try:
            mtu = int(data['MTU'])
        except:
            return jsonify({"status": "failed", "msg": "MTU format is not correct."})
    
    if len(data['keep_alive']) != 0:
        try:
            keep_alive = int(data['keep_alive'])
        except:
            return jsonify({"status": "failed", "msg": "Persistent Keepalive format is not correct."})
    
    if private_key != "":
        check_key = checkKeyMatch(private_key, id, config_name)
        if check_key['status'] == "failed":
            return jsonify(check_key)
    
    # Check for IP conflicts
    check_ip = check_repeat_allowed_IP(id, allowed_ip, config_name)
    if check_ip['status'] == "failed":
        return jsonify(check_ip)
    
    try:
        if allowed_ip == "": allowed_ip = '""'
        change_ip = subprocess.check_output(f'wg set {config_name} peer {id} allowed-ips {allowed_ip}',
                                            shell=True, stderr=subprocess.STDOUT)
        
        # Save configuration with locking
        if not save_wireguard_config(config_name):
            return jsonify({"status": "failed", "msg": "Failed to save WireGuard configuration"})
            
        if change_ip.decode("UTF-8") != "":
            return jsonify({"status": "failed", "msg": change_ip.decode("UTF-8")})
        
        # Update Redis
        update_data = {
            "name": name,
            "private_key": private_key,
            "DNS": DNS,
            "endpoint_allowed_ip": endpoint_allowed_ip,
            "mtu": data['MTU'],
            "keepalive": data['keep_alive']
        }
        
        r.hset(peer_key, mapping=update_data)
        
        # Force persistence
        r.save()
        
        return jsonify({"status": "success", "msg": ""})
    except subprocess.CalledProcessError as exc:
        return jsonify({"status": "failed", "msg": str(exc.output.decode("UTF-8").strip())})

# Get peer settings
@app.route('/get_peer_data/<config_name>', methods=['POST'])
def get_peer_name(config_name):
    """Get peer data from Redis"""
    data = request.get_json()
    id = data['id']
    
    # Get Redis connection
    r = get_redis_client()
    if not r:
        return jsonify({"status": "failed", "msg": "Redis connection not available"})
    
    # Get peer data
    peer_data = get_peer_from_redis(config_name, id)
    
    if not peer_data:
        return jsonify({"status": "failed", "msg": "Peer not found"})
    
    # Return formatted data
    result = {
        "name": peer_data.get('name', ''),
        "allowed_ip": peer_data.get('allowed_ip', ''),
        "DNS": peer_data.get('DNS', ''),
        "private_key": peer_data.get('private_key', ''),
        "endpoint_allowed_ip": peer_data.get('endpoint_allowed_ip', ''),
        "mtu": peer_data.get('mtu', ''),
        "keep_alive": peer_data.get('keepalive', '')
    }
    
    return jsonify(result)

# Generate a private key
@app.route('/generate_peer', methods=['GET'])
def generate_peer():
    return jsonify(gen_private_key())

# Generate a public key from a private key
@app.route('/generate_public_key', methods=['POST'])
def generate_public_key():
    data = request.get_json()
    private_key = data['private_key']
    return jsonify(gen_public_key(private_key))

# Check if both key match
@app.route('/check_key_match/<config_name>', methods=['POST'])
def check_key_match(config_name):
    data = request.get_json()
    private_key = data['private_key']
    public_key = data['public_key']
    return jsonify(checkKeyMatch(private_key, public_key, config_name))

# Download configuration file
@app.route('/download/<config_name>', methods=['GET'])
def download(config_name):
    """Generate and download a peer configuration file"""
    id = request.args.get('id')
    
    # Get Redis connection
    r = get_redis_client()
    if not r:
        return redirect("/configuration/" + config_name)
    
    # Get peer data
    peer_data = get_peer_from_redis(config_name, id)
    
    if not peer_data or 'private_key' not in peer_data or not peer_data['private_key']:
        return redirect("/configuration/" + config_name)
    
    config = get_dashboard_conf()
    public_key = get_conf_pub_key(config_name)
    listen_port = get_conf_listen_port(config_name)
    endpoint = config.get("Peers", "remote_endpoint") + ":" + listen_port
    
    private_key = peer_data['private_key']
    allowed_ip = peer_data['allowed_ip']
    DNS = peer_data['DNS']
    endpoint_allowed_ip = peer_data['endpoint_allowed_ip']
    filename = peer_data['name']
    
    # Generate filename
    if len(filename) == 0:
        filename = "Untitled_Peers"
    else:
        # Clean filename
        illegal_filename = [".", ",", "/", "?", "<", ">", "\\", ":", "*", '|' '\"', "com1", "com2", "com3",
                            "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4",
                        "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "con", "nul", "prn"]
        for i in illegal_filename:
            filename = filename.replace(i, "")
        if len(filename) == 0:
            filename = "Untitled_Peer"
        filename = "".join(filename.split(' '))
    
    filename = filename + "_" + config_name
    
    # Generate config
    def generate(private_key, allowed_ip, DNS, public_key, endpoint):
        yield "[Interface]\nPrivateKey = " + private_key + "\nAddress = " + allowed_ip + "\nDNS = " + DNS + "\n\n[Peer]\nPublicKey = " + public_key + "\nAllowedIPs = "+endpoint_allowed_ip+"\nEndpoint = " + endpoint
    
    return app.response_class(generate(private_key, allowed_ip, DNS, public_key, endpoint),
                            mimetype='text/conf',
                            headers={"Content-Disposition": "attachment;filename=" + filename + ".conf"})

# Switch peer displate mode
@app.route('/switch_display_mode/<mode>', methods=['GET'])
def switch_display_mode(mode):
    if mode in ['list','grid']:
        config.read(dashboard_conf)
        config.set("Peers", "peer_display_mode", mode)
        config.write(open(dashboard_conf, "w"))
        return "true"
    else:
        return "false"


"""
Dashboard Tools Related
"""
# Get all IP for ping
@app.route('/get_ping_ip', methods=['POST'])
def get_ping_ip():
    config = request.form['config']
    
    # Get Redis connection
    r = get_redis_client()
    if not r:
        return "Error: Redis connection not available"
    
    # Get all peers from Redis
    peers = get_all_peers_from_redis(config)
    
    html = ""
    for peer in peers:
        peer_id = peer.get('id', '')
        peer_name = peer.get('name', 'Unknown')
        
        html += f'<optgroup label="{peer_name} - {peer_id}">'
        
        # Process allowed IPs
        allowed_ip = peer.get('allowed_ip', '')
        if allowed_ip:
            allowed_ips = allowed_ip.split(',')
            for ip in allowed_ips:
                ip_parts = ip.split('/')
                if len(ip_parts) == 2:
                    html += f'<option value="{ip_parts[0]}">{ip_parts[0]}</option>'
        
        # Process endpoint
        endpoint = peer.get('endpoint', '')
        if endpoint:
            endpoint_parts = endpoint.split(':')
            if len(endpoint_parts) == 2:
                html += f'<option value="{endpoint_parts[0]}">{endpoint_parts[0]}</option>'
        
        html += '</optgroup>'
    
    return html

# Ping IP
@app.route('/ping_ip', methods=['POST'])
def ping_ip():
    try:
        result = ping('' + request.form['ip'] + '', count=int(request.form['count']), privileged=True, source=None)
        returnjson = {
            "address": result.address,
            "is_alive": result.is_alive,
            "min_rtt": result.min_rtt,
            "avg_rtt": result.avg_rtt,
            "max_rtt": result.max_rtt,
            "package_sent": result.packets_sent,
            "package_received": result.packets_received,
            "package_loss": result.packet_loss
        }
        if returnjson['package_loss'] == 1.0:
            returnjson['package_loss'] = returnjson['package_sent']


        return jsonify(returnjson)
    except Exception:
        return "Error"

# Traceroute IP
@app.route('/traceroute_ip', methods=['POST'])
def traceroute_ip():
    try:
        result = traceroute('' + request.form['ip'] + '', first_hop=1, max_hops=30, count=1, fast=True)
        returnjson = []
        last_distance = 0
        for hop in result:
            if last_distance + 1 != hop.distance:
                returnjson.append({"hop": "*", "ip": "*", "avg_rtt": "", "min_rtt": "", "max_rtt": ""})
            returnjson.append({"hop": hop.distance, "ip": hop.address, "avg_rtt": hop.avg_rtt, "min_rtt": hop.min_rtt,
                               "max_rtt": hop.max_rtt})
            last_distance = hop.distance
        return jsonify(returnjson)
    except Exception:
        return "Error"


@app.route('/create_client/<config_name>', methods=['POST'])
def create_client(config_name):
    cleanup_inactive_peers()
    
    # Get Redis connection
    r = get_redis_client()
    if not r:
        return jsonify({"error": "Redis connection not available"}), 500
    
    data = request.get_json()
    keys = get_conf_peer_key(config_name)
    private_key = ""
    public_key = ""
    checkExist = False
    config_content = ""

    # Get all peers for this config to check for existing name
    peers = get_all_peers_from_redis(config_name)
    # Check if peer with given name already exists
    for peer in peers:
        print("peer:",peer)
        if peer.get("name") == data["name"]:
            print("peer:",peer.get('allowed_ip', ''))
            config_content = f"""# {peer['name']}
            
PrivateKey = {peer.get('private_key', '')}
Address = {peer.get('allowed_ip', '')}
DNS = {DEFAULT_DNS}

[Peer]
PublicKey = {get_conf_pub_key(config_name)}
Endpoint = {peer.get('endpoint_allowed_ip', DEFAULT_ENDPOINT_ALLOWED_IP)}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = {data.get('keep_alive', 21)}
"""
            checkExist = True
            break
            
    if not checkExist:
        # Generate new key pair if peer doesn't exist
        check = False
        while not check:
            key = gen_private_key()
            private_key = key["private_key"]
            public_key = key["public_key"]
            if len(public_key) != 0 and public_key not in keys:
                check = True
        
        # Find available IP in the 10.66.66.x range
        existing_ips = []
        for peer in peers:
            print("peer 1870:",peer.get('allowed_ip', ''))
            allowed_ip = peer.get('allowed_ip', '')
            if allowed_ip and allowed_ip.startswith(BASE_IP):
                try:
                    ip_last_octet = int(allowed_ip.split('.')[3].split('/')[0])
                    existing_ips.append(ip_last_octet)
                except (IndexError, ValueError):
                    pass
                    
        next_ip = 2
        for ip in range(2, 255, 1):
            if ip not in existing_ips:
                next_ip = ip
                break
                
        allowed_ips = f"{BASE_IP}.{next_ip}/32"
        print("current ip:",allowed_ips)
        # Check for IP conflicts
        ip_conflict = False
        for peer in peers:
            if peer.get('allowed_ip') == allowed_ips:
                ip_conflict = True
                break
                
        if ip_conflict:
            return jsonify({"error": "IP already exists"}), 409
            
        try:
            # Add to WireGuard
            status = subprocess.check_output(
                f"wg set {config_name} peer {public_key} allowed-ips {allowed_ips}", 
                shell=True, stderr=subprocess.STDOUT
            )
            
            # Save configuration with locking
            if not save_wireguard_config(config_name):
                return jsonify({"error": "Failed to save WireGuard configuration"}), 500
            
            # Get server details
            server_public_key = get_conf_pub_key(config_name)
            listen_port = get_conf_listen_port(config_name)
            config = get_dashboard_conf()
            endpoint = f"{config.get('Peers', 'remote_endpoint')}:{listen_port}"
            
            # Save peer to Redis
            peer_data = {
                "name": data['name'],
                "private_key": private_key,
                "DNS": DEFAULT_DNS,
                "endpoint_allowed_ip": endpoint,
                "allowed_ip": allowed_ips,
                "status": "stopped",
                "public_key": server_public_key,
                "mtu": config.get("Peers", "peer_mtu", fallback="1420"),
                "keepalive": data.get('keep_alive', 25),
                "created_at": datetime.now().isoformat()
            }
            
            save_peer_to_redis(config_name, public_key, peer_data)
            
            # Create filename
            filename = data["name"]
            if len(filename) == 0:
                filename = "Untitled_Peers"
            else:
                # Clean filename
                illegal_filename = [".", ",", "/", "?", "<", ">", "\\", ":", "*", '|', '\"', "com1", "com2", "com3",
                                "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4",
                            "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "con", "nul", "prn"]
                for i in illegal_filename:
                    filename = filename.replace(i, "")
                if len(filename) == 0:
                    filename = "Untitled_Peer"
                filename = "".join(filename.split(' '))
                filename = f"{filename}_{config_name}"
                
            # Create config content
            config_content = f"""# {data['name']}
[Interface]
PrivateKey = {private_key}
Address = {allowed_ips}
DNS = {DEFAULT_DNS}

[Peer]
PublicKey = {server_public_key}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = {data.get('keep_alive', 25)}
"""

        except subprocess.CalledProcessError as exc:
            return exc.output.decode('utf-8').strip()
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Return config file
    response = make_response(config_content)
    response.headers['Content-Disposition'] = f'attachment; filename="{data["name"]}_wg.conf"'
    return response

import requests

def get_public_ip():
    response = requests.get("https://ifconfig.me")
    # print(response.text)
    return response.text.strip()

# Configure Redis persistence
def configure_redis_persistence():
    """Configure Redis to save data to disk properly"""
    r = get_redis_client()
    if not r:
        print("[ERROR] Failed to configure Redis persistence - connection failed")
        return False
    
    try:
        # Check if persistence is already configured
        config = r.config_get('save')
        
        # Configure automatic saving
        # Save if at least 1 key changes in 60 seconds
        r.config_set('save', '60 1')
        
        # Force an immediate save
        save_result = r.save()
        print(f"[INFO] Redis persistence configured, save result: {save_result}")
        
        return True
    except redis.exceptions.ResponseError as e:
        # This can happen in protected mode or when CONFIG commands are disabled
        print(f"[WARNING] Could not configure Redis persistence: {str(e)}")
        print("[WARNING] Make sure your Redis configuration allows persistence")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to configure Redis persistence: {str(e)}")
        return False

"""
Dashboard Initialization
"""
def init_dashboard():
    remote_endpoint=get_public_ip()
    # print("remote_endpoint:",remote_endpoint)
    # Set Default INI File
    if not os.path.isfile("wg-dashboard.ini"):
        conf_file = open("wg-dashboard.ini", "w+")
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    
    # Try to configure Redis persistence
    configure_redis_persistence()
    
    # Defualt dashboard account setting
    if "Account" not in config:
        config['Account'] = {}
    if "username" not in config['Account']:
        config['Account']['username'] = 'admin'
    if "password" not in config['Account']:
        config['Account']['password'] = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'
    # Defualt dashboard server setting
    if "Server" not in config:
        config['Server'] = {}
    if 'wg_conf_path' not in config['Server']:
        config['Server']['wg_conf_path'] = '/etc/wireguard'
    if 'app_ip' not in config['Server']:
        config['Server']['app_ip'] = '0.0.0.0'
    if 'app_port' not in config['Server']:
        config['Server']['app_port'] = '10086'
    if 'auth_req' not in config['Server']:
        config['Server']['auth_req'] = 'true'
    if 'version' not in config['Server'] or config['Server']['version'] != dashboard_version:
        config['Server']['version'] = dashboard_version
    if 'dashboard_refresh_interval' not in config['Server']:
        config['Server']['dashboard_refresh_interval'] = '60000'
    if 'dashboard_sort' not in config['Server']:
        config['Server']['dashboard_sort'] = 'status'
    # Defualt dashboard peers setting
    if "Peers" not in config:
        config['Peers'] = {}
    if 'peer_global_DNS' not in config['Peers']:
        config['Peers']['peer_global_DNS'] = '1.1.1.1'
    if 'peer_endpoint_allowed_ip' not in config['Peers']:
        config['Peers']['peer_endpoint_allowed_ip'] = '0.0.0.0/0'
    if 'peer_display_mode' not in config['Peers']:
        config['Peers']['peer_display_mode'] = 'grid'
    if 'remote_endpoint' not in config['Peers']:
        # config['Peers']['remote_endpoint'] = ifcfg.default_interface()['inet']
        config['Peers']['remote_endpoint'] =remote_endpoint
    if 'peer_MTU' not in config['Peers']:
        config['Peers']['peer_MTU'] = "1420"
    if 'peer_keep_alive' not in config['Peers']:
        config['Peers']['peer_keep_alive'] = "21"
    config.write(open(dashboard_conf, "w"))
    config.clear()
import signal
import sys
if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    init_dashboard()
    config = configparser.ConfigParser(strict=False)
    config.read('wg-dashboard.ini')
    app_ip = config.get("Server", "app_ip")
    app_port = config.get("Server", "app_port")
    wg_conf_path = config.get("Server", "wg_conf_path")
    config.clear()
    app.run(host=app_ip, debug=False, port=app_port)

def get_all_configs():
    """Get all WireGuard configurations"""
    configs = []
    
    # Get Redis connection
    r = get_redis_client()
    if not r:
        print("Redis connection not available")
        return configs
    
    try:
        # Get all config names from the system
        config_files = subprocess.check_output("find /etc/wireguard -name '*.conf' -type f", 
                                              shell=True, stderr=subprocess.STDOUT)
        config_files = config_files.decode("utf-8").strip().split("\n")
        
        # If no configs found, return empty list
        if not config_files or config_files[0] == '':
            return configs
        
        # Process each configuration
        for conf_file in config_files:
            config_name = os.path.basename(conf_file).replace(".conf", "")
            
            # Get status
            status = get_conf_status(config_name)
            
            # Get peer count
            peer_count = 0
            peers_set_key = get_peers_set_key(config_name)
            if r.exists(peers_set_key):
                peer_count = r.scard(peers_set_key)
            
            # Get interface address
            address = "N/A"
            try:
                interface = read_conf_file_interface(config_name)
                if "Address" in interface:
                    address = interface["Address"]
            except:
                pass
            
            # Create config object
            config = {
                "name": config_name,
                "status": status,
                "peer_count": peer_count,
                "address": address
            }
            
            configs.append(config)
        
        return configs
    except Exception as e:
        print(f"Error getting configurations: {str(e)}")
        return configs

def get_conf_total_data(config_name):
    """Get total data usage for a configuration from Redis"""
    r = get_redis_client()
    if not r:
        return [0, 0, 0]
    
    upload_total = 0
    download_total = 0
    
    # Get all peers for this config
    peers = get_all_peers_from_redis(config_name)
    
    for peer in peers:
        upload_total += float(peer.get('total_sent', 0))
        download_total += float(peer.get('total_receive', 0))
        
        # Add traffic from history
        for traffic_entry in peer.get('traffic', []):
            upload_total += float(traffic_entry.get('total_sent', 0))
            download_total += float(traffic_entry.get('total_receive', 0))
    
    total = round(upload_total + download_total, 4)
    upload_total = round(upload_total, 4)
    download_total = round(download_total, 4)
    
    return [total, upload_total, download_total]

def generate_qrcode(config_name, peer_id):
    """Generate QR code for a peer"""
    # Get peer data from Redis
    r = get_redis_client()
    if not r:
        return "Error: Redis connection not available"
    
    # Get peer data
    peer_key = get_peer_key(config_name, peer_id)
    peer_data = r.hgetall(peer_key)
    
    if not peer_data:
        return "Peer not found"
    
    # Get server public key
    server_public_key = get_conf_pub_key(config_name)
    
    # Get server endpoint
    config = get_dashboard_conf()
    listen_port = get_conf_listen_port(config_name)
    endpoint = f"{config.get('Peers', 'remote_endpoint')}:{listen_port}"
    
    # Create config string
    config_str = f"""[Interface]
PrivateKey = {peer_data.get('private_key', '')}
Address = {peer_data.get('allowed_ip', '')}
DNS = {peer_data.get('DNS', DEFAULT_DNS)}

[Peer]
PublicKey = {server_public_key}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = {peer_data.get('keepalive', '25')}
"""
    
    return config_str

def get_wireguard_peers(config_name):
    """Get peers directly from WireGuard"""
    peers = []
    
    try:
        # Get all public keys
        keys = get_conf_peer_key(config_name)
        if not isinstance(keys, list):
            return []
        
        # Get handshake and transfer data
        dump = get_conf_peer_data(config_name)
        
        # Process each peer
        for key in keys:
            peer = {"id": key}
            
            # Get allowed IPs
            try:
                allowed_ips = subprocess.check_output(
                    f"wg show {config_name} allowed-ips | grep {key}",
                    shell=True
                ).decode('utf-8').strip()
                
                if allowed_ips:
                    parts = allowed_ips.split("\t")
                    if len(parts) > 1:
                        peer["allowed_ip"] = parts[1].split(",")[0]
            except:
                peer["allowed_ip"] = ""
            
            # Get handshake and transfer data from dump
            if key in dump:
                peer_dump = dump[key]
                peer["latest_handshake"] = peer_dump.get("latest_handshake", "Never")
                peer["transfer_rx"] = peer_dump.get("transfer_rx", "0")
                peer["transfer_tx"] = peer_dump.get("transfer_tx", "0")
            else:
                peer["latest_handshake"] = "Never"
                peer["transfer_rx"] = "0"
                peer["transfer_tx"] = "0"
            
            peers.append(peer)
            
        return peers
    except Exception as e:
        print(f"Error in get_wireguard_peers: {str(e)}")
        return []

def get_conf_peer_data(config_name):
    """Get peer data from wireguard dump"""
    try:
        # Get dump from wireguard
        dump = subprocess.check_output(
            f"wg show {config_name} dump", 
            shell=True
        ).decode('utf-8').strip().split("\n")
        
        # Skip header
        if len(dump) > 0:
            dump = dump[1:]
        
        # Process dump
        peers_data = {}
        for line in dump:
            peer_info = line.split("\t")
            if len(peer_info) >= 6:
                peer_id = peer_info[0]
                
                # Parse handshake - convert to timestamp if possible
                handshake = peer_info[4]
                if handshake == "0":
                    handshake = "Never"
                
                peers_data[peer_id] = {
                    "latest_handshake": handshake,
                    "transfer_rx": peer_info[5],
                    "transfer_tx": peer_info[6]
                }
        
        return peers_data
    except Exception as e:
        print(f"Error in get_conf_peer_data: {str(e)}")
        return {}

def diagnose_redis_connection():
    """Diagnose Redis connection and check existing keys"""
    print("[DEBUG] Starting Redis connection diagnosis...")
    r = get_redis_client(max_retries=1)
    
    if not r:
        print("[ERROR] Failed to connect to Redis server")
        return False
    
    try:
        # Check server info
        info = r.info()
        print(f"[DEBUG] Redis version: {info.get('redis_version')}")
        print(f"[DEBUG] Connected clients: {info.get('connected_clients')}")
        print(f"[DEBUG] Used memory: {info.get('used_memory_human')}")
        
        # Check existing keys for WireGuard
        all_keys = r.keys(f"{REDIS_PREFIX}*")
        print(f"[DEBUG] Found {len(all_keys)} WireGuard related keys in Redis")
        
        # Check for config sets
        config_sets = [k for k in all_keys if k.endswith(":peers")]
        print(f"[DEBUG] Found {len(config_sets)} configuration sets: {config_sets}")
        
        # Check peer counts for each config
        for config_set in config_sets:
            config_name = config_set.replace(f"{REDIS_PREFIX}", "").replace(":peers", "")
            peers_count = r.scard(config_set)
            print(f"[DEBUG] Config '{config_name}' has {peers_count} peers")
            
            # Sample peer IDs
            sample_peers = list(r.smembers(config_set))[:5]  # Get up to 5 peers
            print(f"[DEBUG] Sample peer IDs for '{config_name}': {sample_peers}")
            
            # Check sample peer data
            for peer_id in sample_peers:
                peer_key = get_peer_key(config_name, peer_id)
                peer_exists = r.exists(peer_key)
                peer_fields = r.hkeys(peer_key) if peer_exists else []
                print(f"[DEBUG] Peer {peer_id} data exists: {peer_exists}, fields: {peer_fields}")
        
        return True
    except Exception as e:
        print(f"[ERROR] Error diagnosing Redis: {str(e)}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return False

# Add this near the initialization code or function
@app.route('/diagnose_redis', methods=['GET'])
def api_diagnose_redis():
    """API endpoint to diagnose Redis connection"""
    result = diagnose_redis_connection()
    return jsonify({"success": result})

# Configure Redis persistence
def configure_redis_persistence():
    """Configure Redis to save data to disk properly"""
    r = get_redis_client()
    if not r:
        print("[ERROR] Failed to configure Redis persistence - connection failed")
        return False
    
    try:
        # Check if persistence is already configured
        config = r.config_get('save')
        
        # Configure automatic saving
        # Save if at least 1 key changes in 60 seconds
        r.config_set('save', '60 1')
        
        # Force an immediate save
        save_result = r.save()
        print(f"[INFO] Redis persistence configured, save result: {save_result}")
        
        return True
    except redis.exceptions.ResponseError as e:
        # This can happen in protected mode or when CONFIG commands are disabled
        print(f"[WARNING] Could not configure Redis persistence: {str(e)}")
        print("[WARNING] Make sure your Redis configuration allows persistence")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to configure Redis persistence: {str(e)}")
        return False


# Safe function to save WireGuard configuration


def save_server_setting(request_data, config_name):
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
        conf_file = open(f"/etc/wireguard/{config_name}.conf")
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
        conf_file = open(f"/etc/wireguard/{config_name}.conf")
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
        print("peers:",peers)
        for key in peers:
            print("key:",key)
            peer = json.loads(key)
            print("PEER:",peer)
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
        with open(f"/etc/wireguard/{config_name}.conf.tmp", "w") as conf_file:
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
        os.makedirs(os.path.dirname(f"/etc/wireguard/{config_name}.conf"), exist_ok=True)
        
        # Move temporary file to final location
        os.replace(f"/etc/wireguard/{config_name}.conf.tmp", f"/etc/wireguard/{config_name}.conf")
        
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