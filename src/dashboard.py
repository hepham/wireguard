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
REDIS_PASSWORD = None  # Set to None if no password is required
REDIS_CLIENT = None
REDIS_LOCK = threading.Lock()

# Keys for Redis
def get_peer_key(config_name, peer_id):
    """Get Redis key for a peer"""
    return f"wireguard:{config_name}:peer:{peer_id}"

def get_config_key(config_name):
    """Get Redis key for a configuration"""
    return f"wireguard:{config_name}:config"

def get_peers_set_key(config_name):
    """Get Redis key for the set of peer IDs"""
    return f"wireguard:{config_name}:peers"

def get_last_seen_key(config_name, peer_id):
    """Get Redis key for peer's last seen timestamp"""
    return f"wireguard:{config_name}:last_seen:{peer_id}"

def get_redis_client():
    """Get or create a Redis client"""
    global REDIS_CLIENT
    
    with REDIS_LOCK:
        if REDIS_CLIENT is None:
            try:
                REDIS_CLIENT = redis.Redis(
                    host=REDIS_HOST,
                    port=REDIS_PORT,
                    db=REDIS_DB,
                    password=REDIS_PASSWORD,
                    decode_responses=True  # Automatically decode responses to strings
                )
                # Test the connection
                REDIS_CLIENT.ping()
            except redis.ConnectionError as e:
                print(f"Error connecting to Redis: {e}")
                REDIS_CLIENT = None
    
    return REDIS_CLIENT

def get_peer_from_redis(config_name, peer_id):
    """Get a peer from Redis"""
    r = get_redis_client()
    if not r:
        return None
    
    peer_key = get_peer_key(config_name, peer_id)
    if not r.exists(peer_key):
        return None
    
    peer_data = r.hgetall(peer_key)
    if not peer_data:
        return None
    
    # Add the ID to the data
    peer_data['id'] = peer_id
    
    return peer_data

def get_all_peers_from_redis(config_name):
    """Get all peers for a configuration from Redis"""
    r = get_redis_client()
    if not r:
        return []
    
    # Get all peer IDs from the set
    peers_set_key = get_peers_set_key(config_name)
    peer_ids = r.smembers(peers_set_key)
    
    peers = []
    for peer_id in peer_ids:
        peer_data = get_peer_from_redis(config_name, peer_id)
        if peer_data:
            peers.append(peer_data)
    
    return peers

def save_peer_to_redis(config_name, peer_id, peer_data):
    """Save a peer to Redis"""
    r = get_redis_client()
    if not r:
        return False
    
    # Add to the set of peers
    peers_set_key = get_peers_set_key(config_name)
    r.sadd(peers_set_key, peer_id)
    
    # Save the peer data
    peer_key = get_peer_key(config_name, peer_id)
    r.hset(peer_key, mapping=peer_data)
    
    # Update last seen
    last_seen_key = get_last_seen_key(config_name, peer_id)
    r.set(last_seen_key, int(time.time()))
    
    return True

def delete_peer_from_redis(config_name, peer_id):
    """Delete a peer from Redis"""
    r = get_redis_client()
    if not r:
        return False
    
    # Remove from the set of peers
    peers_set_key = get_peers_set_key(config_name)
    r.srem(peers_set_key, peer_id)
    
    # Delete the peer data
    peer_key = get_peer_key(config_name, peer_id)
    r.delete(peer_key)
    
    # Delete last seen
    last_seen_key = get_last_seen_key(config_name, peer_id)
    r.delete(last_seen_key)
    
    return True

def update_peer_last_seen(config_name, peer_id):
    """Update the last seen timestamp for a peer"""
    r = get_redis_client()
    if not r:
        return False
    
    last_seen_key = get_last_seen_key(config_name, peer_id)
    r.set(last_seen_key, int(time.time()))
    
    return True

def should_update_db(config_name):
    """Check if database should be updated (every 5 minutes)"""
    current_time = time.time()
    if config_name not in last_db_update:
        last_db_update[config_name] = 0
        return True
    
    # Update every 5 minutes (300 seconds)
    if current_time - last_db_update[config_name] >= 300:
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
                    
                except Exception as e:
                    print(f"error delete peer {peer_id}: {str(e)}")

        # Lưu cấu hình
        subprocess.check_call(['wg-quick', 'save', config_name])

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
    """Get and update peer data from WireGuard to Redis"""
    # Get Redis connection
    r = get_redis_client()
    if not r:
        print("Redis connection not available")
        return
    
    # Read configuration files
    conf_peer_data = read_conf_file(config_name)
    config = get_dashboard_conf()
    
    # Check if we should persist to disk
    should_persist = should_update_db(config_name)
    
    # Track existing peers for cleanup
    existing_peer_ids = set()
    
    # Process peers from configuration
    for peer in conf_peer_data['Peers']:
        if "PublicKey" not in peer:
            continue
        
        peer_id = peer['PublicKey']
        existing_peer_ids.add(peer_id)
        
        # Check if peer exists in Redis
        peer_key = get_peer_key(config_name, peer_id)
        if not r.exists(peer_key):
            # Add new peer
            new_peer = {
                "id": peer_id,
                "private_key": "",
                "DNS": config.get("Peers", "peer_global_DNS"),
                "endpoint_allowed_ip": config.get("Peers", "peer_endpoint_allowed_ip"),
                "name": "",
                "total_receive": 0,
                "total_sent": 0,
                "total_data": 0,
                "endpoint": "N/A",
                "status": "stopped",
                "latest_handshake": "N/A",
                "allowed_ip": "N/A",
                "traffic": "[]",
                "mtu": config.get("Peers", "peer_mtu"),
                "keepalive": config.get("Peers", "peer_keep_alive"),
                "remote_endpoint": config.get("Peers", "remote_endpoint")
            }
            
            # Save to Redis
            r.hset(peer_key, mapping=new_peer)
            r.sadd(get_peers_set_key(config_name), peer_id)
        else:
            # Update peer settings if needed
            fields_to_check = {
                "DNS": config.get("Peers", "peer_global_DNS"),
                "endpoint_allowed_ip": config.get("Peers", "peer_endpoint_allowed_ip"),
                "private_key": "",
                "mtu": config.get("Peers", "peer_mtu"),
                "keepalive": config.get("Peers", "peer_keep_alive"),
                "remote_endpoint": config.get("Peers", "remote_endpoint")
            }
            
            # Check each field and update if missing
            for field, default_value in fields_to_check.items():
                if not r.hexists(peer_key, field):
                    r.hset(peer_key, field, default_value)
    
    # Remove peers that no longer exist in WireGuard
    peers_key = get_peers_set_key(config_name)
    all_peer_ids = r.smembers(peers_key)
    
    for peer_id in all_peer_ids:
        if peer_id not in existing_peer_ids:
            # Delete peer data
            delete_peer_from_redis(config_name, peer_id)
    
    # Update real-time data
    tic = time.perf_counter()
    get_latest_handshake(config_name)
    get_transfer(config_name)
    get_endpoint(config_name)
    get_allowed_ip(config_name, conf_peer_data)
    toc = time.perf_counter()
    print(f"Finish fetching data in {toc - tic:0.4f} seconds")
    
    # Ensure data is persisted if needed
    if should_persist:
        print(f"Persisting Redis data for {config_name}")
        r.save()

# Search for peers
def get_peers(config_name, search, sort_t):
    """Get filtered and sorted peers from Redis"""
    get_all_peers_data(config_name)
    
    r = get_redis_client()
    if not r:
        return []
    
    # Get all peers
    peers = get_all_peers_from_redis(config_name)
    
    # Filter by search term if provided
    if search and len(search) > 0:
        search = search.lower()
        peers = [p for p in peers if search in p.get('name', '').lower()]
    
    # Sort peers
    if sort_t:
        peers = sorted(peers, key=lambda d: d.get(sort_t, ''))
    
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
    gen = subprocess.check_output('wg genkey > private_key.txt && wg pubkey < private_key.txt > public_key.txt',
                                  shell=True)
    private = open('private_key.txt')
    private_key = private.readline().strip()
    public = open('public_key.txt')
    public_key = public.readline().strip()
    data = {"private_key": private_key, "public_key": public_key}
    private.close()
    public.close()
    os.remove('private_key.txt')
    os.remove('public_key.txt')
    return data

# Generate public key
def gen_public_key(private_key):
    pri_key_file = open('private_key.txt', 'w')
    pri_key_file.write(private_key)
    pri_key_file.close()
    try:
        check = subprocess.check_output("wg pubkey < private_key.txt > public_key.txt", shell=True)
        public = open('public_key.txt')
        public_key = public.readline().strip()
        os.remove('private_key.txt')
        os.remove('public_key.txt')
        return {"status": 'success', "msg": "", "data": public_key}
    except subprocess.CalledProcessError as exc:
        os.remove('private_key.txt')
        return {"status": 'failed', "msg": "Key is not the correct length or format", "data": ""}

# Check if private key and public key match
def checkKeyMatch(private_key, public_key, config_name):
    result = gen_public_key(private_key)
    if result['status'] == 'failed':
        return result
    else:
        db = TinyDB('db/' + config_name + '.json')
        peers = Query()
        match = db.search(peers.id == result['data'])
        if len(match) != 1 or result['data'] != public_key:
            return {'status': 'failed', 'msg': 'Please check your private key, it does not match with the public key.'}
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
@app.route('/get_config/<config_name>', methods=['GET'])
def get_conf(config_name):
    config_interface = read_conf_file_interface(config_name)
    search = request.args.get('search')
    if len(search) == 0: search = ""
    search = urllib.parse.unquote(search)
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
    sort = config.get("Server", "dashboard_sort")
    peer_display_mode = config.get("Peers", "peer_display_mode")
    if "Address" not in config_interface.keys():
        conf_address = "N/A"
    else:
        conf_address = config_interface['Address']
    conf_data = {
        "peer_data": get_peers(config_name, search, sort),
        "name": config_name,
        "status": get_conf_status(config_name),
        "total_data_usage": get_conf_total_data(config_name),
        "public_key": get_conf_pub_key(config_name),
        "listen_port": get_conf_listen_port(config_name),
        "running_peer": get_conf_running_peer_number(config_name),
        "conf_address": conf_address
    }
    if conf_data['status'] == "stopped":
        conf_data['checked'] = "nope"
    else:
        conf_data['checked'] = "checked"
    print(config.get("Peers","remote_endpoint"))
    return render_template('get_conf.html', conf_data=conf_data, wg_ip=config.get("Peers","remote_endpoint"), sort_tag=sort,
                           dashboard_refresh_interval=int(config.get("Server", "dashboard_refresh_interval")), peer_display_mode=peer_display_mode)

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
        save_status = subprocess.check_output(f'wg-quick save {config_name}', shell=True, stderr=subprocess.STDOUT)
        
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
        status = subprocess.check_output("wg-quick save " + config_name, shell=True, stderr=subprocess.STDOUT)
        
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
        save_change_ip = subprocess.check_output(f'wg-quick save {config_name}', shell=True,
                                                stderr=subprocess.STDOUT)
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
    db = TinyDB('db/' + config + '.json')
    html = ""
    for i in db.all():
        html += '<optgroup label="' + i['name'] + ' - ' + i['id'] + '">'
        allowed_ip = str(i['allowed_ip']).split(",")
        for k in allowed_ip:
            k = k.split("/")
            if len(k) == 2:
                html += "<option value=" + k[0] + ">" + k[0] + "</option>"
        endpoint = str(i['endpoint']).split(":")
        if len(endpoint) == 2:
            html += "<option value=" + endpoint[0] + ">" + endpoint[0] + "</option>"
        html += "</optgroup>"
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
        if peer.get("name") == data["name"]:
            config_content = f"""# {peer['name']}
[Interface]
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
            status = subprocess.check_output(
                f"wg-quick save {config_name}", 
                shell=True, stderr=subprocess.STDOUT
            )
            
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
                "endpoint_allowed_ip": DEFAULT_ENDPOINT_ALLOWED_IP,
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
    print(response.text)
    return response.text.strip()

"""
Dashboard Initialization
"""
def init_dashboard():
    remote_endpoint=get_public_ip()
    print("remote_endpoint:",remote_endpoint)
    # Set Default INI File
    if not os.path.isfile("wg-dashboard.ini"):
        conf_file = open("wg-dashboard.ini", "w+")
    config = configparser.ConfigParser(strict=False)
    config.read(dashboard_conf)
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