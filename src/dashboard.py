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
# Thay thế TinyDB bằng sqlite3
import sqlite3
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

# SQLite Utility Functions
def get_db_path(config_name):
    """Trả về đường dẫn đến file database SQLite"""
    db_dir = "db"
    # Đảm bảo thư mục tồn tại
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    return os.path.join(db_dir, f"{config_name}.db")

def init_db_for_config(config_name):
    """Khởi tạo database SQLite cho một config nếu chưa tồn tại"""
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Tạo bảng peers nếu chưa tồn tại
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS peers (
        id TEXT PRIMARY KEY,
        name TEXT DEFAULT '',
        private_key TEXT DEFAULT '',
        DNS TEXT,
        endpoint_allowed_ip TEXT,
        allowed_ip TEXT DEFAULT 'N/A',
        status TEXT DEFAULT 'stopped',
        latest_handshake TEXT DEFAULT 'N/A',
        endpoint TEXT DEFAULT 'N/A',
        total_receive REAL DEFAULT 0,
        total_sent REAL DEFAULT 0,
        total_data REAL DEFAULT 0,
        mtu TEXT,
        keepalive TEXT,
        remote_endpoint TEXT,
        public_key TEXT DEFAULT '',
        traffic TEXT DEFAULT '[]'
    )
    ''')
    conn.commit()
    conn.close()

def dict_factory(cursor, row):
    """Chuyển đổi row thành dictionary để tương thích với TinyDB"""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

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

        # Xử lý database
        db_path = get_db_path(config_name)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        current_time = int(time.time())

        # Lấy tất cả các peers
        cursor.execute("SELECT id, doc_id FROM peers")
        all_peers = cursor.fetchall()

        for peer_id, doc_id in all_peers:
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
                    
                    # Xóa khỏi database
                    cursor.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
                    
                except Exception as e:
                    print(f"error delete peer {peer_id}: {str(e)}")

        # Lưu cấu hình và đóng DB
        subprocess.check_call(['wg-quick', 'save', config_name])
        conn.commit()
        conn.close()

    except Exception as e:
        print(f"error cleanup: {str(e)}")

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
def get_latest_handshake(config_name, conn, cursor):
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
            cursor.execute(
                "UPDATE peers SET latest_handshake = ?, status = ? WHERE id = ?",
                (str(minus).split(".")[0], status, data_usage[count])
            )
        else:
            cursor.execute(
                "UPDATE peers SET latest_handshake = ?, status = ? WHERE id = ?",
                ("(None)", status, data_usage[count])
            )
        count += 2
    conn.commit()

# Get transfer from all peers of a configuration
def get_transfer(config_name, conn, cursor):
    # Get transfer
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " transfer", shell=True)
    except Exception:
        return "stopped"
    
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    for i in range(int(len(data_usage) / 3)):
        cursor.execute("SELECT total_sent, total_receive, traffic, status FROM peers WHERE id = ?", (data_usage[count],))
        cur_i = cursor.fetchone()
        
        if not cur_i:
            count += 3
            continue
            
        # Lấy giá trị hoặc sử dụng giá trị mặc định
        total_sent = cur_i[0] or 0
        total_receive = cur_i[1] or 0
        traffic_str = cur_i[2] or '[]'
        status = cur_i[3]
        
        try:
            traffic = json.loads(traffic_str)
        except:
            traffic = []
        
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
            
            cursor.execute(
                "UPDATE peers SET traffic = ?, total_receive = ?, total_sent = ?, total_data = ? WHERE id = ?",
                (
                    json.dumps(traffic),
                    round(total_receive, 4),
                    round(total_sent, 4),
                    round(total_receive + total_sent, 4),
                    data_usage[count]
                )
            )

        count += 3
    conn.commit()

# Get endpoint from all peers of a configuration
def get_endpoint(config_name, conn, cursor):
    # Get endpoint
    try:
        data_usage = subprocess.check_output("wg show " + config_name + " endpoints", shell=True)
    except Exception:
        return "stopped"
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    for i in range(int(len(data_usage) / 2)):
        cursor.execute(
            "UPDATE peers SET endpoint = ? WHERE id = ?",
            (data_usage[count + 1], data_usage[count])
        )
        count += 2
    conn.commit()

# Get allowed ips from all peers of a configuration
def get_allowed_ip(config_name, conn, cursor, conf_peer_data):
    # Get allowed ip
    for i in conf_peer_data["Peers"]:
        cursor.execute(
            "UPDATE peers SET allowed_ip = ? WHERE id = ?",
            (i.get('AllowedIPs', '(None)'), i["PublicKey"])
        )
    conn.commit()

# Look for new peers from WireGuard
def get_all_peers_data(config_name):
    # Đảm bảo database đã được khởi tạo
    init_db_for_config(config_name)
    
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    
    conf_peer_data = read_conf_file(config_name)
    config = get_dashboard_conf()
    
    # Lấy danh sách peer hiện có trong database
    cursor.execute("SELECT id FROM peers")
    existing_peers = {row['id'] for row in cursor.fetchall()}
    
    for i in conf_peer_data['Peers']:
        # Kiểm tra peer có tồn tại chưa
        cursor.execute("SELECT COUNT(*) FROM peers WHERE id = ?", (i['PublicKey'],))
        if cursor.fetchone()[0] == 0:
            # Thêm peer mới
            cursor.execute("""
                INSERT INTO peers (
                    id, private_key, DNS, endpoint_allowed_ip, name, 
                    total_receive, total_sent, total_data, endpoint, 
                    status, latest_handshake, allowed_ip, traffic, 
                    mtu, keepalive, remote_endpoint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                i['PublicKey'], "", config.get("Peers", "peer_global_DNS"),
                config.get("Peers", "peer_endpoint_allowed_ip"), "", 
                0, 0, 0, "N/A", "stopped", "N/A", "N/A", "[]",
                config.get("Peers", "peer_mtu"), 
                config.get("Peers", "peer_keep_alive"),
                config.get("Peers", "remote_endpoint")
            ))
        else:
            # Cập nhật peer nếu cần
            cursor.execute("""
                SELECT DNS, endpoint_allowed_ip, private_key, mtu, keepalive, remote_endpoint 
                FROM peers WHERE id = ?
            """, (i['PublicKey'],))
            row = cursor.fetchone()
            
            # Cập nhật thiếu các thiết lập mặc định
            update_fields = {}
            if not row['DNS']:  # DNS
                update_fields['DNS'] = config.get("Peers", "peer_global_DNS")
            if not row['endpoint_allowed_ip']:  # endpoint_allowed_ip
                update_fields['endpoint_allowed_ip'] = config.get("Peers", "peer_endpoint_allowed_ip")
            if not row['private_key']:  # private_key
                update_fields['private_key'] = ''
            if not row['mtu']:  # mtu
                update_fields['mtu'] = config.get("Peers", "peer_mtu")
            if not row['keepalive']:  # keepalive
                update_fields['keepalive'] = config.get("Peers", "peer_keep_alive")
            if not row['remote_endpoint']:  # remote_endpoint
                update_fields['remote_endpoint'] = config.get("Peers", "remote_endpoint")
                
            # Cập nhật nếu có thiếu thông tin
            if update_fields:
                set_clause = ", ".join([f"{key} = ?" for key in update_fields.keys()])
                values = list(update_fields.values()) + [i['PublicKey']]
                cursor.execute(f"UPDATE peers SET {set_clause} WHERE id = ?", values)
    
    # Lấy danh sách peer từ WireGuard
    wg_keys = {peer['PublicKey'] for peer in conf_peer_data['Peers']}
    
    # Xóa peer không còn tồn tại trong WireGuard
    for db_key in existing_peers:
        if db_key not in wg_keys:
            cursor.execute("DELETE FROM peers WHERE id = ?", (db_key,))
    
    # Đồng bộ thông tin
    tic = time.perf_counter()
    get_latest_handshake(config_name, conn, cursor)
    get_transfer(config_name, conn, cursor)
    get_endpoint(config_name, conn, cursor)
    get_allowed_ip(config_name, conn, cursor, conf_peer_data)
    toc = time.perf_counter()
    print(f"Finish fetching data in {toc - tic:0.4f} seconds")
    
    conn.commit()
    conn.close()

"""
Frontend Related Functions
"""
# Search for peers
def get_peers(config_name, search, sort_t):
    get_all_peers_data(config_name)
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    
    if len(search) == 0:
        cursor.execute("SELECT * FROM peers")
    else:
        cursor.execute("SELECT * FROM peers WHERE name LIKE ?", (f'%{search}%',))
        
    result = cursor.fetchall()
    
    # Chuyển đổi traffic từ JSON string thành list
    for row in result:
        if 'traffic' in row and row['traffic']:
            try:
                row['traffic'] = json.loads(row['traffic'])
            except:
                row['traffic'] = []
    
    # Sắp xếp kết quả
    if sort_t in result[0] if result else []:
        result = sorted(result, key=lambda d: d[sort_t])
    
    conn.close()
    return result




# Get configuration total data
def get_conf_total_data(config_name):
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    
    upload_total = 0
    download_total = 0
    
    # Lấy tổng dữ liệu hiện tại
    cursor.execute("SELECT total_sent, total_receive, traffic FROM peers")
    peers = cursor.fetchall()
    
    for peer in peers:
        upload_total += peer['total_sent'] or 0
        download_total += peer['total_receive'] or 0
        
        if peer['traffic']:
            try:
                traffic = json.loads(peer['traffic'])
                for k in traffic:
                    upload_total += k['total_sent']
                    download_total += k['total_receive']
            except:
                pass
    
    total = round(upload_total + download_total, 4)
    upload_total = round(upload_total, 4)
    download_total = round(download_total, 4)
    
    conn.close()
    return [total, upload_total, download_total]

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
        db_path = get_db_path(config_name)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM peers WHERE id = ?", (public_key,))
        match_count = cursor.fetchone()[0]
        
        conn.close()
        
        if match_count != 1 or result['data'] != public_key:
            return {'status': 'failed', 'msg': 'Please check your private key, it does not match with the public key.'}
        else:
            return {'status': 'success'}

# Check if there is repeated allowed IP
def check_repeat_allowed_IP(public_key, ip, config_name):
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Kiểm tra peer tồn tại
    cursor.execute("SELECT COUNT(*) FROM peers WHERE id = ?", (public_key,))
    if cursor.fetchone()[0] != 1:
        conn.close()
        return {'status': 'failed', 'msg': 'Peer does not exist'}
    
    # Kiểm tra IP đã tồn tại
    cursor.execute("SELECT COUNT(*) FROM peers WHERE id != ? AND allowed_ip = ?", (public_key, ip))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return {'status': 'failed', 'msg': "Allowed IP already taken by another peer."}
    
    conn.close()
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
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    data = request.get_json()
    public_key = data['public_key']
    allowed_ips = data['allowed_ips']
    endpoint_allowed_ip = data['endpoint_allowed_ip']
    DNS = data['DNS']
    keys = get_conf_peer_key(config_name)
    
    if len(public_key) == 0 or len(DNS) == 0 or len(allowed_ips) == 0 or len(endpoint_allowed_ip) == 0:
        conn.close()
        return "Please fill in all required box."
        
    if type(keys) != list:
        conn.close()
        return config_name + " is not running."
        
    if public_key in keys:
        conn.close()
        return "Public key already exist."
    
    # Kiểm tra allowed IP đã tồn tại chưa
    cursor.execute("SELECT COUNT(*) FROM peers WHERE allowed_ip = ?", (allowed_ips,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return "Allowed IP already taken by another peer."
    
    if not check_DNS(DNS):
        conn.close()
        return "DNS formate is incorrect. Example: 1.1.1.1"
        
    if not check_Allowed_IPs(endpoint_allowed_ip):
        conn.close()
        return "Endpoint Allowed IPs format is incorrect."
        
    if len(data['MTU']) != 0:
        try:
            mtu = int(data['MTU'])
        except:
            conn.close()
            return "MTU format is not correct."
            
    if len(data['keep_alive']) != 0:
        try:
            keep_alive = int(data['keep_alive'])
        except:
            conn.close()
            return "Persistent Keepalive format is not correct."
    
    try:
        status = subprocess.check_output(
            "wg set " + config_name + " peer " + public_key + " allowed-ips " + allowed_ips, shell=True,
            stderr=subprocess.STDOUT)
        status = subprocess.check_output("wg-quick save " + config_name, shell=True, stderr=subprocess.STDOUT)
        get_all_peers_data(config_name)
        
        # Update peer trong database
        cursor.execute("""
            UPDATE peers SET name = ?, private_key = ?, DNS = ?, endpoint_allowed_ip = ? 
            WHERE id = ?
        """, (data['name'], data['private_key'], data['DNS'], endpoint_allowed_ip, public_key))
        
        conn.commit()
        conn.close()
        return "true"
    except subprocess.CalledProcessError as exc:
        conn.close()
        return exc.output.strip()

# Remove peer
@app.route('/remove_peer/<config_name>', methods=['POST'])
def remove_peer(config_name):
    if get_conf_status(config_name) == "stopped":
        return "Your need to turn on " + config_name + " first."
        
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    data = request.get_json()
    delete_key = data['peer_id']
    keys = get_conf_peer_key(config_name)
    
    if type(keys) != list:
        conn.close()
        return config_name + " is not running."
        
    if delete_key not in keys:
        conn.close()
        return "This key does not exist"
    else:
        try:
            status = subprocess.check_output("wg set " + config_name + " peer " + delete_key + " remove", shell=True,
                                             stderr=subprocess.STDOUT)
            status = subprocess.check_output("wg-quick save " + config_name, shell=True, stderr=subprocess.STDOUT)
            
            cursor.execute("DELETE FROM peers WHERE id = ?", (delete_key,))
            conn.commit()
            conn.close()
            return "true"
        except subprocess.CalledProcessError as exc:
            conn.close()
            return exc.output.strip()

# Save peer settings
@app.route('/save_peer_setting/<config_name>', methods=['POST'])
def save_peer_setting(config_name):
    data = request.get_json()
    id = data['id']
    name = data['name']
    private_key = data['private_key']
    DNS = data['DNS']
    allowed_ip = data['allowed_ip']
    endpoint_allowed_ip = data['endpoint_allowed_ip']
    
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Kiểm tra peer tồn tại
    cursor.execute("SELECT COUNT(*) FROM peers WHERE id = ?", (id,))
    if cursor.fetchone()[0] == 1:
        check_ip = check_repeat_allowed_IP(id, allowed_ip, config_name)
        
        if not check_IP_with_range(endpoint_allowed_ip):
            conn.close()
            return jsonify({"status": "failed", "msg": "Endpoint Allowed IPs format is incorrect."})
            
        if not check_DNS(DNS):
            conn.close()
            return jsonify({"status": "failed", "msg": "DNS format is incorrect."})
            
        if len(data['MTU']) != 0:
            try:
                mtu = int(data['MTU'])
            except:
                conn.close()
                return jsonify({"status": "failed", "msg": "MTU format is not correct."})
                
        if len(data['keep_alive']) != 0:
            try:
                keep_alive = int(data['keep_alive'])
            except:
                conn.close()
                return jsonify({"status": "failed", "msg": "Persistent Keepalive format is not correct."})
                
        if private_key != "":
            check_key = checkKeyMatch(private_key, id, config_name)
            if check_key['status'] == "failed":
                conn.close()
                return jsonify(check_key)
                
        if check_ip['status'] == "failed":
            conn.close()
            return jsonify(check_ip)
            
        try:
            if allowed_ip == "": allowed_ip = '""'
            change_ip = subprocess.check_output('wg set ' + config_name + " peer " + id + " allowed-ips " + allowed_ip,
                                                shell=True, stderr=subprocess.STDOUT)
            save_change_ip = subprocess.check_output('wg-quick save ' + config_name, shell=True,
                                                     stderr=subprocess.STDOUT)
                                                     
            if change_ip.decode("UTF-8") != "":
                conn.close()
                return jsonify({"status": "failed", "msg": change_ip.decode("UTF-8")})
                
            cursor.execute("""
                UPDATE peers SET name = ?, private_key = ?, DNS = ?, endpoint_allowed_ip = ?, mtu = ?, keepalive = ?
                WHERE id = ?
            """, (name, private_key, DNS, endpoint_allowed_ip, data['MTU'], data['keep_alive'], id))
            
            conn.commit()
            conn.close()
            return jsonify({"status": "success", "msg": ""})
        except subprocess.CalledProcessError as exc:
            conn.close()
            return jsonify({"status": "failed", "msg": str(exc.output.decode("UTF-8").strip())})
    else:
        conn.close()
        return jsonify({"status": "failed", "msg": "This peer does not exist."})

# Get peer settings
@app.route('/get_peer_data/<config_name>', methods=['POST'])
def get_peer_name(config_name):
    data = request.get_json()
    id = data['id']
    
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT name, allowed_ip, DNS, private_key, endpoint_allowed_ip, mtu, keepalive 
        FROM peers WHERE id = ?
    """, (id,))
    result = cursor.fetchone()
    
    conn.close()
    
    if result:
        return jsonify(result)
    else:
        return jsonify({})

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
    print(request.headers.get('User-Agent'))
    id = request.args.get('id')
    db = sqlite3.connect(get_db_path(config_name))
    cursor = db.cursor()
    get_peer = cursor.execute("SELECT * FROM peers WHERE id = ?", (id,)).fetchone()
    config = get_dashboard_conf()
    if len(get_peer) == 1:
        peer = get_peer
        if peer['private_key'] != "":
            public_key = get_conf_pub_key(config_name)
            listen_port = get_conf_listen_port(config_name)
            endpoint = config.get("Peers","remote_endpoint") + ":" + listen_port
            private_key = peer['private_key']
            allowed_ip = peer['allowed_ip']
            DNS = peer['DNS']
            endpoint_allowed_ip = peer['endpoint_allowed_ip']
            filename = peer['name']
            if len(filename) == 0:
                filename = "Untitled_Peers"
            else:
                filename = peer['name']
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

            def generate(private_key, allowed_ip, DNS, public_key, endpoint):
                yield "[Interface]\nPrivateKey = " + private_key + "\nAddress = " + allowed_ip + "\nDNS = " + DNS + "\n\n[Peer]\nPublicKey = " + public_key + "\nAllowedIPs = "+endpoint_allowed_ip+"\nEndpoint = " + endpoint

            return app.response_class(generate(private_key, allowed_ip, DNS, public_key, endpoint),
                                      mimetype='text/conf',
                                      headers={"Content-Disposition": "attachment;filename=" + filename + ".conf"})
    else:
        return redirect("/configuration/" + config_name)

# Switch peer displate mode
@app.route('/switch_display_mode/<mode>', methods=['GET'])
def switch_display_mode(mode):
    if mode in ['list','grid']:
        config = configparser.ConfigParser(strict=False)
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
    db = sqlite3.connect(get_db_path(config))
    html = ""
    for i in db.execute("SELECT * FROM peers").fetchall():
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
    
    db_path = get_db_path(config_name)
    conn = sqlite3.connect(db_path)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    
    data = request.get_json()
    keys = get_conf_peer_key(config_name)
    private_key=""
    public_key=""
    checkExist=False
    config_content=""
    
    # Kiểm tra peer có tồn tại
    cursor.execute("SELECT * FROM peers WHERE name = ?", (data["name"],))
    peer = cursor.fetchone()
    
    if peer:
        # Peer đã tồn tại
        config_content = f"""# {peer['name']}
            [Interface]
            PrivateKey = {peer['private_key']}
            Address = {peer['allowed_ip']}
            DNS = {DEFAULT_DNS}

            [Peer]
            PublicKey = {peer['public_key']}
            Endpoint = {peer['endpoint_allowed_ip']}
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = {data.get('keep_alive', 21)}
            """
        checkExist=True
    
    if not checkExist:
        check = False
        while not check:
            key = gen_private_key()
            private_key = key["private_key"]
            public_key = key["public_key"]
            if len(public_key) != 0 and public_key not in keys:
                check = True
        
        # Tìm IP địa chỉ tiếp theo
        cursor.execute("SELECT allowed_ip FROM peers WHERE allowed_ip LIKE ?", (f"{BASE_IP}.%",))
        existing_ips = []
        
        for row in cursor.fetchall():
            try:
                ip_part = row['allowed_ip'].split('.')[3].split('/')[0]
                existing_ips.append(int(ip_part))
            except:
                pass
        
        next_ip=2
        for ip in range(2,255,1):
            if ip not in existing_ips:
                next_ip = ip
                break
                
        allowed_ips = f"{BASE_IP}.{next_ip}/32"
        print("--------------------------------")
        print("existing_ips:", existing_ips)
        print("ip allowed_ip:", allowed_ips)
        print("------------------------------")

        # Kiểm tra IP trùng
        cursor.execute("SELECT COUNT(*) FROM peers WHERE allowed_ip = ?", (allowed_ips,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            return jsonify({"error": "IP đã tồn tại"}), 409
            
        try:
            status = subprocess.check_output(
                "wg set " + config_name + " peer " + public_key + " allowed-ips " + allowed_ips, shell=True,
                stderr=subprocess.STDOUT)
            status = subprocess.check_output("wg-quick save " + config_name, shell=True, stderr=subprocess.STDOUT)
            get_all_peers_data(config_name)

        except subprocess.CalledProcessError as exc:
            conn.close()
            return exc.output.strip()
        
        public_key_ip = public_key
        public_key = get_conf_pub_key(config_name)
        listen_port = get_conf_listen_port(config_name)
        config = get_dashboard_conf()
        endpoint = config.get("Peers","remote_endpoint") + ":" + listen_port
        
        try:
            cursor.execute("""
                UPDATE peers 
                SET name = ?, private_key = ?, DNS = ?, public_key = ?, endpoint_allowed_ip = ?, allowed_ip = ?
                WHERE id = ?
            """, (
                data['name'], private_key, DEFAULT_DNS, public_key, 
                endpoint, allowed_ips, public_key_ip
            ))
            conn.commit()
        except Exception as exc:
            print(f"Error updating peer: {str(exc)}")
            
        filename = data["name"]
        if len(filename) == 0:
            filename = "Untitled_Peers"
        else:
            filename = data["name"]
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
            
        # Tạo config
        config_content = f"""# {data['name']}
                [Interface]
                PrivateKey = {private_key}
                Address = {allowed_ips}
                DNS = {DEFAULT_DNS}

                [Peer]
                PublicKey = {public_key}
                Endpoint ={endpoint}
                AllowedIPs = 0.0.0.0/0
                PersistentKeepalive = {data.get('keep_alive', 25)}
                """

    conn.close()
    
    # Trả về file config
    response = make_response(config_content)
    response.headers['Content-Disposition'] = \
            f'attachment; filename="{data["name"]}_wg.conf"'
    return response

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

if __name__ == "__main__":
    init_dashboard()
    config = configparser.ConfigParser(strict=False)
    config.read('wg-dashboard.ini')
    app_ip = config.get("Server", "app_ip")
    app_port = config.get("Server", "app_port")
    wg_conf_path = config.get("Server", "wg_conf_path")
    config.clear()
    app.run(host=app_ip, debug=False, port=app_port)