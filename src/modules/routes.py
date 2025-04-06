"""
Routes Module - Contains Flask route handlers
"""
import os
import json
import subprocess
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response

from .auth import login_required, verify_user, change_password
from .config import get_dashboard_conf, save_dashboard_config
from .redis_manager import (
    get_redis_client, configure_redis_persistence, save_peer_to_redis,
    delete_peer_from_redis, get_peer_from_redis, get_all_peers_from_redis,
    get_peer_key
)
from .wireguard import (
    WG_CONF_PATH, DEFAULT_DNS, DEFAULT_ENDPOINT, DEFAULT_ENDPOINT_ALLOWED_IP, BASE_IP,
    get_conf_status, get_conf_peer_key, get_conf_pub_key, get_conf_listen_port,
    get_conf_data, gen_private_key, gen_public_key, cleanup_inactive_peers,
    check_IP_with_range, check_DNS, checkKeyMatch, check_repeat_allowed_IP,
    save_wireguard_config
)
from .utils import ping_host, ping_range, traceroute, get_ip_from_peer

def init_routes(app):
    """Initialize Flask routes"""
    
    @app.route('/')
    @login_required
    def index():
        """Main dashboard page"""
        config = get_dashboard_conf()
        app_port = config.get("Server", "app_port", fallback="10086")
        refresh_interval = config.get("Server", "dashboard_refresh_interval", fallback="60000")
        sort_by = config.get("Server", "dashboard_sort", fallback="status")
        
        wg_conf_path = config.get("Server", "wg_conf_path", fallback="/etc/wireguard")
        configurations = []
        
        try:
            conf_dir = os.listdir(wg_conf_path)
            for conf in conf_dir:
                if conf.endswith('.conf'):
                    name = conf.split('.')[0]
                    status = get_conf_status(name)
                    configurations.append({"name": name, "status": status})
        except:
            pass
            
        return render_template('index.html', 
                              configurations=configurations, 
                              app_port=app_port,
                              refresh_interval=refresh_interval,
                              sort_by=sort_by)
    
    @app.route('/signin', methods=['GET', 'POST'])
    def signin():
        """Sign in page"""
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            if verify_user(username, password):
                session['username'] = username
                return redirect(url_for('index'))
            else:
                return render_template('signin.html', error="Invalid credentials")
        
        return render_template('signin.html')
    
    @app.route('/signout')
    def signout():
        """Sign out"""
        session.pop('username', None)
        return redirect(url_for('signin'))
    
    @app.route('/change_password', methods=['POST'])
    @login_required
    def change_pwd():
        """Change password"""
        current = request.form.get('current_password')
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        
        if not current or not new or not confirm:
            return jsonify({"status": "failed", "msg": "All fields are required"})
            
        if new != confirm:
            return jsonify({"status": "failed", "msg": "New passwords don't match"})
            
        result = change_password(current, new)
        return jsonify(result)
    
    @app.route('/switch/<config_name>', methods=['GET'])
    @login_required
    def switch(config_name):
        """Turn on/off a WireGuard configuration"""
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
    
    @app.route('/add_peer/<config_name>', methods=['POST'])
    @login_required
    def add_peer(config_name):
        """Add a new peer to WireGuard and Redis"""
        data = request.form
        name = data['name']
        DNS = data['DNS']
        allowed_ip = data['allowed_ip']
        endpoint_allowed_ip = data['endpoint_allowed_ip']
        private_key = ""
        public_key = ""
        
        if get_conf_status(config_name) == "stopped":
            return "Your need to turn on " + config_name + " first."
            
        # Get Redis connection
        r = get_redis_client()
        if not r:
            return "Redis connection not available"
            
        # Validate data
        if not check_IP_with_range(allowed_ip):
            return "Allowed IPs format is not correct."
            
        if not check_IP_with_range(endpoint_allowed_ip):
            return "Endpoint Allowed IPs format is not correct."
            
        if not check_DNS(DNS):
            return "DNS format is not correct."
        
        # Generate new key pair
        check = False
        keys = get_conf_peer_key(config_name)
        
        if type(keys) != list:
            return config_name + " is not running."
            
        while not check:
            key = gen_private_key()
            private_key = key["private_key"]
            public_key = key["public_key"]
            if len(public_key) != 0 and public_key not in keys:
                check = True
                
        # Check for IP conflicts
        check_ip = check_repeat_allowed_IP(public_key, allowed_ip, config_name)
        if check_ip['status'] == "failed":
            return check_ip['msg']
            
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
    
    @app.route('/remove_peer/<config_name>', methods=['POST'])
    @login_required
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
    
    @app.route('/save_peer_setting/<config_name>', methods=['POST'])
    @login_required
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
            
    @app.route('/get_conf_data/<config_name>', methods=['GET'])
    @login_required
    def get_configuration_data(config_name):
        """Get configuration data for the dashboard"""
        conf_data = get_conf_data(config_name)
        
        if type(conf_data) == str:
            return conf_data
            
        # Get peer data from Redis
        r = get_redis_client()
        if not r:
            return jsonify({"error": "Redis connection not available"})
            
        for peer in conf_data["peers"]:
            peer_id = peer["public_key"]
            peer_data = get_peer_from_redis(config_name, peer_id)
            
            if peer_data:
                peer["name"] = peer_data.get("name", "")
                peer["DNS"] = peer_data.get("DNS", "")
                peer["private_key"] = peer_data.get("private_key", "")
                peer["endpoint_allowed_ip"] = peer_data.get("endpoint_allowed_ip", "")
                peer["mtu"] = peer_data.get("mtu", "")
                peer["keepalive"] = peer_data.get("keepalive", "")
                peer["created_at"] = peer_data.get("created_at", "")
            else:
                peer["name"] = ""
                
        return jsonify(conf_data)
        
    @app.route('/create_client/<config_name>', methods=['POST'])
    @login_required
    def create_client(config_name):
        """Create a new client configuration file"""
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
        
    @app.route('/ping/<config_name>/<peer_id>', methods=['GET'])
    @login_required
    def ping_peer(config_name, peer_id):
        """Ping a peer"""
        # Get peer data from Redis
        peer_data = get_peer_from_redis(config_name, peer_id)
        if not peer_data:
            return jsonify({"error": "Peer not found"}), 404
            
        # Extract IP address
        ip = get_ip_from_peer(peer_data)
        
        # Ping the peer
        response_time = ping_host(ip)
        
        if response_time is None:
            return jsonify({"status": "failed", "msg": f"Could not ping {ip}"})
        
        return jsonify({
            "status": "success", 
            "ip": ip, 
            "response_time": response_time
        })
        
    @app.route('/traceroute/<config_name>/<peer_id>', methods=['GET'])
    @login_required
    def traceroute_peer(config_name, peer_id):
        """Perform traceroute to a peer"""
        # Get peer data from Redis
        peer_data = get_peer_from_redis(config_name, peer_id)
        if not peer_data:
            return jsonify({"error": "Peer not found"}), 404
            
        # Extract IP address
        ip = get_ip_from_peer(peer_data)
        
        # Perform traceroute
        result = traceroute(ip)
        
        return jsonify(result)
        
    @app.route('/server_setting/<config_name>', methods=['GET'])
    @login_required
    def server_setting(config_name):
        """Get server settings page"""
        conf = configparser.ConfigParser(strict=False)
        conf.read(f"{WG_CONF_PATH}/{config_name}.conf")
        
        status = get_conf_status(config_name)
        port = ""
        try:
            port = conf.get("Interface", "ListenPort")
        except:
            if status == "running":
                port = subprocess.check_output("wg show " + config_name + " listen-port", shell=True)
                port = port.decode("UTF-8")
                
        private_key = ""
        try:
            private_key = conf.get("Interface", "PrivateKey")
        except:
            pass
            
        address = ""
        try:
            address = conf.get("Interface", "Address")
        except:
            pass
            
        dns = ""
        try:
            dns = conf.get("Interface", "DNS")
        except:
            pass
            
        post_up = ""
        try:
            post_up = conf.get("Interface", "PostUp")
        except:
            pass
            
        post_down = ""
        try:
            post_down = conf.get("Interface", "PostDown")
        except:
            pass
            
        # Get endpoint interfaces
        ifaces = []
        try:
            output = subprocess.check_output("ls /sys/class/net", shell=True)
            ifaces = output.decode("UTF-8").strip().split()
        except:
            pass
            
        dashboard_conf = get_dashboard_conf()
        mtu = dashboard_conf.get("Peers", "peer_mtu", fallback="1420")
        try:
            endpoint = post_up.split("-o")[1].strip().split()[0]
        except:
            endpoint = DEFAULT_ENDPOINT
            
        try:
            remote_endpoint = dashboard_conf.get("Peers", "remote_endpoint")
        except:
            remote_endpoint = endpoint
            
        conf.clear()
        
        return render_template('server_setting.html', 
                             config_name=config_name,
                             port=port,
                             address=address,
                             private_key=private_key,
                             dns=dns,
                             post_up=post_up,
                             post_down=post_down,
                             interfaces=ifaces,
                             endpoint=endpoint,
                             remote_endpoint=remote_endpoint,
                             mtu=mtu)
                             
    @app.route('/save_server_setting/<config_name>', methods=['POST'])
    @login_required
    def save_server_setting_route(config_name):
        """Save server settings"""
        from .server_config import save_server_setting
        result, status_code = save_server_setting(request.form, config_name)
        return jsonify(result), status_code
        
    @app.route('/dashboard_setting', methods=['GET'])
    @login_required
    def dashboard_setting():
        """Get dashboard settings page"""
        dashboard_conf = get_dashboard_conf()
        
        settings = {
            "app_port": dashboard_conf.get("Server", "app_port", fallback="10086"),
            "refresh_interval": dashboard_conf.get("Server", "dashboard_refresh_interval", fallback="60000"),
            "sort_by": dashboard_conf.get("Server", "dashboard_sort", fallback="status"),
        }
        
        return render_template('dashboard_setting.html', settings=settings)
        
    @app.route('/save_dashboard_setting', methods=['POST'])
    @login_required
    def save_dashboard_setting():
        """Save dashboard settings"""
        dashboard_conf = get_dashboard_conf()
        
        try:
            app_port = request.form.get('app_port', '')
            refresh_interval = request.form.get('refresh_interval', '')
            sort_by = request.form.get('sort_by', '')
            
            dashboard_conf.set("Server", "app_port", app_port)
            dashboard_conf.set("Server", "dashboard_refresh_interval", refresh_interval)
            dashboard_conf.set("Server", "dashboard_sort", sort_by)
            
            save_dashboard_config(dashboard_conf)
            
            return redirect(url_for('dashboard_setting'))
        except Exception as e:
            return f"Error: {str(e)}"
            
    # Initialize error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        """404 error handler"""
        return render_template('404.html'), 404
        
    @app.errorhandler(500)
    def internal_error(e):
        """500 error handler"""
        return render_template('500.html'), 500
        
    return app 