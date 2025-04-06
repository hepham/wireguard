"""
WireGuard Dashboard - Main application entry point
"""
import os
from flask import Flask, session
from datetime import timedelta

from modules.config import get_dashboard_conf
from modules.redis_manager import configure_redis_persistence
from modules.routes import init_routes

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__, 
               template_folder='templates',
               static_folder='static',
               static_url_path='/static')
    
    # Configure session
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'wireguard-dashboard-secret-key')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_TYPE'] = 'filesystem'
    
    # Initialize routes
    init_routes(app)
    
    # Configure Redis persistence
    configure_redis_persistence()
    
    return app

if __name__ == '__main__':
    # Get configuration
    config = get_dashboard_conf()
    app_ip = config.get("Server", "app_ip", fallback="0.0.0.0")
    app_port = int(config.get("Server", "app_port", fallback="10086"))
    
    # Create and run app
    app = create_app()
    app.run(host=app_ip, port=app_port, debug=True) 