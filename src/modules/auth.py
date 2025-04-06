"""
Authentication Module - Handles user authentication
"""
import os
import configparser
import hashlib
from flask import session, redirect, url_for
from functools import wraps

from .config import get_dashboard_conf, save_dashboard_config

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("signin"))
        return f(*args, **kwargs)
    return decorated_function

def verify_user(username, password):
    """Verify user credentials"""
    config = get_dashboard_conf()
    
    # Get stored username and password
    stored_username = config.get("Account", "username")
    stored_password = config.get("Account", "password")
    
    # Check if credentials match
    if username == stored_username and password == stored_password:
        return True
    
    return False

def change_password(current_password, new_password):
    """Change user password"""
    config = get_dashboard_conf()
    
    # Get stored password
    stored_password = config.get("Account", "password")
    
    # Verify current password
    if current_password != stored_password:
        return {"status": "failed", "msg": "Current password is incorrect"}
    
    # Update password in config
    config.set("Account", "password", new_password)
    
    # Save config
    if save_dashboard_config(config):
        return {"status": "success", "msg": "Password updated successfully"}
    else:
        return {"status": "failed", "msg": "Failed to save new password"}

def secure_password(password):
    """Hash password for storage (not currently used but could be implemented)"""
    # In a production environment, you'd want to use a secure hashing algorithm with salt
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()

def verify_secure_password(stored_password, provided_password):
    """Verify a stored hashed password against a provided password (not currently used)"""
    salt_hex, key_hex = stored_password.split(':')
    salt = bytes.fromhex(salt_hex)
    stored_key = bytes.fromhex(key_hex)
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return stored_key == new_key 