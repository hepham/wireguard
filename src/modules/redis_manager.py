"""
Redis Manager - Handles Redis connections and operations
"""
import redis
import time
import json
from datetime import datetime

# Redis configuration
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # Set this if your Redis server requires authentication
REDIS_PREFIX = 'wireguard:'

# Redis connection with retry
def get_redis_client(max_retries=3, retry_delay=1):
    """Get Redis client with connection retry logic"""
    for attempt in range(max_retries):
        try:
            r = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                password=REDIS_PASSWORD,
                decode_responses=False
            )
            r.ping()  # Test connection
            return r
        except redis.exceptions.ConnectionError as e:
            if attempt < max_retries - 1:
                print(f"Redis connection failed, retrying in {retry_delay}s... ({e})")
                time.sleep(retry_delay)
            else:
                print(f"Redis connection failed after {max_retries} attempts: {e}")
                return None

def configure_redis_persistence():
    """Configure Redis to save data to disk"""
    r = get_redis_client()
    if not r:
        print("Warning: Could not configure Redis persistence - connection failed")
        return False
    
    try:
        # Configure Redis to save every 60 seconds if at least 1 key changed
        r.config_set('save', '60 1')
        print("Redis persistence configured successfully")
        return True
    except redis.exceptions.ResponseError as e:
        print(f"Warning: Could not configure Redis persistence - {e}")
        return False
    except Exception as e:
        print(f"Warning: Could not configure Redis persistence - {e}")
        return False

def save_peer_to_redis(config_name, peer_id, peer_data):
    """Save peer data to Redis"""
    r = get_redis_client()
    if not r:
        return False
    
    key = f"{config_name}_peer:{peer_id}"
    r.set(key, json.dumps(peer_data))
    return True

def delete_peer_from_redis(config_name, peer_id):
    """Delete peer data from Redis"""
    r = get_redis_client()
    if not r:
        return False
    
    key = f"{config_name}_peer:{peer_id}"
    r.delete(key)
    return True

def get_peer_from_redis(config_name, peer_id):
    """Get peer data from Redis"""
    r = get_redis_client()
    if not r:
        return None
    
    key = f"{config_name}_peer:{peer_id}"
    data = r.get(key)
    if data:
        return json.loads(data.decode('utf-8'))
    return None

def get_all_peers_from_redis(config_name):
    """Get all peers for a configuration from Redis"""
    r = get_redis_client()
    if not r:
        return []
    
    peers = []
    for key in r.scan_iter(f"{config_name}_peer:*"):
        try:
            peer_data = r.get(key)
            if peer_data:
                peers.append(json.loads(peer_data.decode('utf-8')))
        except Exception as e:
            print(f"Error loading peer data: {e}")
    
    return peers

def get_peer_key(config_name, peer_id):
    """Get Redis key for a peer"""
    return f"{config_name}_peer:{peer_id}" 