# ./waf/ip_utils.py

import ipaddress
import json
from datetime import datetime

# --- Ban Logic ---
# We will use a simple, dedicated key for temporary bans.
# This is more efficient than storing the ban status inside a complex JSON object.
BAN_KEY_PREFIX = "banned_ip:"

async def ban_ip_for_duration(redis_client, ip: str, duration: int) -> None:
    """
    Bans an IP by creating a key in Redis with a specific expiration time.
    """
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    # SETEX atomically sets a key with an expiration time in seconds.
    # We store the reason as the value for debugging purposes.
    await redis_client.setex(ban_key, duration, "banned")

async def is_banned_ip(redis_client, ip: str) -> bool:
    """
    Checks if an IP is banned by seeing if the ban key exists in Redis.
    """
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    return await redis_client.exists(ban_key)

async def unban_ip(redis_client, ip: str) -> None:
    """
    Unbans an IP by explicitly deleting the ban key.
    """
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    await redis_client.delete(ban_key)


# --- IP Info and Geolocation/VT Cache Logic ---
# This logic can remain for storing non-expiring data like VirusTotal results.
# It is now separate from the ban logic.

def is_local_ip(ip: str) -> bool:
    """
    Checks if an IP is a loopback or private network address.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False

async def set_ip_info(redis_client, ip: str, vt: dict = None, clean: dict = None):
    """
    Sets non-banning information for an IP, like VirusTotal results.
    """
    key = f"ip_info:{ip}"
    info = {}
    val = await redis_client.get(key)
    if val:
        try:
            info = json.loads(val)
        except Exception:
            info = {}
    if vt is not None:
        info['vt'] = vt
    if clean is not None:
        info['clean'] = clean
    await redis_client.set(key, json.dumps(info))

async def get_ip_info(redis_client, ip: str) -> dict:
    """
    Gets non-banning information for an IP.
    """
    key = f"ip_info:{ip}"
    val = await redis_client.get(key)
    if val:
        try:
            return json.loads(val)
        except Exception:
            return {}
    return {}

# The old ban_ip function is no longer needed as we use ban_ip_for_duration.
# You can keep it for legacy purposes or remove it.
# async def ban_ip(redis_client, ip: str) -> None:
#     ban = {"banned": True, "banned_at": datetime.now().isoformat()}
#     await set_ip_info(redis_client, ip, ban=ban)