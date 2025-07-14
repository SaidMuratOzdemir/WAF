# ip_utils.py

import ipaddress
import json

def is_local_ip(ip: str) -> bool:
    """
    Loopback or private network IPs (10/8, 172.16/12, 192.168/16, ::1) are considered local.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False

async def set_ip_info(redis_client, ip: str, vt: dict = None, ban: dict = None, clean: dict = None):
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
    if ban is not None:
        info['ban'] = ban
    if clean is not None:
        info['clean'] = clean
    await redis_client.set(key, json.dumps(info))

async def get_ip_info(redis_client, ip: str) -> dict:
    key = f"ip_info:{ip}"
    val = await redis_client.get(key)
    if val:
        try:
            return json.loads(val)
        except Exception:
            return {}
    return {}

async def ban_ip(redis_client, ip: str) -> None:
    from datetime import datetime
    ban = {"banned": True, "banned_at": datetime.now().isoformat()}
    await set_ip_info(redis_client, ip, ban=ban)

async def unban_ip(redis_client, ip: str) -> None:
    info = await get_ip_info(redis_client, ip)
    if 'ban' in info:
        del info['ban']
        key = f"ip_info:{ip}"
        import json
        await redis_client.set(key, json.dumps(info))

async def is_banned_ip(redis_client, ip: str) -> bool:
    info = await get_ip_info(redis_client, ip)
    return info.get('ban', {}).get('banned', False)
