# ip_utils.py

import ipaddress

def is_local_ip(ip: str) -> bool:
    """
    Loopback or private network IPs (10/8, 172.16/12, 192.168/16, ::1) are considered local.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False

async def ban_ip(redis_client, ip: str) -> None:
    """
    Permanently ban an IP by setting a Redis key.
    Manual removal can be done directly in Redis for debugging.
    """
    key = f"banned_ip:{ip}"
    # No expiry → stays banned until manually deleted
    await redis_client.set(key, "1")

async def unban_ip(redis_client, ip: str) -> None:
    """
    Remove an IP from the ban list.
    """
    key = f"banned_ip:{ip}"
    await redis_client.delete(key)


async def is_banned_ip(redis_client, ip: str) -> bool:
    """
    Check if an IP is on the ban list.
    """
    key = f"banned_ip:{ip}"
    result = await redis_client.exists(key)
    return result == 1
