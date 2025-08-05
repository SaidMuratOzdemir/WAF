# api/app/routers/logs.py

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional, Dict, Any
import pymongo
import os
from datetime import datetime, timedelta

from app.core.security import get_current_admin_user
from app.schemas import UserInDB

router = APIRouter(prefix="/logs", tags=["logs"])

# MongoDB connection
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017/waf_logs")

def get_mongodb_client():
    try:
        client = pymongo.MongoClient(MONGODB_URL)
        db = client.waf_logs
        return db
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MongoDB connection failed: {e}")

def safe_isoformat(timestamp):
    """Safely convert timestamp to ISO format with +3 hours timezone adjustment"""
    if isinstance(timestamp, datetime):
        # Add 3 hours to datetime object (convert UTC to Turkey time)
        adjusted_timestamp = timestamp + timedelta(hours=3)
        return adjusted_timestamp.isoformat()
    elif isinstance(timestamp, (int, float)):
        # Convert Unix timestamp to datetime
        try:
            # Handle edge cases like NaN, infinity, or very large numbers
            if isinstance(timestamp, float):
                if timestamp != timestamp:  # NaN check
                    return "1970-01-01T03:00:00"
                if timestamp == float('inf') or timestamp == float('-inf'):
                    return "1970-01-01T03:00:00"
                if timestamp > 1e12:  # Likely milliseconds, convert to seconds
                    timestamp = timestamp / 1000
                elif timestamp < 0:  # Invalid negative timestamp
                    return "1970-01-01T03:00:00"
            
            # Convert to datetime and add 3 hours (convert UTC to Turkey time)
            dt = datetime.fromtimestamp(timestamp)
            adjusted_dt = dt + timedelta(hours=3)
            return adjusted_dt.isoformat()
        except (ValueError, OSError, OverflowError):
            # Fallback for invalid timestamps
            return "1970-01-01T03:00:00"
    else:
        return str(timestamp)

@router.get("/requests")
async def get_recent_requests(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, le=1000),
    site_name: Optional[str] = None,
    client_ip: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    blocked_only: bool = False,
    db = Depends(get_mongodb_client),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get recent requests with optional filtering - ADMIN ONLY"""
    try:
        filter_query = {}
        
        if site_name:
            filter_query["site_name"] = site_name
        if client_ip:
            filter_query["client_ip"] = client_ip
        if method:
            filter_query["method"] = method.upper()
        if blocked_only:
            filter_query["is_blocked"] = True
            
        # Calculate skip for pagination
        skip = (page - 1) * limit
        
        # Get total count
        total_count = db.requests.count_documents(filter_query)
        
        # Get requests with pagination
        requests = list(db.requests.find(filter_query).sort("timestamp", -1).skip(skip).limit(limit))
        
        # Convert to new format for frontend
        logs = []
        for req in requests:
            # Get corresponding response for status code
            response = db.responses.find_one({"request_id": req["request_id"]})
            status_code = response["status_code"] if response else 0
            
            log_entry = {
                "id": req["request_id"],
                "ip": req["client_ip"],
                "method": req["method"],
                "status": status_code,
                "url": req["path"],
                "host": req.get("host", ""),
                "timestamp": safe_isoformat(req["timestamp"]),
                "request": f"{req['method']} {req['path']} HTTP/1.1\nHost: {req.get('host', '')}\n{chr(10).join([f'{k}: {v}' for k, v in req.get('headers', {}).items()])}",
                "response": f"HTTP/1.1 {status_code} OK\n{chr(10).join([f'{k}: {v}' for k, v in response.get('headers', {}).items()])}" if response else "",
                "site_name": req.get("site_name", ""),
                "is_blocked": req.get("is_blocked", False),
                "block_reason": req.get("block_reason", "")
            }
            logs.append(log_entry)
            
        return {
            "logs": logs,
            "total": total_count,
            "page": page,
            "hasMore": skip + limit < total_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get requests: {e}")

@router.get("/requests/{request_id}")
async def get_request_details(
    request_id: str, 
    db = Depends(get_mongodb_client),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get detailed request and response information - ADMIN ONLY"""
    try:
        request = db.requests.find_one({"request_id": request_id})
        response = db.responses.find_one({"request_id": request_id})
        
        if not request:
            raise HTTPException(status_code=404, detail="Request not found")
            
        # Convert ObjectId to string for JSON serialization
        if request:
            request["_id"] = str(request["_id"])
            request["timestamp"] = safe_isoformat(request["timestamp"])
            
        if response:
            response["_id"] = str(response["_id"])
            response["timestamp"] = safe_isoformat(response["timestamp"])
            
        return {
            "request": request,
            "response": response
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get request details: {e}")

@router.get("/statistics")
async def get_log_statistics(
    hours: int = Query(default=24, le=168),  # Max 7 days
    db = Depends(get_mongodb_client),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get logging statistics - ADMIN ONLY"""
    try:
        # Calculate time range with +3 hours adjustment
        end_time = datetime.utcnow() + timedelta(hours=3)
        start_time = end_time - timedelta(hours=hours)
        
        # Pipeline for aggregation
        pipeline = [
            {
                "$match": {
                    "timestamp": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$group": {
                    "_id": {
                        "site_name": "$site_name",
                        "is_blocked": "$is_blocked"
                    },
                    "count": {"$sum": 1},
                    "unique_ips": {"$addToSet": "$client_ip"}
                }
            },
            {
                "$group": {
                    "_id": "$_id.site_name",
                    "total_requests": {
                        "$sum": "$count"
                    },
                    "blocked_requests": {
                        "$sum": {
                            "$cond": [{"$eq": ["$_id.is_blocked", True]}, "$count", 0]
                        }
                    },
                    "unique_ips": {
                        "$addToSet": "$unique_ips"
                    }
                }
            }
        ]
        
        stats = list(db.requests.aggregate(pipeline))
        
        # Flatten unique IPs
        for stat in stats:
            all_ips = []
            for ip_list in stat["unique_ips"]:
                all_ips.extend(ip_list)
            stat["unique_ips"] = list(set(all_ips))
            stat["unique_ip_count"] = len(stat["unique_ips"])
            del stat["unique_ips"]
            
        return {
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "hours": hours
            },
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {e}")

@router.get("/blocked")
async def get_blocked_requests(
    limit: int = Query(default=50, le=500),
    site_name: Optional[str] = None,
    db = Depends(get_mongodb_client),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get blocked requests with reasons - ADMIN ONLY"""
    try:
        filter_query = {"is_blocked": True}
        if site_name:
            filter_query["site_name"] = site_name
            
        blocked = list(db.requests.find(filter_query).sort("timestamp", -1).limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        for req in blocked:
            req["_id"] = str(req["_id"])
            req["timestamp"] = safe_isoformat(req["timestamp"])
            
        return {
            "blocked_requests": blocked,
            "total": len(blocked)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get blocked requests: {e}")

@router.delete("/requests/{request_id}")
async def delete_request(
    request_id: str, 
    db = Depends(get_mongodb_client),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Delete a specific request and its response - ADMIN ONLY"""
    try:
        # Delete request
        request_result = db.requests.delete_one({"request_id": request_id})
        
        # Delete corresponding response
        response_result = db.responses.delete_one({"request_id": request_id})
        
        if request_result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Request not found")
            
        return {
            "message": "Request and response deleted successfully",
            "request_deleted": request_result.deleted_count > 0,
            "response_deleted": response_result.deleted_count > 0
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete request: {e}") 