# client.py

import requests
import os
from dotenv import load_dotenv
import logging
import time
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class Client:
    def __init__(self, ip: str):
        self.ip = ip
        self.base_url = "https://www.virustotal.com/api/v3"
        load_dotenv()
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
        # In-process cache to reduce duplicate calls within ~5 minutes
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_timeout = 300  # seconds

    def _is_cache_valid(self, key: str) -> bool:
        if key not in self._cache:
            return False
        return (time.time() - self._cache[key]["timestamp"]) < self._cache_timeout

    def _get_cached_result(self, key: str) -> Optional[Any]:
        if self._is_cache_valid(key):
            return self._cache[key]["data"]
        return None

    def _set_cache(self, key: str, data: Any) -> None:
        self._cache[key] = {"data": data, "timestamp": time.time()}

    def get_ip_report(self) -> Dict[str, Any]:
        """
        Fetch IP report from VirusTotal, with in-process caching and skip for local IPs.
        """
        cache_key = f"ip_report_{self.ip}"
        # Skip for local/private IPs
        if self.ip in ["127.0.0.1", "localhost", "::1"] or \
           self.ip.startswith("192.168.") or self.ip.startswith("10."):
            logger.debug(f"Skipping VirusTotal check for local IP {self.ip}")
            return {"data": {"attributes": {"is_local": True}}}

        # In-process cache
        cached = self._get_cached_result(cache_key)
        if cached is not None:
            logger.debug(f"Using in-process cache for {self.ip}")
            return cached

        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {"error": "API key not configured"}

        try:
            url = f"{self.base_url}/ip_addresses/{self.ip}"
            resp = requests.get(url, headers=self.headers, timeout=10)
            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit hit")
                return {"error": "Rate limit"}
            if resp.status_code != 200:
                logger.warning(f"VirusTotal returned {resp.status_code}")
                return {"error": f"API error: {resp.status_code}"}

            result = resp.json()
            self._set_cache(cache_key, result)
            return result

        except requests.exceptions.Timeout:
            logger.error(f"Timeout querying VT for {self.ip}")
            return {"error": "Timeout"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying VT for {self.ip}: {e}")
            return {"error": str(e)}

    def scan_url(self, url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "API key not configured"}
        try:
            endpoint = f"{self.base_url}/urls"
            resp = requests.post(endpoint, headers=self.headers, data={"url": url}, timeout=10)
            return resp.json()
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return {"error": str(e)}

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "API key not configured"}
        try:
            endpoint = f"{self.base_url}/files/{file_hash}"
            resp = requests.get(endpoint, headers=self.headers, timeout=10)
            return resp.json()
        except Exception as e:
            logger.error(f"Error fetching file report for {file_hash}: {e}")
            return {"error": str(e)}

    def is_ip_malicious(self) -> bool:
        """
        Decide if IP is malicious based on VT analysis.
        Returns False for local IPs or on any error.
        """
        # Skip local
        if self.ip in ["127.0.0.1", "localhost", "::1"] or \
           self.ip.startswith("192.168.") or self.ip.startswith("10."):
            return False

        report = self.get_ip_report()
        if "error" in report:
            return False

        attrs = report.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        if total:
            if stats.get("malicious", 0) / total > 0.1 or \
               stats.get("suspicious", 0) / total > 0.2:
                return True

        if attrs.get("reputation", 0) < -50:
            return True

        for eng, res in attrs.get("last_analysis_results", {}).items():
            if res.get("category") == "malicious":
                nm = (res.get("result") or "").lower()
                if any(k in nm for k in ["botnet", "trojan", "malware", "virus", "backdoor"]):
                    return True

        return False

    def get_threat_summary(self) -> Dict[str, Any]:
        report = self.get_ip_report()
        if "error" in report:
            return {"error": report["error"]}

        attrs = report.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        summary = {
            "ip": self.ip,
            "is_malicious": self.is_ip_malicious(),
            "reputation": attrs.get("reputation", 0),
            "threat_types": [],
            "detection_count": stats.get("malicious", 0) + stats.get("suspicious", 0),
            "total_engines": sum(stats.values())
        }
