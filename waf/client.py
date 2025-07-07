import requests
import os
from dotenv import load_dotenv
import logging
import asyncio
from typing import Optional, Dict, Any
import time

logger = logging.getLogger(__name__)

class Client:
    def __init__(self, ip: str):
        self.ip = ip
        self.base_url = "https://www.virustotal.com/api/v3"
        load_dotenv()
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {
            "x-apikey": self.api_key
        } if self.api_key else {}
        self._cache = {}
        self._cache_timeout = 300  # 5 minutes cache

    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached result is still valid."""
        if key not in self._cache:
            return False
        return time.time() - self._cache[key]['timestamp'] < self._cache_timeout

    def _get_cached_result(self, key: str) -> Optional[Any]:
        """Get cached result if valid."""
        if self._is_cache_valid(key):
            return self._cache[key]['data']
        return None

    def _set_cache(self, key: str, data: Any) -> None:
        """Cache result with timestamp."""
        self._cache[key] = {
            'data': data,
            'timestamp': time.time()
        }

    def get_ip_report(self) -> Dict[str, Any]:
        """Get information about an IP address with caching."""
        cache_key = f"ip_report_{self.ip}"
        
        # Check cache first
        cached_result = self._get_cached_result(cache_key)
        if cached_result is not None:
            logger.debug(f"Using cached result for IP {self.ip}")
            return cached_result

        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {"error": "API key not configured"}

        try:
            endpoint = f"{self.base_url}/ip_addresses/{self.ip}"
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            
            if response.status_code == 429:  # Rate limit
                logger.warning("VirusTotal API rate limit reached")
                return {"error": "Rate limit reached"}
            
            if response.status_code != 200:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return {"error": f"API error: {response.status_code}"}
            
            result = response.json()
            self._set_cache(cache_key, result)
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout querying VirusTotal for IP {self.ip}")
            return {"error": "Timeout"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying VirusTotal for IP {self.ip}: {e}")
            return {"error": str(e)}

    def scan_url(self, url: str) -> Dict[str, Any]:
        """Submit a URL for analysis."""
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            endpoint = f"{self.base_url}/urls"
            data = {"url": url}
            response = requests.post(endpoint, headers=self.headers, data=data, timeout=10)
            return response.json()
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return {"error": str(e)}

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get information about a file by its hash."""
        if not self.api_key:
            return {"error": "API key not configured"}

        try:
            endpoint = f"{self.base_url}/files/{file_hash}"
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            return response.json()
        except Exception as e:
            logger.error(f"Error getting file report for {file_hash}: {e}")
            return {"error": str(e)}

    def is_ip_malicious(self) -> bool:
        """Check if the IP is malicious or suspicious with enhanced logic."""
        try:
            ip_report = self.get_ip_report()
            
            if 'error' in ip_report:
                logger.debug(f"Cannot check IP {self.ip}: {ip_report['error']}")
                return False  # Don't block if we can't verify

            if 'data' not in ip_report or 'attributes' not in ip_report['data']:
                logger.debug(f"Invalid response format for IP {self.ip}")
                return False

            attributes = ip_report['data']['attributes']
            
            # Check analysis stats
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                
                # More sophisticated scoring
                total_engines = sum(stats.values())
                if total_engines > 0:
                    malicious_ratio = malicious_count / total_engines
                    suspicious_ratio = suspicious_count / total_engines
                    
                    # Block if more than 10% of engines detect as malicious
                    # or more than 20% detect as suspicious
                    if malicious_ratio > 0.1 or suspicious_ratio > 0.2:
                        logger.warning(f"IP {self.ip} flagged as malicious/suspicious: "
                                     f"malicious={malicious_count}, suspicious={suspicious_count}")
                        return True

            # Check reputation
            if 'reputation' in attributes:
                reputation = attributes['reputation']
                if reputation < -50:  # Negative reputation threshold
                    logger.warning(f"IP {self.ip} has poor reputation: {reputation}")
                    return True

            # Check for known malware families
            if 'last_analysis_results' in attributes:
                results = attributes['last_analysis_results']
                for engine, result in results.items():
                    if result.get('category') == 'malicious':
                        threat_name = result.get('result', '')
                        if any(keyword in threat_name.lower() for keyword in 
                               ['botnet', 'trojan', 'malware', 'virus', 'backdoor']):
                            logger.warning(f"IP {self.ip} associated with malware: {threat_name}")
                            return True

            return False

        except Exception as e:
            logger.error(f"Error checking if IP {self.ip} is malicious: {e}")
            return False  # Don't block on error

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get a comprehensive threat summary for the IP."""
        report = self.get_ip_report()
        
        if 'error' in report:
            return {"error": report['error']}

        summary = {
            "ip": self.ip,
            "is_malicious": self.is_ip_malicious(),
            "reputation": 0,
            "threat_types": [],
            "detection_count": 0,
            "total_engines": 0
        }

        if 'data' in report and 'attributes' in report['data']:
            attributes = report['data']['attributes']
            
            # Reputation
            summary["reputation"] = attributes.get('reputation', 0)
            
            # Analysis stats
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                summary["detection_count"] = stats.get('malicious', 0) + stats.get('suspicious', 0)
                summary["total_engines"] = sum(stats.values())
            
            # Threat types
            if 'last_analysis_results' in attributes:
                results = attributes['last_analysis_results']
                threat_types = set()
                for engine, result in results.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        threat_name = result.get('result', '').lower()
                        if 'botnet' in threat_name:
                            threat_types.add('botnet')
                        elif 'trojan' in threat_name:
                            threat_types.add('trojan')
                        elif 'malware' in threat_name:
                            threat_types.add('malware')
                        elif 'phishing' in threat_name:
                            threat_types.add('phishing')
                
                summary["threat_types"] = list(threat_types)

        return summary

def main():
    """Enhanced main function with better testing."""
    test_ips = [
        "65.1.84.103",  # Original test IP
        "8.8.8.8",      # Google DNS (should be clean)
        "127.0.0.1",    # Localhost (should be clean)
    ]
    
    for ip in test_ips:
        print(f"\n=== Testing IP: {ip} ===")
        client = Client(ip)
        
        # Basic malicious check
        is_malicious = client.is_ip_malicious()
        print(f"Is malicious: {is_malicious}")
        
        # Detailed summary
        summary = client.get_threat_summary()
        if 'error' not in summary:
            print(f"Reputation: {summary['reputation']}")
            print(f"Detections: {summary['detection_count']}/{summary['total_engines']}")
            print(f"Threat types: {summary['threat_types']}")
        else:
            print(f"Error: {summary['error']}")

if __name__ == "__main__":
    main()