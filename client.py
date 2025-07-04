import requests
import os
from dotenv import load_dotenv


class Client:
    def __init__(self, ip):
        self.ip = ip
        self.base_url = "https://www.virustotal.com/api/v3"
        load_dotenv()
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {
            "x-apikey": self.api_key
        }

    def get_ip_report(self):
        """Get information about an IP address"""
        endpoint = f"{self.base_url}/ip_addresses/{self.ip}"
        response = requests.get(endpoint, headers=self.headers)
        return response.json()

    def scan_url(self, url):
        """Submit a URL for analysis"""
        endpoint = f"{self.base_url}/urls"
        data = {"url": url}
        response = requests.post(endpoint, headers=self.headers, data=data)
        return response.json()

    def get_file_report(self, file_hash):
        """Get information about a file by its hash"""
        endpoint = f"{self.base_url}/files/{file_hash}"
        response = requests.get(endpoint, headers=self.headers)
        return response.json()

    def is_ip_malicious(self):
        """get the result of the ip report and check if it is malicious or suspicious"""
        ip_report = self.get_ip_report()
        if 'data' in ip_report and 'attributes' in ip_report['data']:
            attributes = ip_report['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                malware_count = stats.get('malware', 0)

                if malicious_count > 0 or suspicious_count > 0 or malware_count > 0:
                    return True
        return False


def main():
    ip = "65.1.84.103"
    client = Client(ip)

    if client.is_ip_malicious():
        print(f"The IP address {ip} is malicious or suspicious.")
    else:
        print(f"The IP address {ip} is clean.")