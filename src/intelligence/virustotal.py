"""
VirusTotal API Integration
"""

import requests
import time

class VirusTotalClient:
    """Client for VirusTotal API v3"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key, "Accept": "application/json"}
    
    def check_url(self, url):
        """Check URL reputation"""
        try:
            response = requests.post(
                f"{self.base_url}/urls",
                headers=self.headers,
                data={"url": url}
            )
            if response.status_code == 200:
                url_id = response.json()['data']['id']
                time.sleep(2)
                result = requests.get(f"{self.base_url}/urls/{url_id}", headers=self.headers)
                if result.status_code == 200:
                    stats = result.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    return {
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'risk': self._calc_risk(stats)
                    }
            return {'malicious': 0, 'suspicious': 0, 'risk': 'unknown'}
        except Exception as e:
            return {'error': str(e)}
    
    def check_ip(self, ip):
        """Check IP reputation"""
        try:
            response = requests.get(f"{self.base_url}/ip_addresses/{ip}", headers=self.headers)
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'risk': self._calc_risk(stats)
                }
            return {'error': f"Status: {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}
    
    def check_hash(self, file_hash):
        """Check file hash reputation"""
        try:
            response = requests.get(f"{self.base_url}/files/{file_hash}", headers=self.headers)
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'risk': self._calc_risk(stats)
                }
            return {'malicious': 0, 'suspicious': 0, 'risk': 'clean'}
        except Exception as e:
            return {'error': str(e)}
    
    def _calc_risk(self, stats):
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        if malicious >= 2:
            return 'high'
        elif malicious >= 1 or suspicious >= 3:
            return 'medium'
        elif suspicious >= 1:
            return 'low'
        return 'clean'