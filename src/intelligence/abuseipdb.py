"""
AbuseIPDB API Integration
"""

import requests

class AbuseIPDBClient:
    """Client for AbuseIPDB API v2"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {"Key": api_key, "Accept": "application/json"}
    
    def check_ip(self, ip):
        """Check IP for abuse reports"""
        try:
            response = requests.get(
                f"{self.base_url}/check",
                headers=self.headers,
                params={'ipAddress': ip, 'maxAgeInDays': 90}
            )
            if response.status_code == 200:
                data = response.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                return {
                    'abuse_confidence_score': score,
                    'total_reports': data.get('totalReports', 0),
                    'risk': self._calc_risk(score)
                }
            return {'error': f"Status: {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}
    
    def _calc_risk(self, score):
        if score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 10:
            return 'low'
        return 'clean'