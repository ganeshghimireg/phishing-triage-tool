"""
IOC Extractor - Finds URLs, IPs, domains in text
"""

import re
from urllib.parse import urlparse

class IOCExtractor:
    """Extract Indicators of Compromise from email content"""
    
    def __init__(self):
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE
        )
        self.ip_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            re.IGNORECASE
        )
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            re.IGNORECASE
        )
        self.email_pattern = re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            re.IGNORECASE
        )
    
    def extract_all(self, text):
        """Extract all IOCs from text"""
        if not text:
            return {'urls': [], 'ips': [], 'domains': [], 'emails': [], 'hashes': []}
        
        urls = self.url_pattern.findall(text)
        ips = self.ip_pattern.findall(text)
        domains = self._extract_domains(text, urls)
        emails = self.email_pattern.findall(text)
        
        return {
            'urls': list(set(urls)),
            'ips': [ip for ip in set(ips) if self._is_valid_ip(ip)],
            'domains': list(set(domains)),
            'emails': list(set(emails))
        }
    
    def _is_valid_ip(self, ip):
        """Validate IP address (not private/reserved)"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        first_octet = int(parts[0])
        if (first_octet == 10 or first_octet == 127 or
            (first_octet == 172 and 16 <= int(parts[1]) <= 31) or
            (first_octet == 192 and int(parts[1]) == 168)):
            return False
        return True
    
    def _extract_domains(self, text, urls):
        """Extract domains from text and URLs"""
        domains = []
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc
            if domain:
                domain = domain.split(':')[0]
                domains.append(domain)
        found_domains = self.domain_pattern.findall(text)
        domains.extend(found_domains)
        cleaned = []
        for domain in set(domains):
            if domain.startswith('www.'):
                domain = domain[4:]
            cleaned.append(domain.lower())
        return cleaned