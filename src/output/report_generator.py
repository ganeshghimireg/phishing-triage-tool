"""
Report Generator Module
"""

import json
from datetime import datetime

class ReportGenerator:
    """Generate and export analysis reports"""
    
    def generate_full_report(self, email_data, iocs, vt_results, abuse_results, risk_result):
        report = {
            'metadata': {
                'tool': 'Phishing Email Triage Tool',
                'timestamp': datetime.now().isoformat()
            },
            'email_summary': {
                'sender': email_data.get('sender', 'Unknown'),
                'subject': email_data.get('subject', 'No Subject'),
                'attachment_count': len(email_data.get('attachments', []))
            },
            'extracted_iocs': {
                'urls': iocs.get('urls', []),
                'ips': iocs.get('ips', []),
                'domains': iocs.get('domains', [])
            },
            'risk_assessment': {
                'score': risk_result.get('score', 0),
                'rating': risk_result.get('rating', 'UNKNOWN'),
                'recommendation': risk_result.get('recommendation', 'Review with caution.')
            }
        }
        return report
    
    def display_report(self, report):
        risk = report['risk_assessment']
        email = report['email_summary']
        iocs = report['extracted_iocs']
        
        output = []
        output.append("\n" + "="*60)
        output.append("PHISHING EMAIL ANALYSIS REPORT")
        output.append("="*60)
        output.append(f"\nFrom: {email['sender']}")
        output.append(f"Subject: {email['subject']}")
        output.append(f"\nExtracted IOCs:")
        output.append(f"  URLs: {len(iocs['urls'])}")
        output.append(f"  IPs:  {len(iocs['ips'])}")
        output.append(f"\nRISK: {risk['rating']} (Score: {risk['score']}/100)")
        output.append(f"\nRecommendation: {risk['recommendation']}")
        output.append("\n" + "="*60)
        return "\n".join(output)
    
    def save_report(self, report, filepath):
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        return filepath