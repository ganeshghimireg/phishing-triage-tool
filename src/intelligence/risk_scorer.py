"""
Risk Scoring Algorithm
"""

class RiskScorer:
    """Calculate overall risk score for an email"""
    
    def __init__(self):
        self.weights = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'clean': 0, 'unknown': 10}
    
    def calculate_score(self, email_data, vt_results, abuse_results):
        """Calculate overall risk score and rating"""
        scores = []
        
        for url in vt_results.get('urls', []):
            scores.append(self.weights.get(url.get('risk', 'unknown'), 10))
        for ip in vt_results.get('ips', []):
            scores.append(self.weights.get(ip.get('risk', 'unknown'), 10))
        for ip in abuse_results.get('ips', []):
            scores.append(self.weights.get(ip.get('risk', 'unknown'), 10))
        for h in vt_results.get('hashes', []):
            scores.append(self.weights.get(h.get('risk', 'unknown'), 10))
        
        anomaly_score = self._calc_anomaly_score(email_data)
        scores.append(anomaly_score)
        
        final_score = sum(scores) / len(scores) if scores else 0
        
        if final_score >= 75:
            rating = 'CRITICAL'
        elif final_score >= 60:
            rating = 'HIGH'
        elif final_score >= 35:
            rating = 'MEDIUM'
        elif final_score >= 15:
            rating = 'LOW'
        else:
            rating = 'CLEAN'
        
        return {
            'score': round(final_score, 2),
            'rating': rating,
            'recommendation': self._get_recommendation(rating)
        }
    
    def _calc_anomaly_score(self, email_data):
        score = 0
        sender = email_data.get('sender', '').lower()
        suspicious = ['noreply', 'admin', 'support', 'service', 'security']
        for s in suspicious:
            if s in sender:
                score += 15
                break
        
        subject = email_data.get('subject', '').lower()
        urgency = ['urgent', 'immediate', 'password', 'verify', 'confirm']
        for u in urgency:
            if u in subject:
                score += 5
        
        headers = email_data.get('headers', {})
        reply_to = headers.get('Reply-To', '')
        if reply_to and reply_to != email_data.get('sender', ''):
            score += 20
        
        if len(email_data.get('attachments', [])) > 2:
            score += 10
        
        return min(score, 100)
    
    def _get_recommendation(self, rating):
        recs = {
            'CRITICAL': "BLOCK IMMEDIATELY - Do not open. Delete the email.",
            'HIGH': "HIGH RISK - Do not click links. Quarantine the email.",
            'MEDIUM': "MEDIUM RISK - Investigate further before acting.",
            'LOW': "LOW RISK - Likely benign but verify suspicious elements.",
            'CLEAN': "CLEAN - No threats detected."
        }
        return recs.get(rating, "Review with caution.")