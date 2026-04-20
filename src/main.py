from dotenv import load_dotenv
import os
import sys
import email
from email import policy
from email.parser import BytesParser

# Load environment variables
load_dotenv()

def parse_email(file_path):
    """Parse an email file and extract headers and body"""
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        # Extract email details
        from_addr = msg.get('From', 'Unknown')
        subject = msg.get('Subject', 'No Subject')
        to_addr = msg.get('To', 'Unknown')
        date = msg.get('Date', 'Unknown')
        
        # Get body content
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body = part.get_content()
                    break
        else:
            body = msg.get_content()
        
        return {
            'from': from_addr,
            'subject': subject,
            'to': to_addr,
            'date': date,
            'body': body
        }
    except Exception as e:
        print(f"Error parsing email: {e}")
        return None

def extract_iocs(content):
    """Extract Indicators of Compromise from email content"""
    import re
    
    iocs = {
        'urls': [],
        'emails': [],
        'ips': [],
        'domains': []
    }
    
    # Extract URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s,;()<>"\']*'
    iocs['urls'] = re.findall(url_pattern, content)
    
    # Extract emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    iocs['emails'] = re.findall(email_pattern, content)
    
    # Extract IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    iocs['ips'] = re.findall(ip_pattern, content)
    
    # Extract domains (simplified)
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    iocs['domains'] = list(set(re.findall(domain_pattern, content)))
    
    return iocs

def analyze_phishing_risk(email_data, iocs):
    """Simple phishing risk analysis"""
    risk_score = 0
    reasons = []
    
    # Check for urgency keywords
    urgency_words = ['urgent', 'immediate', 'suspended', 'verify', 'account', 'security']
    body_lower = email_data['body'].lower()
    
    for word in urgency_words:
        if word in body_lower:
            risk_score += 1
            reasons.append(f"Contains urgency keyword: '{word}'")
    
    # Check for suspicious URLs
    if iocs['urls']:
        risk_score += len(iocs['urls'])
        reasons.append(f"Contains {len(iocs['urls'])} suspicious URL(s)")
    
    # Check for suspicious sender
    suspicious_domains = ['gmail.com', 'yahoo.com', 'hotmail.com']
    from_lower = email_data['from'].lower()
    for domain in suspicious_domains:
        if domain in from_lower and 'security' in from_lower:
            risk_score += 2
            reasons.append(f"Suspicious sender using {domain}")
    
    # Determine risk level
    if risk_score >= 5:
        risk_level = "HIGH"
    elif risk_score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return risk_level, risk_score, reasons

def main():
    # Check if email file was provided
    if len(sys.argv) < 2:
        print("Usage: python src/main.py <email_file>")
        print("Example: python src/main.py samples/sample_email.eml")
        sys.exit(1)
    
    email_file = sys.argv[1]
    
    print("\n" + "="*50)
    print("PHISHING EMAIL TRIAGE TOOL")
    print("="*50 + "\n")
    
    # Step 1: Parse the email
    print(f"[1/4] Parsing: {email_file}")
    email_data = parse_email(email_file)
    
    if not email_data:
        print("❌ Failed to parse email file!")
        sys.exit(1)
    
    print(f"From: {email_data['from']}")
    print(f"Subject: {email_data['subject']}")
    print(f"To: {email_data['to']}")
    print(f"Date: {email_data['date']}\n")
    
    # Step 2: Extract IOCs
    print("[2/4] Extracting IOCs...")
    full_content = f"{email_data['subject']}\n{email_data['body']}"
    iocs = extract_iocs(full_content)
    
    print(f"📊 URLs found: {len(iocs['urls'])}")
    print(f"📧 Emails found: {len(iocs['emails'])}")
    print(f"🌐 Domains found: {len(iocs['domains'])}")
    print(f"🔢 IPs found: {len(iocs['ips'])}\n")
    
    # Step 3: Analyze risk
    print("[3/4] Analyzing phishing risk...")
    risk_level, risk_score, reasons = analyze_phishing_risk(email_data, iocs)
    
    print(f"\n⚠️ RISK ASSESSMENT: {risk_level} (Score: {risk_score}/10)")
    print("\nReasons:")
    for reason in reasons[:5]:  # Show top 5 reasons
        print(f"  • {reason}")
    
    # Step 4: Generate report
    print("\n[4/4] Generating report...")
    print("\n" + "-"*50)
    print("IOC SUMMARY:")
    print("-"*50)
    
    if iocs['urls']:
        print("\n🔗 Suspicious URLs:")
        for url in iocs['urls'][:3]:  # Show first 3 URLs
            print(f"  • {url}")
    
    if iocs['domains']:
        print("\n🌐 Domains:")
        for domain in iocs['domains'][:3]:
            print(f"  • {domain}")
    
    print("\n" + "="*50)
    print(f"✅ Analysis complete! Risk Level: {risk_level}")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()#!/usr/bin/env python3
