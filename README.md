# Phishing Email Triage and Threat Intelligence Tool

## Overview
This tool analyzes suspicious emails by extracting indicators of compromise (IOCs) and checking them against VirusTotal and AbuseIPDB threat intelligence APIs.

## Features
- Parse .eml and .msg email files
- Extract URLs, IP addresses, domains, and file hashes
- Query VirusTotal for reputation scores
- Query AbuseIPDB for abuse reports
- Generate risk scores (Critical/High/Medium/Low/Clean)
- Provide remediation recommendations

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/phishing-email-triage-tool.git
cd phishing-email-triage-tool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
