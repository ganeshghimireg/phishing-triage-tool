# Phishing Email Triage and Threat Intelligence Automation Tool

## Overview
The **Phishing Email Triage and Threat Intelligence Automation Tool** is a Python-based security automation application designed to help Security Operations Centers (SOCs) and cybersecurity analysts rapidly analyze suspicious emails for malicious indicators. The tool automates the extraction of Indicators of Compromise (IOCs) from email files and queries them against external threat intelligence databases to produce actionable risk assessments with clear remediation recommendations.

Security analysts traditionally spend 10–45 minutes manually reviewing each suspicious email. This tool reduces the analysis time to under 30 seconds per email, enabling teams to prioritize the most dangerous threats and reduce analyst fatigue.

**GitHub Repository:**
https://github.com/ganeshghimireg/phishing-triage-tool

## Project Objectives

1. **Automate Email Parsing:** Extract headers, body content, attachments, and metadata from `.eml` and `.msg` email formats.
2. **IOC Extraction:** Identify URLs, IP addresses, domains, email addresses, and file hashes using optimized regular expressions.
3. **Threat Intelligence Integration:** Query extracted IOCs against VirusTotal and AbuseIPDB APIs for reputation scoring.
4. **Risk Assessment:** Calculate a consolidated risk score (0–100) mapped to a five-tier rating system: Critical, High, Medium, Low, or Clean.
5. **Actionable Reporting:** Generate human-readable console output and machine-readable JSON reports with remediation recommendations.
6. **Modular Architecture:** Enable future extensibility through independent, reusable components.
   
## Features
- Parse .eml and .msg email files
- Extract URLs, IP addresses, domains, and file hashes
- Query VirusTotal for reputation scores
- Query AbuseIPDB for abuse reports
- Generate risk scores (Critical/High/Medium/Low/Clean)
- Provide remediation recommendations

## Prerequisites

Before installing the tool, ensure you have the following:

 Python | https://www.python.org/downloads/ |
 Git | https://git-scm.com/downloads |
| VS Code | https://code.visualstudio.com/ |

**Operating System:** Windows 10/11, macOS, or Linux

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

# Obtain API Keys
VirusTotal API Key | https://www.virustotal.com/ |
AbuseIPDB API Key | https://www.abuseipdb.com/ |

# Configure Environment Variables
Create a .env file
Add API keys

# Usage
Basic Usage to analyze a single email file

## Example Output
 Suspicious URLs:
  • http://evil-phishing-site.com/verify

 Domains:
  • evil-phishing-link.com

 Analysis complete! Risk Level: HIGH

## Risk Scoring Methodology
Critical | High | Medium | Low | Clean

## Contributing
This project was developed as a coursework assignment for CYB333 Security Automation at National University.


