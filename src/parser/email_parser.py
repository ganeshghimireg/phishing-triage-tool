"""
Email Parser Module - Reads .eml and .msg email files
"""

import email
from email import policy
from email.parser import BytesParser
import hashlib
from pathlib import Path

class EmailParser:
    """Parse email files and extract components"""
    
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.email_data = {
            'headers': {},
            'sender': '',
            'recipient': '',
            'subject': '',
            'body_text': '',
            'body_html': '',
            'attachments': [],
            'hashes': []
        }
    
    def parse(self):
        """Main parsing method"""
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        if self.file_path.suffix.lower() == '.eml':
            self._parse_eml()
        elif self.file_path.suffix.lower() == '.msg':
            self._parse_msg()
        else:
            raise ValueError(f"Unsupported file type: {self.file_path.suffix}")
        
        return self.email_data
    
    def _parse_eml(self):
        """Parse .eml file"""
        with open(self.file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            
            self.email_data['headers'] = dict(msg.items())
            self.email_data['sender'] = msg.get('From', 'Unknown')
            self.email_data['recipient'] = msg.get('To', 'Unknown')
            self.email_data['subject'] = msg.get('Subject', 'No Subject')
            
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        self.email_data['body_text'] = part.get_content()
                    elif part.get_content_type() == "text/html":
                        self.email_data['body_html'] = part.get_content()
                    elif part.get_content_disposition() == "attachment":
                        self._extract_attachment(part)
            else:
                self.email_data['body_text'] = msg.get_content()
    
    def _parse_msg(self):
        """Parse .msg file"""
        try:
            import extract_msg
            msg = extract_msg.Message(self.file_path)
            self.email_data['sender'] = msg.sender
            self.email_data['recipient'] = msg.to
            self.email_data['subject'] = msg.subject
            self.email_data['body_text'] = msg.body
            msg.close()
        except ImportError:
            print("Warning: extract-msg not installed")
            raise
    
    def _extract_attachment(self, part):
        """Extract and hash attachments"""
        filename = part.get_filename()
        if filename:
            content = part.get_payload(decode=True)
            file_hash = hashlib.sha256(content).hexdigest()
            self.email_data['attachments'].append({
                'name': filename,
                'size': len(content),
                'sha256': file_hash
            })
            self.email_data['hashes'].append(file_hash)