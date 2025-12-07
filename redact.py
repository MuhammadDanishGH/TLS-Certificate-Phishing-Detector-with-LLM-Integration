"""
PII redaction utilities for privacy protection.
"""
import re
from typing import Dict, Any


def redact_ip_addresses(text: str) -> str:
    """Redact IP addresses from text."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.sub(ip_pattern, '[REDACTED_IP]', text)


def redact_email_addresses(text: str) -> str:
    """Redact email addresses from text."""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.sub(email_pattern, '[REDACTED_EMAIL]', text)


def redact_certificate(cert: Dict[str, Any], redact_pii: bool = True) -> Dict[str, Any]:
    """
    Redact sensitive information from certificate.
    
    Args:
        cert: Certificate dictionary
        redact_pii: Whether to redact PII
        
    Returns:
        Redacted certificate
    """
    if not redact_pii:
        return cert
    
    cert_copy = cert.copy()
    
    # Redact from raw_text
    if 'raw_text' in cert_copy:
        text = cert_copy['raw_text']
        text = redact_ip_addresses(text)
        text = redact_email_addresses(text)
        cert_copy['raw_text'] = text
    
    # Redact from subject/issuer fields
    for field in ['subject', 'issuer']:
        if field in cert_copy:
            for key, value in cert_copy[field].items():
                if isinstance(value, str):
                    value = redact_email_addresses(value)
                    cert_copy[field][key] = value
    
    return cert_copy
