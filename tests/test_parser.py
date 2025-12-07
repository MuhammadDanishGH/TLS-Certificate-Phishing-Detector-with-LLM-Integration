"""
Tests for certificate_parser module.
"""
import pytest
from src.certificate_parser import CertificateParser, parse_certificate


class TestCertificateParser:
    """Tests for CertificateParser class."""
    
    def test_parse_pem_certificate(self):
        """Test parsing PEM certificate."""
        pem_content = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKZ0RbPfVX7qMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAw0K...
-----END CERTIFICATE-----"""
        
        parser = CertificateParser()
        result = parser.parse(pem_content, "pem", "test.pem")
        
        assert result['file_name'] == "test.pem"
        assert 'pem' in result or 'subject' in result
    
    def test_parse_openssl_text(self):
        """Test parsing OpenSSL text output."""
        openssl_text = """Certificate chain
 0 s:C = US, O = Example Corp, CN = example.com
   i:C = US, O = Let's Encrypt, CN = R3
---
Server certificate
subject=C = US, O = Example Corp, CN = example.com
issuer=C = US, O = Let's Encrypt, CN = R3
---
"""
        
        parser = CertificateParser()
        result = parser.parse(openssl_text, "openssl_text", "test")
        
        assert 'subject' in result
        assert result['subject'].get('CN') == 'example.com'
    
    def test_parse_with_warnings(self):
        """Test parsing with errors generates warnings."""
        invalid_content = "Not a valid certificate"
        
        parser = CertificateParser()
        result = parser.parse(invalid_content, "unknown", "invalid")
        
        assert 'parse_warnings' in result


def test_parse_certificate_convenience():
    """Test parse_certificate convenience function."""
    content = "test content"
    result = parse_certificate(content, "unknown", "test.cert")
    
    assert result['file_name'] == "test.cert"
    assert 'raw_text' in result
