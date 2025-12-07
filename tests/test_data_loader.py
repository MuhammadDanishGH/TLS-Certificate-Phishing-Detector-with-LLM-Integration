"""
Tests for data_loader module.
"""
import pytest
from pathlib import Path
from src.data_loader import CertificateLoader, load_single_file


class TestCertificateLoader:
    """Tests for CertificateLoader class."""
    
    def test_detect_pem_file(self, tmp_path):
        """Test PEM file detection."""
        # Create temp PEM file
        pem_content = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAK...
-----END CERTIFICATE-----"""
        
        pem_file = tmp_path / "test.pem"
        pem_file.write_text(pem_content)
        
        loader = CertificateLoader()
        file_type = loader.detect_file_type(str(pem_file))
        
        assert file_type == "pem"
    
    def test_detect_openssl_text(self, tmp_path):
        """Test OpenSSL text dump detection."""
        openssl_content = """Certificate chain
 0 s:CN=example.com
   i:CN=Let's Encrypt
---
Server certificate
-----BEGIN CERTIFICATE-----
...
"""
        
        text_file = tmp_path / "cert"
        text_file.write_text(openssl_content)
        
        loader = CertificateLoader()
        file_type = loader.detect_file_type(str(text_file))
        
        assert file_type == "openssl_text"
    
    def test_read_certificate_file(self, tmp_path):
        """Test reading certificate file."""
        content = "Test certificate content"
        cert_file = tmp_path / "test_cert"
        cert_file.write_text(content)
        
        loader = CertificateLoader()
        raw_content, file_type, label = loader.read_certificate_file(str(cert_file))
        
        assert raw_content == content
        assert label == "unknown"
    
    def test_label_inference_from_path(self, tmp_path):
        """Test label inference from directory structure."""
        # Create benign directory
        benign_dir = tmp_path / "benign"
        benign_dir.mkdir()
        benign_file = benign_dir / "cert1"
        benign_file.write_text("content")
        
        loader = CertificateLoader()
        _, _, label = loader.read_certificate_file(str(benign_file))
        
        assert label == "benign"


def test_load_single_file(tmp_path):
    """Test load_single_file convenience function."""
    content = "Test content"
    test_file = tmp_path / "cert"
    test_file.write_text(content)
    
    result = load_single_file(str(test_file))
    
    assert result['file_name'] == "cert"
    assert result['raw_content'] == content
    assert 'file_type' in result
