"""
Multi-format certificate parser supporting PEM, DER, and OpenSSL text dumps.
"""
import re
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import base64

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID, ExtensionOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.warning("cryptography library not available, limited parsing")

logger = logging.getLogger(__name__)


class CertificateParser:
    """Parse certificates from multiple formats into canonical JSON."""
    
    def __init__(self):
        if not CRYPTO_AVAILABLE:
            logger.warning("Cryptography library not available. Parser will have limited functionality.")
    
    def parse(self, raw_content: str, file_type: str, file_name: str) -> Dict[str, Any]:
        """
        Parse certificate into canonical JSON format.
        
        Args:
            raw_content: Raw file content (string or bytes)
            file_type: Detected file type
            file_name: Original filename
            
        Returns:
            Parsed certificate dictionary
        """
        result = {
            'file_name': file_name,
            'pem': None,
            'subject': {},
            'issuer': {},
            'san': [],
            'not_before': None,
            'not_after': None,
            'validity_days': None,
            'pubkey_type': None,
            'pubkey_bits': None,
            'signature_algorithm': None,
            'raw_text': raw_content if isinstance(raw_content, str) else "",
            'handshake_info': {},
            'chain_length': 0,
            'parse_warnings': []
        }
        
        try:
            if file_type == "pem":
                result = self._parse_pem(raw_content, result)
            elif file_type == "der":
                result = self._parse_der(raw_content, result)
            elif file_type == "openssl_text":
                result = self._parse_openssl_text(raw_content, result)
            else:
                # Try all parsing methods
                result = self._parse_fallback(raw_content, result)
        
        except Exception as e:
            result['parse_warnings'].append(f"Parsing error: {str(e)}")
            logger.warning(f"Error parsing {file_name}: {e}")
        
        return result
    
    def _parse_pem(self, content: str, result: Dict) -> Dict:
        """Parse PEM format certificate."""
        if not CRYPTO_AVAILABLE:
            result['parse_warnings'].append("Cryptography library not available")
            return self._parse_openssl_text(content, result)
        
        # Extract all PEM blocks
        pem_blocks = re.findall(
            r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            content,
            re.DOTALL
        )
        
        if not pem_blocks:
            result['parse_warnings'].append("No PEM blocks found")
            return result
        
        result['chain_length'] = len(pem_blocks)
        
        # Parse first certificate (server cert)
        try:
            cert_pem = pem_blocks[0].encode('utf-8')
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            result['pem'] = pem_blocks[0]
            
            # Extract subject
            result['subject'] = self._extract_name(cert.subject)
            
            # Extract issuer
            result['issuer'] = self._extract_name(cert.issuer)
            
            # Extract SAN (Subject Alternative Names)
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                result['san'] = [str(name) for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            # Validity dates
            result['not_before'] = cert.not_valid_before_utc.isoformat()
            result['not_after'] = cert.not_valid_after_utc.isoformat()
            result['validity_days'] = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
            
            # Public key info
            pubkey = cert.public_key()
            result['pubkey_type'] = pubkey.__class__.__name__.replace('PublicKey', '')
            try:
                result['pubkey_bits'] = pubkey.key_size
            except AttributeError:
                pass
            
            # Signature algorithm
            result['signature_algorithm'] = cert.signature_algorithm_oid._name
            
        except Exception as e:
            result['parse_warnings'].append(f"PEM parsing error: {str(e)}")
            logger.warning(f"PEM parse error: {e}")
        
        # Also extract from text
        result = self._parse_openssl_text(content, result)
        
        return result
    
    def _parse_der(self, content: bytes, result: Dict) -> Dict:
        """Parse DER format certificate."""
        if not CRYPTO_AVAILABLE:
            result['parse_warnings'].append("Cryptography library not available for DER")
            return result
        
        try:
            cert = x509.load_der_x509_certificate(content, default_backend())
            
            # Convert to PEM for storage
            pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            result['pem'] = pem
            
            # Extract same fields as PEM
            result['subject'] = self._extract_name(cert.subject)
            result['issuer'] = self._extract_name(cert.issuer)
            
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                result['san'] = [str(name) for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            result['not_before'] = cert.not_valid_before_utc.isoformat()
            result['not_after'] = cert.not_valid_after_utc.isoformat()
            result['validity_days'] = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
            
            pubkey = cert.public_key()
            result['pubkey_type'] = pubkey.__class__.__name__.replace('PublicKey', '')
            try:
                result['pubkey_bits'] = pubkey.key_size
            except AttributeError:
                pass
            
            result['signature_algorithm'] = cert.signature_algorithm_oid._name
            result['chain_length'] = 1
            
        except Exception as e:
            result['parse_warnings'].append(f"DER parsing error: {str(e)}")
            logger.warning(f"DER parse error: {e}")
        
        return result
    
    def _parse_openssl_text(self, content: str, result: Dict) -> Dict:
        """Parse OpenSSL s_client text output."""
        # Count certificate chain entries
        chain_matches = re.findall(r'^\s*\d+\s+s:', content, re.MULTILINE)
        if chain_matches:
            result['chain_length'] = max(result['chain_length'], len(chain_matches))
        
        # Extract subject (multiple patterns)
        subject_match = re.search(r'subject[=:](.+?)(?:\n|issuer)', content, re.IGNORECASE)
        if subject_match:
            result['subject'].update(self._parse_dn_string(subject_match.group(1)))
        
        # Extract issuer
        issuer_match = re.search(r'issuer[=:](.+?)(?:\n|---)', content, re.IGNORECASE)
        if issuer_match:
            result['issuer'].update(self._parse_dn_string(issuer_match.group(1)))
        
        # Extract validity dates
        not_before_match = re.search(r'notBefore[=:](.+)', content, re.IGNORECASE)
        if not_before_match and not result['not_before']:
            result['not_before'] = not_before_match.group(1).strip()
        
        not_after_match = re.search(r'notAfter[=:](.+)', content, re.IGNORECASE)
        if not_after_match and not result['not_after']:
            result['not_after'] = not_after_match.group(1).strip()
        
        # Extract public key info
        pubkey_match = re.search(r'Public[- ]Key:\s*\((\d+)\s*bit\)', content, re.IGNORECASE)
        if pubkey_match and not result['pubkey_bits']:
            result['pubkey_bits'] = int(pubkey_match.group(1))
        
        pubkey_type_match = re.search(r'Public Key Algorithm:\s*(.+)', content, re.IGNORECASE)
        if pubkey_type_match and not result['pubkey_type']:
            result['pubkey_type'] = pubkey_type_match.group(1).strip()
        
        # Extract signature algorithm
        sig_algo_match = re.search(r'Signature Algorithm:\s*(.+)', content, re.IGNORECASE)
        if sig_algo_match and not result['signature_algorithm']:
            result['signature_algorithm'] = sig_algo_match.group(1).strip()
        
        # Extract handshake information
        cipher_match = re.search(r'Cipher\s*:\s*(.+)', content)
        if cipher_match:
            result['handshake_info']['cipher'] = cipher_match.group(1).strip()
        
        protocol_match = re.search(r'Protocol\s*:\s*(.+)', content)
        if protocol_match:
            result['handshake_info']['protocol'] = protocol_match.group(1).strip()
        
        # Extract URL if present (common in phishing captures)
        url_match = re.search(r'https?://[^\s\n]+', content)
        if url_match:
            result['handshake_info']['url'] = url_match.group(0)
        
        # Calculate validity_days if both dates present
        if result['not_before'] and result['not_after'] and not result['validity_days']:
            try:
                # Try multiple date formats
                for fmt in ['%b %d %H:%M:%S %Y %Z', '%Y-%m-%d %H:%M:%S']:
                    try:
                        nb = datetime.strptime(result['not_before'], fmt)
                        na = datetime.strptime(result['not_after'], fmt)
                        result['validity_days'] = (na - nb).days
                        break
                    except ValueError:
                        continue
            except Exception as e:
                result['parse_warnings'].append(f"Date parsing error: {str(e)}")
        
        return result
    
    def _parse_fallback(self, content, result: Dict) -> Dict:
        """Try all parsing methods as fallback."""
        if isinstance(content, bytes):
            # Try DER first
            result = self._parse_der(content, result)
            # Convert to text and try OpenSSL parsing
            try:
                text_content = content.decode('utf-8', errors='replace')
                result = self._parse_openssl_text(text_content, result)
            except:
                pass
        else:
            # Try PEM first
            if '-----BEGIN CERTIFICATE-----' in content:
                result = self._parse_pem(content, result)
            # Always try OpenSSL text parsing
            result = self._parse_openssl_text(content, result)
        
        return result
    
    def _extract_name(self, name) -> Dict[str, str]:
        """Extract fields from X509Name object."""
        fields = {}
        oid_map = {
            NameOID.COMMON_NAME: 'CN',
            NameOID.ORGANIZATION_NAME: 'O',
            NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
            NameOID.COUNTRY_NAME: 'C',
            NameOID.STATE_OR_PROVINCE_NAME: 'ST',
            NameOID.LOCALITY_NAME: 'L',
        }
        
        for oid, key in oid_map.items():
            try:
                attrs = name.get_attributes_for_oid(oid)
                if attrs:
                    fields[key] = attrs[0].value
            except:
                pass
        
        return fields
    
    def _parse_dn_string(self, dn_string: str) -> Dict[str, str]:
        """Parse Distinguished Name string like 'C=US, O=Company'."""
        fields = {}
        # Split by comma, but not within quotes
        parts = re.split(r',\s*(?![^"]*"(?:(?:[^"]*"){2})*[^"]*$)', dn_string)
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                fields[key.strip()] = value.strip()
        
        return fields


def parse_certificate(raw_content, file_type: str, file_name: str) -> Dict[str, Any]:
    """
    Convenience function to parse a single certificate.
    
    Args:
        raw_content: Raw certificate content
        file_type: File type (pem, der, openssl_text, etc.)
        file_name: Original filename
        
    Returns:
        Parsed certificate dictionary
    """
    parser = CertificateParser()
    return parser.parse(raw_content, file_type, file_name)