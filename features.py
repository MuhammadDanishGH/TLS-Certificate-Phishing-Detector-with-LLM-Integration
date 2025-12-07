"""
Feature extraction from parsed certificates.
Includes lexical, structural, statistical, and semantic features.
"""
import re
import math
from typing import Dict, List, Any, Optional
from collections import Counter
import logging

try:
    import Levenshtein
    LEVENSHTEIN_AVAILABLE = True
except ImportError:
    LEVENSHTEIN_AVAILABLE = False
    logging.warning("python-Levenshtein not available, distance features disabled")

try:
    from unidecode import unidecode
    UNIDECODE_AVAILABLE = True
except ImportError:
    UNIDECODE_AVAILABLE = False

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from parsed certificates."""
    
    # Major brands for typosquatting detection
    MAJOR_BRANDS = [
        'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix',
        'twitter', 'instagram', 'linkedin', 'yahoo', 'ebay', 'alibaba', 'baidu',
        'github', 'stackoverflow', 'reddit', 'wikipedia', 'cloudflare', 'adobe',
        'salesforce', 'dropbox', 'spotify', 'zoom', 'slack', 'discord'
    ]
    
    # Known reputable CAs
    REPUTABLE_CAS = [
        'digicert', 'lets encrypt', 'comodo', 'godaddy', 'globalsign', 'sectigo',
        'entrust', 'thawte', 'geotrust', 'rapidssl', 'symantec', 'verisign',
        'google trust services', 'amazon trust services', 'microsoft', 'apple'
    ]
    
    def __init__(self):
        self.issuer_frequencies = {}
    
    def extract_features(self, parsed_cert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all features from parsed certificate.
        
        Args:
            parsed_cert: Parsed certificate dictionary
            
        Returns:
            Feature dictionary
        """
        features = {}
        
        # Structural features
        features.update(self._extract_structural_features(parsed_cert))
        
        # Lexical features
        features.update(self._extract_lexical_features(parsed_cert))
        
        # Subject/Issuer features
        features.update(self._extract_identity_features(parsed_cert))
        
        # Statistical features
        features.update(self._extract_statistical_features(parsed_cert))
        
        # Temporal features
        features.update(self._extract_temporal_features(parsed_cert))
        
        return features
    
    def _extract_structural_features(self, cert: Dict) -> Dict:
        """Extract structural certificate features."""
        features = {}
        
        features['validity_days'] = cert.get('validity_days', 0) or 0
        features['pubkey_bits'] = cert.get('pubkey_bits', 0) or 0
        features['chain_length'] = cert.get('chain_length', 0) or 0
        features['san_count'] = len(cert.get('san', []))
        features['has_san'] = int(len(cert.get('san', [])) > 0)
        
        # Parse warnings indicate parsing issues
        features['parse_warning_count'] = len(cert.get('parse_warnings', []))
        features['has_parse_warnings'] = int(len(cert.get('parse_warnings', [])) > 0)
        
        # Public key type (encoded as features)
        pubkey_type = (cert.get('pubkey_type') or '').lower()
        features['pubkey_is_rsa'] = int('rsa' in pubkey_type)
        features['pubkey_is_ecc'] = int('ecc' in pubkey_type or 'ec' in pubkey_type)
        
        # Signature algorithm
        sig_algo = (cert.get('signature_algorithm') or '').lower()
        features['sig_is_sha256'] = int('sha256' in sig_algo)
        features['sig_is_sha1'] = int('sha1' in sig_algo)
        features['sig_is_md5'] = int('md5' in sig_algo)
        
        return features
    
    def _extract_lexical_features(self, cert: Dict) -> Dict:
        """Extract lexical features from certificate text."""
        features = {}
        
        raw_text = cert.get('raw_text', '')
        if not raw_text:
            return features
        
        features['text_length'] = len(raw_text)
        
        # Character statistics
        features['digit_count'] = sum(c.isdigit() for c in raw_text)
        features['digit_ratio'] = features['digit_count'] / max(len(raw_text), 1)
        
        features['upper_count'] = sum(c.isupper() for c in raw_text)
        features['upper_ratio'] = features['upper_count'] / max(len(raw_text), 1)
        
        features['special_char_count'] = sum(not c.isalnum() and not c.isspace() for c in raw_text)
        features['special_char_ratio'] = features['special_char_count'] / max(len(raw_text), 1)
        
        # Entropy (measure of randomness)
        features['entropy'] = self._calculate_entropy(raw_text)
        
        # Non-ASCII characters (potential internationalized domain names)
        features['non_ascii_count'] = sum(ord(c) > 127 for c in raw_text)
        features['non_ascii_ratio'] = features['non_ascii_count'] / max(len(raw_text), 1)
        
        return features
    
    def _extract_identity_features(self, cert: Dict) -> Dict:
        """Extract features from subject and issuer."""
        features = {}
        
        subject = cert.get('subject', {})
        issuer = cert.get('issuer', {})
        
        # Subject CN analysis
        cn = subject.get('CN', '')
        features['subject_cn_length'] = len(cn)
        features['subject_cn_has_wildcard'] = int('*' in cn)
        features['subject_cn_digit_ratio'] = sum(c.isdigit() for c in cn) / max(len(cn), 1)
        
        # Punycode detection (xn--)
        features['subject_has_punycode'] = int('xn--' in cn.lower())
        san_list = cert.get('san', [])
        features['san_has_punycode'] = int(any('xn--' in str(s).lower() for s in san_list))
        
        # Homoglyph detection (suspicious Unicode characters)
        features['subject_has_homoglyphs'] = int(self._detect_homoglyphs(cn))
        
        # Brand similarity (potential typosquatting)
        brand_scores = []
        cn_lower = cn.lower()
        for brand in self.MAJOR_BRANDS:
            if brand in cn_lower:
                features[f'brand_exact_{brand}'] = 1
                brand_scores.append(1.0)
            elif LEVENSHTEIN_AVAILABLE:
                # Levenshtein distance
                dist = Levenshtein.distance(cn_lower, brand)
                similarity = 1 - (dist / max(len(cn_lower), len(brand)))
                if similarity > 0.7:  # Potential typosquatting
                    brand_scores.append(similarity)
        
        features['max_brand_similarity'] = max(brand_scores) if brand_scores else 0
        features['is_brand_typosquatting'] = int(len(brand_scores) > 0 and max(brand_scores) > 0.7 and max(brand_scores) < 1.0)
        
        # Issuer reputation
        issuer_name = ' '.join(issuer.values()).lower()
        features['issuer_is_reputable'] = int(any(ca in issuer_name for ca in self.REPUTABLE_CAS))
        
        # Self-signed detection (subject == issuer)
        features['is_self_signed'] = int(subject == issuer and len(subject) > 0)
        
        return features
    
    def _extract_statistical_features(self, cert: Dict) -> Dict:
        """Extract statistical features from text."""
        features = {}
        
        raw_text = cert.get('raw_text', '')
        if not raw_text:
            return features
        
        # URL detection
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, raw_text)
        features['url_count'] = len(urls)
        features['has_url'] = int(len(urls) > 0)
        
        # Suspicious keywords (common in phishing)
        suspicious_keywords = [
            'verify', 'verification', 'confirm', 'account', 'suspend', 'update',
            'secure', 'alert', 'urgent', 'locked', 'limited', 'expired'
        ]
        text_lower = raw_text.lower()
        features['suspicious_keyword_count'] = sum(1 for kw in suspicious_keywords if kw in text_lower)
        
        # IP address detection
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        features['ip_count'] = len(re.findall(ip_pattern, raw_text))
        
        return features
    
    def _extract_temporal_features(self, cert: Dict) -> Dict:
        """Extract temporal features."""
        features = {}
        
        # Validity period categorization
        validity = cert.get('validity_days', 0) or 0
        features['validity_very_short'] = int(0 < validity < 7)
        features['validity_short'] = int(7 <= validity < 30)
        features['validity_medium'] = int(30 <= validity < 90)
        features['validity_standard'] = int(90 <= validity <= 398)
        features['validity_long'] = int(validity > 398)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _detect_homoglyphs(self, text: str) -> bool:
        """Detect potential homoglyph attacks."""
        # Common homoglyph characters
        homoglyphs = [
            'а', 'е', 'о', 'р', 'с', 'у', 'х',  # Cyrillic
            'ο', 'а', 'е', 'і',  # Greek
            '0', '1', 'l', 'O',  # Confusables
        ]
        
        # Check for suspicious Unicode ranges
        for char in text:
            code = ord(char)
            # Cyrillic: 0x0400-0x04FF
            # Greek: 0x0370-0x03FF
            if (0x0400 <= code <= 0x04FF) or (0x0370 <= code <= 0x03FF):
                return True
        
        return False
    
    def fit_issuer_frequencies(self, parsed_certs: List[Dict]):
        """
        Build issuer frequency map from training data.
        
        Args:
            parsed_certs: List of parsed certificates
        """
        issuer_counter = Counter()
        
        for cert in parsed_certs:
            issuer = cert.get('issuer', {})
            issuer_key = tuple(sorted(issuer.items()))
            issuer_counter[issuer_key] += 1
        
        # Normalize to frequencies
        total = sum(issuer_counter.values())
        self.issuer_frequencies = {
            k: v / total for k, v in issuer_counter.items()
        }
        
        logger.info(f"Built issuer frequency map with {len(self.issuer_frequencies)} unique issuers")
    
    def get_issuer_frequency(self, cert: Dict) -> float:
        """Get frequency score for certificate issuer."""
        issuer = cert.get('issuer', {})
        issuer_key = tuple(sorted(issuer.items()))
        return self.issuer_frequencies.get(issuer_key, 0.0)


def extract_all_features(
    parsed_certs: List[Dict[str, Any]],
    fit_issuer_freq: bool = True
) -> List[Dict[str, Any]]:
    """
    Extract features from multiple certificates.
    
    Args:
        parsed_certs: List of parsed certificates
        fit_issuer_freq: Whether to fit issuer frequencies
        
    Returns:
        List of feature dictionaries
    """
    extractor = FeatureExtractor()
    
    if fit_issuer_freq:
        extractor.fit_issuer_frequencies(parsed_certs)
    
    features_list = []
    for cert in parsed_certs:
        features = extractor.extract_features(cert)
        features['issuer_frequency'] = extractor.get_issuer_frequency(cert)
        features_list.append(features)
    
    return features_list