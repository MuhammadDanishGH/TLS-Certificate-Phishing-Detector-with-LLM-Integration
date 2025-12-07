"""
Rule-based phishing detection system.
"""
from typing import Dict, List, Tuple, Any
import logging

logger = logging.getLogger(__name__)


class RuleEngine:
    """Rule-based certificate phishing detector."""
    
    def __init__(self, config=None):
        """
        Initialize rule engine.
        
        Args:
            config: Configuration object (optional)
        """
        from .config import get_config
        self.config = config or get_config()
    
    def evaluate(self, parsed_cert: Dict, features: Dict) -> Dict[str, Any]:
        """
        Evaluate certificate against all rules.
        
        Args:
            parsed_cert: Parsed certificate data
            features: Extracted features
            
        Returns:
            Dict with score, triggered_rules, and reasons
        """
        triggered_rules = []
        reasons = []
        rule_scores = []
        
        # Rule 1: Very short validity period
        if 0 < features.get('validity_days', 0) < self.config.min_validity_days:
            triggered_rules.append('short_validity_period')
            reasons.append(
                f"Validity period is only {features['validity_days']} days "
                f"(suspicious, normal is 90-398 days)"
            )
            rule_scores.append(0.8)
        
        # Rule 2: Excessively long validity period
        if features.get('validity_days', 0) > self.config.max_validity_days:
            triggered_rules.append('long_validity_period')
            reasons.append(
                f"Validity period is {features['validity_days']} days "
                f"(exceeds CA/Browser Forum baseline of 398 days)"
            )
            rule_scores.append(0.6)
        
        # Rule 3: Weak public key
        if 0 < features.get('pubkey_bits', 0) < self.config.min_pubkey_bits:
            triggered_rules.append('weak_public_key')
            reasons.append(
                f"Weak public key: {features['pubkey_bits']} bits "
                f"(minimum should be {self.config.min_pubkey_bits})"
            )
            rule_scores.append(0.9)
        
        # Rule 4: Weak signature algorithm
        if features.get('sig_is_sha1') or features.get('sig_is_md5'):
            algo = 'SHA1' if features.get('sig_is_sha1') else 'MD5'
            triggered_rules.append('weak_signature_algorithm')
            reasons.append(
                f"Weak signature algorithm: {algo} "
                f"(deprecated, should use SHA-256 or stronger)"
            )
            rule_scores.append(0.85)
        
        # Rule 5: Punycode domain (IDN homograph attack)
        if features.get('subject_has_punycode') or features.get('san_has_punycode'):
            triggered_rules.append('punycode_domain')
            reasons.append(
                "Domain uses Punycode (xn--), potential homograph attack"
            )
            rule_scores.append(0.7)
        
        # Rule 6: Detected homoglyphs
        if features.get('subject_has_homoglyphs'):
            triggered_rules.append('homoglyph_characters')
            reasons.append(
                "Subject contains homoglyph characters (confusable Unicode)"
            )
            rule_scores.append(0.75)
        
        # Rule 7: Brand typosquatting
        if features.get('is_brand_typosquatting'):
            triggered_rules.append('brand_typosquatting')
            max_similarity = features.get('max_brand_similarity', 0)
            reasons.append(
                f"Domain appears to typosquat a major brand "
                f"(similarity: {max_similarity:.2f})"
            )
            rule_scores.append(0.85)
        
        # Rule 8: Self-signed certificate
        if features.get('is_self_signed'):
            triggered_rules.append('self_signed')
            reasons.append(
                "Certificate is self-signed (not from trusted CA)"
            )
            rule_scores.append(0.6)
        
        # Rule 9: Very rare issuer + short validity
        if (features.get('issuer_frequency', 1.0) < 0.001 and 
            features.get('validity_days', 0) < 90):
            triggered_rules.append('rare_issuer_short_validity')
            reasons.append(
                "Rare issuer combined with short validity period"
            )
            rule_scores.append(0.7)
        
        # Rule 10: Suspicious URL in certificate
        if features.get('has_url'):
            triggered_rules.append('url_in_certificate')
            reasons.append(
                "Certificate contains URL (unusual, may be from phishing capture)"
            )
            rule_scores.append(0.5)
        
        # Rule 11: Suspicious keywords
        if features.get('suspicious_keyword_count', 0) >= 2:
            triggered_rules.append('suspicious_keywords')
            count = features['suspicious_keyword_count']
            reasons.append(
                f"Contains {count} suspicious keywords (verify, account, etc.)"
            )
            rule_scores.append(0.6)
        
        # Rule 12: Missing certificate chain
        if features.get('chain_length', 0) == 0:
            triggered_rules.append('missing_chain')
            reasons.append(
                "Certificate chain is missing or incomplete"
            )
            rule_scores.append(0.4)
        
        # Rule 13: No SAN entries (unusual for modern certificates)
        if not features.get('has_san'):
            triggered_rules.append('no_san')
            reasons.append(
                "No Subject Alternative Names (unusual for modern certificates)"
            )
            rule_scores.append(0.3)
        
        # Calculate overall score
        # Average of triggered rule scores, or 0 if no rules triggered
        if rule_scores:
            score = sum(rule_scores) / len(rule_scores)
            # Boost score if many rules triggered
            if len(rule_scores) >= 3:
                score = min(1.0, score * 1.2)
        else:
            score = 0.0
        
        return {
            'score': score,
            'triggered_rules': triggered_rules,
            'reasons': reasons,
            'rule_count': len(triggered_rules)
        }
    
    def get_rule_descriptions(self) -> Dict[str, str]:
        """Get human-readable descriptions of all rules."""
        return {
            'short_validity_period': 'Validity period is suspiciously short (<7 days)',
            'long_validity_period': 'Validity period exceeds CA/B Forum limit (>398 days)',
            'weak_public_key': 'Public key strength below minimum (2048 bits for RSA)',
            'weak_signature_algorithm': 'Uses deprecated signature algorithm (SHA-1, MD5)',
            'punycode_domain': 'Domain uses Punycode (potential homograph attack)',
            'homoglyph_characters': 'Contains confusable Unicode characters',
            'brand_typosquatting': 'Domain name similar to major brand (typosquatting)',
            'self_signed': 'Certificate is self-signed',
            'rare_issuer_short_validity': 'Rare CA with short validity (suspicious combination)',
            'url_in_certificate': 'Contains URL (may be from phishing capture)',
            'suspicious_keywords': 'Contains multiple suspicious keywords',
            'missing_chain': 'Certificate chain missing or incomplete',
            'no_san': 'No Subject Alternative Names (unusual for modern certs)',
        }


def evaluate_certificate(
    parsed_cert: Dict[str, Any],
    features: Dict[str, Any],
    config=None
) -> Dict[str, Any]:
    """
    Convenience function to evaluate a single certificate.
    
    Args:
        parsed_cert: Parsed certificate
        features: Extracted features
        config: Configuration (optional)
        
    Returns:
        Rule evaluation results
    """
    engine = RuleEngine(config)
    return engine.evaluate(parsed_cert, features)