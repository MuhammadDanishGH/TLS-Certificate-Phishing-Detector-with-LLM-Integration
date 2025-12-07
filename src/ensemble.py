"""
Ensemble methods for combining rule-based, ML, and LLM predictions.
"""
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class EnsembleDetector:
    """Ensemble certificate phishing detector."""
    
    def __init__(self, config=None):
        """
        Initialize ensemble detector.
        
        Args:
            config: Configuration object
        """
        from .config import get_config
        self.config = config or get_config()
        self.weights = self.config.ensemble_weights
    
    def combine_scores(
        self,
        rule_result: Dict[str, Any],
        ml_result: Optional[Dict[str, Any]] = None,
        llm_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Combine scores from multiple detection methods.
        
        Args:
            rule_result: Result from rule-based detection
            ml_result: Result from ML model (optional)
            llm_result: Result from LLM (optional)
            
        Returns:
            Combined result with final score and label
        """
        # Extract scores
        rule_score = rule_result.get('score', 0.0)
        ml_score = ml_result.get('score', 0.5) if ml_result else 0.5
        llm_score = self._extract_llm_score(llm_result) if llm_result else 0.5
        
        # Calculate weighted score
        scores = {
            'rules': rule_score,
            'ml': ml_score,
            'llm': llm_score
        }
        
        final_score = (
            self.weights['rules'] * rule_score +
            self.weights['ml'] * ml_score +
            self.weights['llm'] * llm_score
        )
        
        # Determine label
        label = 'phishing' if final_score >= self.config.phishing_threshold else 'benign'
        
        # Determine confidence level
        if final_score >= self.config.high_confidence_threshold:
            confidence = 'high'
        elif final_score <= self.config.low_confidence_threshold:
            confidence = 'high'  # High confidence in benign
        else:
            confidence = 'medium'
        
        # Combine reasons
        combined_reasons = self._combine_reasons(rule_result, ml_result, llm_result)
        
        result = {
            'label': label,
            'final_score': final_score,
            'confidence': confidence,
            'method_scores': {
                'rules': {
                    'score': rule_score,
                    'triggered_rules': rule_result.get('triggered_rules', []),
                    'reasons': rule_result.get('reasons', [])
                }
            },
            'combined_reasons': combined_reasons
        }
        
        if ml_result:
            result['method_scores']['ml'] = {
                'score': ml_score,
                'model': ml_result.get('model', 'unknown')
            }
        
        if llm_result:
            result['method_scores']['llm'] = {
                'score': llm_score,
                'confidence': llm_result.get('confidence', 0.5),
                'model': llm_result.get('model', 'unknown'),
                'reasoning': llm_result.get('reasoning', ''),
                'red_flags': llm_result.get('red_flags', []),
                'benign_signals': llm_result.get('benign_signals', [])
            }
        
        return result
    
    def _extract_llm_score(self, llm_result: Dict) -> float:
        """Extract score from LLM result."""
        label = llm_result.get('label', 'unknown')
        confidence = llm_result.get('confidence', 0.5)
        
        if label == 'phishing':
            return confidence
        elif label == 'benign':
            return 1.0 - confidence
        else:
            return 0.5
    
    def _combine_reasons(
        self,
        rule_result: Dict,
        ml_result: Optional[Dict],
        llm_result: Optional[Dict]
    ) -> List[str]:
        """Combine reasons from all methods."""
        reasons = []
        
        # Add rule-based reasons
        for rule_name in rule_result.get('triggered_rules', []):
            reasons.append(f"[RULE] {rule_name}")
        
        # Add top rule reason with detail
        if rule_result.get('reasons'):
            reasons.append(f"[RULE] {rule_result['reasons'][0]}")
        
        # Add ML insight if available
        if ml_result and ml_result.get('score', 0) > 0.7:
            reasons.append(f"[ML] High ML model confidence: {ml_result['score']:.2f}")
        
        # Add LLM reasoning
        if llm_result:
            llm_label = llm_result.get('label', 'unknown')
            llm_conf = llm_result.get('confidence', 0)
            
            if llm_label == 'phishing':
                reasons.append(f"[LLM] Classified as phishing (confidence: {llm_conf:.2f})")
                # Add top red flags
                for flag in llm_result.get('red_flags', [])[:3]:
                    reasons.append(f"[LLM] {flag}")
            elif llm_label == 'benign':
                reasons.append(f"[LLM] Classified as benign (confidence: {llm_conf:.2f})")
        
        return reasons[:10]  # Limit to top 10 reasons
    
    def process_certificate(
        self,
        parsed_cert: Dict[str, Any],
        features: Dict[str, Any],
        rule_engine,
        ml_model=None,
        llm_client=None
    ) -> Dict[str, Any]:
        """
        Process a single certificate through full pipeline.
        
        Args:
            parsed_cert: Parsed certificate
            features: Extracted features
            rule_engine: Rule engine instance
            ml_model: ML model instance (optional)
            llm_client: LLM client instance (optional)
            
        Returns:
            Complete detection result
        """
        # Rule-based detection
        rule_result = rule_engine.evaluate(parsed_cert, features)
        
        # ML detection
        ml_result = None
        if ml_model:
            try:
                _, scores = ml_model.predict([parsed_cert], [features])
                ml_result = {'score': scores[0], 'model': ml_model.model_type}
            except Exception as e:
                logger.warning(f"ML prediction failed: {e}")
        
        # LLM detection
        llm_result = None
        if llm_client and self.config.use_llm:
            try:
                llm_result = llm_client.classify_certificate(parsed_cert)
            except Exception as e:
                logger.warning(f"LLM classification failed: {e}")
        
        # Combine results
        ensemble_result = self.combine_scores(rule_result, ml_result, llm_result)
        
        # Add certificate metadata
        ensemble_result['file_name'] = parsed_cert.get('file_name')
        ensemble_result['certificate_details'] = {
            'subject_cn': parsed_cert.get('subject', {}).get('CN', ''),
            'issuer': parsed_cert.get('issuer', {}).get('CN', ''),
            'validity_days': parsed_cert.get('validity_days'),
            'san_entries': parsed_cert.get('san', [])
        }
        
        return ensemble_result


def detect_certificate(
    parsed_cert: Dict[str, Any],
    features: Dict[str, Any],
    config=None
) -> Dict[str, Any]:
    """
    Convenience function for full certificate detection.
    
    Args:
        parsed_cert: Parsed certificate
        features: Extracted features
        config: Configuration (optional)
        
    Returns:
        Detection result
    """
    from .rules import RuleEngine
    from .llm.gemini_client import GeminiClient
    
    ensemble = EnsembleDetector(config)
    rule_engine = RuleEngine(config)
    
    # Initialize LLM if available and enabled
    llm_client = None
    if config and config.use_llm:
        try:
            llm_client = GeminiClient(config)
        except Exception as e:
            logger.warning(f"Could not initialize LLM client: {e}")
    
    return ensemble.process_certificate(
        parsed_cert,
        features,
        rule_engine,
        ml_model=None,  # ML model not provided in simple function
        llm_client=llm_client
    )
