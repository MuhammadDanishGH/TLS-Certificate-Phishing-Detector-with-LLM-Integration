"""
Google Gemini API client for certificate classification.
"""
import os
import time
import logging
from typing import Dict, Any, Optional
import json

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    logging.warning("google-generativeai not installed, LLM features disabled")

from .prompts import get_classification_prompt, parse_llm_response

logger = logging.getLogger(__name__)


class GeminiClient:
    """Client for Google Gemini API."""
    
    def __init__(self, config=None):
        """
        Initialize Gemini client.
        
        Args:
            config: Configuration object (optional)
        """
        if not GENAI_AVAILABLE:
            raise ImportError(
                "google-generativeai not installed. "
                "Install with: pip install google-generativeai"
            )
        
        from ..config import get_config
        self.config = config or get_config()
        
        # Get API key
        api_key = self.config.gemini_api_key
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY not set. "
                "Set via environment variable: export GEMINI_API_KEY='your-key'"
            )
        
        # Configure API
        genai.configure(api_key=api_key)
        
        # Initialize model
        self.model = genai.GenerativeModel(self.config.llm_model)
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 60.0 / self.config.gemini_rpm_limit
        
        # Cache
        self.cache = {} if self.config.llm_cache_enabled else None
        
        logger.info(f"Initialized Gemini client with model: {self.config.llm_model}")
    
    def classify_certificate(
        self,
        parsed_cert: Dict[str, Any],
        include_context: bool = True
    ) -> Dict[str, Any]:
        """
        Classify certificate using Gemini.
        
        Args:
            parsed_cert: Parsed certificate dictionary
            include_context: Include few-shot examples in prompt
            
        Returns:
            Classification result with label, confidence, reasoning
        """
        # Check cache
        if self.cache is not None:
            cache_key = self._get_cache_key(parsed_cert)
            if cache_key in self.cache:
                logger.debug(f"Cache hit for {parsed_cert.get('file_name')}")
                return self.cache[cache_key]
        
        # Generate prompt
        prompt = get_classification_prompt(parsed_cert, include_context)
        
        # Rate limiting
        self._rate_limit()
        
        # Make API call with retry
        result = None
        for attempt in range(self.config.llm_max_retries):
            try:
                result = self._call_api(prompt)
                break
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt < self.config.llm_max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"All retry attempts failed for {parsed_cert.get('file_name')}")
                    result = {
                        'label': 'unknown',
                        'confidence': 0.5,
                        'reasoning': f'API error after {self.config.llm_max_retries} attempts',
                        'red_flags': [],
                        'benign_signals': [],
                        'error': str(e)
                    }
        
        # Cache result
        if self.cache is not None and result:
            cache_key = self._get_cache_key(parsed_cert)
            self.cache[cache_key] = result
        
        return result
    
    def _call_api(self, prompt: str) -> Dict[str, Any]:
        """
        Make API call to Gemini.
        
        Args:
            prompt: Formatted prompt
            
        Returns:
            Parsed response
        """
        # Configure generation parameters
        generation_config = genai.types.GenerationConfig(
            temperature=self.config.llm_temperature,
            max_output_tokens=1024,
        )
        
        # Generate response
        response = self.model.generate_content(
            prompt,
            generation_config=generation_config,
            request_options={'timeout': self.config.llm_timeout}
        )
        
        # Extract text from response
        response_text = response.text
        
        # Parse response
        result = parse_llm_response(response_text)
        
        # Add metadata
        result['model'] = self.config.llm_model
        result['raw_response'] = response_text
        
        return result
    
    def _rate_limit(self):
        """Enforce rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _get_cache_key(self, parsed_cert: Dict) -> str:
        """Generate cache key from certificate."""
        # Use hash of critical fields
        import hashlib
        key_data = json.dumps({
            'subject': parsed_cert.get('subject'),
            'issuer': parsed_cert.get('issuer'),
            'not_before': parsed_cert.get('not_before'),
            'not_after': parsed_cert.get('not_after'),
        }, sort_keys=True)
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def clear_cache(self):
        """Clear the response cache."""
        if self.cache is not None:
            self.cache.clear()
            logger.info("Cache cleared")
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        if self.cache is None:
            return {'enabled': False}
        return {
            'enabled': True,
            'size': len(self.cache)
        }


def classify_certificate_with_gemini(
    parsed_cert: Dict[str, Any],
    config=None
) -> Dict[str, Any]:
    """
    Convenience function to classify a single certificate.
    
    Args:
        parsed_cert: Parsed certificate dictionary
        config: Configuration (optional)
        
    Returns:
        Classification result
    """
    if not GENAI_AVAILABLE:
        logger.warning("Gemini not available, returning neutral result")
        return {
            'label': 'unknown',
            'confidence': 0.5,
            'reasoning': 'Gemini API not available',
            'red_flags': [],
            'benign_signals': []
        }
    
    try:
        client = GeminiClient(config)
        return client.classify_certificate(parsed_cert)
    except Exception as e:
        logger.error(f"Gemini classification failed: {e}")
        return {
            'label': 'unknown',
            'confidence': 0.5,
            'reasoning': f'Classification error: {str(e)}',
            'red_flags': [],
            'benign_signals': [],
            'error': str(e)
        }