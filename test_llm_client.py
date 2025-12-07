"""
Tests for LLM client module.
"""
import pytest
from unittest.mock import Mock, patch
from src.llm.prompts import get_classification_prompt, parse_llm_response


class TestPrompts:
    """Tests for prompt generation."""
    
    def test_get_classification_prompt(self):
        """Test prompt generation."""
        cert_data = {
            'file_name': 'test.pem',
            'subject': {'CN': 'example.com'},
            'issuer': {'CN': 'CA'},
            'validity_days': 90
        }
        
        prompt = get_classification_prompt(cert_data, include_context=True)
        
        assert 'phishing' in prompt.lower()
        assert 'benign' in prompt.lower()
        assert 'example.com' in prompt
    
    def test_parse_valid_json_response(self):
        """Test parsing valid JSON response."""
        response = """{
            "label": "phishing",
            "confidence": 0.85,
            "reasoning": "Suspicious domain",
            "red_flags": ["typosquatting"],
            "benign_signals": []
        }"""
        
        result = parse_llm_response(response)
        
        assert result['label'] == 'phishing'
        assert result['confidence'] == 0.85
    
    def test_parse_json_with_markdown(self):
        """Test parsing JSON wrapped in markdown."""
        response = """Here's the analysis:
```json
{
    "label": "benign",
    "confidence": 0.9,
    "reasoning": "Legitimate certificate",
    "red_flags": [],
    "benign_signals": ["reputable CA"]
}
```
"""
        
        result = parse_llm_response(response)
        
        assert result['label'] == 'benign'
        assert 'parse_error' not in result or not result['parse_error']
    
    def test_parse_invalid_response(self):
        """Test parsing invalid response returns default."""
        response = "This is not JSON at all"
        
        result = parse_llm_response(response)
        
        assert result['label'] == 'unknown'
        assert result.get('parse_error') == True


@pytest.mark.skipif(
    True,  # Skip by default to avoid API calls
    reason="Requires Gemini API key and network"
)
class TestGeminiClient:
    """Tests for GeminiClient (requires API key)."""
    
    def test_gemini_classification(self):
        """Test real Gemini API call."""
        from src.llm.gemini_client import GeminiClient
        from src.config import Config
        
        # This test requires GEMINI_API_KEY to be set
        config = Config()
        client = GeminiClient(config)
        
        cert_data = {
            'file_name': 'test.pem',
            'subject': {'CN': 'example.com', 'O': 'Example Corp'},
            'issuer': {'CN': 'Let\'s Encrypt'},
            'validity_days': 90,
            'pubkey_bits': 2048,
            'raw_text': 'Certificate data...'
        }
        
        result = client.classify_certificate(cert_data)
        
        assert 'label' in result
        assert result['label'] in ['phishing', 'benign', 'unknown']
