"""
LLM prompt templates for certificate classification.
Includes few-shot examples and structured output formatting.
"""

# Few-shot example: Benign certificate
EXAMPLE_BENIGN = {
    "input": {
        "file_name": "Google_Internet_Authority_G3",
        "subject": {
            "CN": "*.google.com",
            "O": "Google LLC",
            "C": "US"
        },
        "issuer": {
            "CN": "Google Internet Authority G3",
            "O": "Google Trust Services",
            "C": "US"
        },
        "san": ["*.google.com", "google.com", "*.youtube.com"],
        "not_before": "2024-09-15T00:00:00Z",
        "not_after": "2024-12-14T23:59:59Z",
        "validity_days": 90,
        "pubkey_type": "RSA",
        "pubkey_bits": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "chain_length": 3,
        "raw_text": "Certificate chain, Server certificate, ..."
    },
    "output": {
        "label": "benign",
        "confidence": 0.95,
        "reasoning": "This certificate shows strong indicators of legitimacy. The certificate is issued by Google Trust Services, a well-known and reputable Certificate Authority. The subject matches Google's legitimate domain (*.google.com) with appropriate wildcard usage. The validity period of 90 days is standard for modern certificates following industry best practices. Strong cryptography is used (RSA 2048-bit with SHA-256). The SAN entries include legitimate Google properties (google.com, youtube.com). The complete certificate chain (length 3) indicates proper CA hierarchy. No typosquatting, homoglyphs, or suspicious patterns detected.",
        "red_flags": [],
        "benign_signals": [
            "Reputable CA (Google Trust Services)",
            "Standard 90-day validity period",
            "Strong cryptography (RSA 2048 + SHA256)",
            "Legitimate domain matching organization",
            "Complete certificate chain",
            "Multiple legitimate SAN entries"
        ]
    }
}

# Few-shot example: Phishing certificate
EXAMPLE_PHISHING = {
    "input": {
        "file_name": "nazwaSSL_f134ad015f9b2b901c873e48c415207",
        "subject": {
            "CN": "ciekawetutaj.pl",
            "C": "PL"
        },
        "issuer": {
            "CN": "nazwaSSL",
            "O": "nazwa.pl sp. z o.o.",
            "OU": "http://nazwa.pl",
            "C": "PL"
        },
        "san": ["ciekawetutaj.pl", "www.ciekawetutaj.pl"],
        "not_before": "2019-08-06T11:42:27Z",
        "not_after": "2020-08-05T11:42:27Z",
        "validity_days": 364,
        "pubkey_type": "RSA",
        "pubkey_bits": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "chain_length": 4,
        "raw_text": "http://ciekawetutaj.pl/austria/artykul-porwanie/stream/weryfikacja/index.html\n----------END URL----------\nCONNECTED(00000003)\n--- Certificate chain..."
    },
    "output": {
        "label": "phishing",
        "confidence": 0.88,
        "reasoning": "This certificate exhibits multiple phishing indicators. Most critically, the raw text contains a suspicious URL path with social engineering keywords ('artykul-porwanie/stream/weryfikacja') designed to create urgency. The domain 'ciekawetutaj.pl' translates to 'interesting here' in Polish, a generic name often used in phishing. The URL structure suggests credential harvesting ('weryfikacja' means verification). While the certificate uses adequate cryptography (RSA 2048, SHA256) and has a reasonable validity period (364 days), these legitimate technical aspects are commonly exploited by phishers who obtain valid certificates for malicious domains. The issuer 'nazwaSSL' is a lesser-known Polish CA, making verification harder. The presence of the full URL in the certificate data is highly unusual and indicates this may be extracted from a phishing capture.",
        "red_flags": [
            "URL in certificate contains social engineering path (/artykul-porwanie/stream/weryfikacja/)",
            "Domain name is generic and not tied to legitimate business",
            "URL path includes 'weryfikacja' (verification) - common in phishing",
            "Path includes sensational keywords ('porwanie' = kidnapping)",
            "Lesser-known CA makes trust verification difficult",
            "URL structure typical of credential harvesting pages"
        ],
        "benign_signals": [
            "Valid certificate with proper chain",
            "Standard validity period (364 days)",
            "Strong cryptography (RSA 2048 + SHA256)"
        ]
    }
}


def get_classification_prompt(
    certificate_data: dict,
    include_context: bool = True
) -> str:
    """
    Generate classification prompt for LLM.
    
    Args:
        certificate_data: Parsed certificate dictionary
        include_context: Whether to include few-shot examples
        
    Returns:
        Formatted prompt string
    """
    import json
    
    system_prompt = """You are a cybersecurity expert specializing in TLS certificate analysis and phishing detection.

Your task is to analyze a TLS certificate and determine if it is BENIGN or PHISHING.

Consider these indicators:
- Subject/Issuer fields: Look for typosquatting, homoglyphs, brand impersonation
- Validity period: Very short (<7 days) or suspiciously long (>398 days)  
- SAN entries: Unusual patterns, mismatched domains
- Issuer reputation: Unknown or suspicious CAs
- Public key: Weak algorithms (RSA<2048, SHA1/MD5)
- Certificate chain: Missing or incomplete chains
- Contextual clues: URLs in raw text, handshake anomalies, suspicious paths

Respond ONLY with valid JSON in this exact format:
{
  "label": "phishing" or "benign",
  "confidence": 0.0 to 1.0,
  "reasoning": "Detailed explanation of your decision",
  "red_flags": ["list", "of", "specific", "concerns"],
  "benign_signals": ["list", "of", "normal", "indicators"]
}

DO NOT include any text before or after the JSON. DO NOT use markdown code fences."""

    few_shot_examples = ""
    if include_context:
        few_shot_examples = f"""

EXAMPLES:

Example 1 - Benign Certificate:
INPUT:
{json.dumps(EXAMPLE_BENIGN['input'], indent=2)}

OUTPUT:
{json.dumps(EXAMPLE_BENIGN['output'], indent=2)}

Example 2 - Phishing Certificate:
INPUT:
{json.dumps(EXAMPLE_PHISHING['input'], indent=2)}

OUTPUT:
{json.dumps(EXAMPLE_PHISHING['output'], indent=2)}
"""

    # Prepare certificate data (simplified for LLM)
    cert_summary = {
        'file_name': certificate_data.get('file_name'),
        'subject': certificate_data.get('subject', {}),
        'issuer': certificate_data.get('issuer', {}),
        'san': certificate_data.get('san', []),
        'not_before': certificate_data.get('not_before'),
        'not_after': certificate_data.get('not_after'),
        'validity_days': certificate_data.get('validity_days'),
        'pubkey_type': certificate_data.get('pubkey_type'),
        'pubkey_bits': certificate_data.get('pubkey_bits'),
        'signature_algorithm': certificate_data.get('signature_algorithm'),
        'chain_length': certificate_data.get('chain_length'),
        'raw_text': (certificate_data.get('raw_text', '') or '')[:2000]  # Limit to 2000 chars
    }
    
    prompt = f"""{system_prompt}{few_shot_examples}

Now analyze this certificate:
{json.dumps(cert_summary, indent=2)}

Respond with JSON only:"""

    return prompt


def get_batch_classification_prompt(certificates: list) -> str:
    """
    Generate prompt for batch classification (not currently used by Gemini).
    
    Args:
        certificates: List of parsed certificate dictionaries
        
    Returns:
        Formatted prompt for batch processing
    """
    # Note: Google Gemini doesn't support batch API yet
    # This is for potential future use or other LLM providers
    raise NotImplementedError("Batch classification not yet supported")


def parse_llm_response(response_text: str) -> dict:
    """
    Parse LLM response into structured format.
    Handles various response formats including markdown fences.
    
    Args:
        response_text: Raw LLM response
        
    Returns:
        Parsed response dictionary
    """
    import json
    import re
    
    # Default fallback structure
    default_response = {
        'label': 'unknown',
        'confidence': 0.5,
        'reasoning': 'Failed to parse LLM response',
        'red_flags': [],
        'benign_signals': [],
        'parse_error': True
    }
    
    try:
        # Try direct JSON parse
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass
    
    # Try to extract JSON from markdown code fences
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # Try to find JSON object in text
    json_match = re.search(r'\{[^{}]*"label"[^{}]*\}', response_text, re.DOTALL)
    if json_match:
        try:
            # Try to find the complete JSON object
            text = response_text[json_match.start():]
            # Count braces to find complete object
            brace_count = 0
            end_pos = 0
            for i, char in enumerate(text):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            if end_pos > 0:
                json_str = text[:end_pos]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
    
    # Last resort: try to extract fields manually
    try:
        result = default_response.copy()
        
        # Extract label
        label_match = re.search(r'"label"\s*:\s*"(phishing|benign)"', response_text, re.IGNORECASE)
        if label_match:
            result['label'] = label_match.group(1).lower()
        
        # Extract confidence
        conf_match = re.search(r'"confidence"\s*:\s*([0-9.]+)', response_text)
        if conf_match:
            result['confidence'] = float(conf_match.group(1))
        
        # Extract reasoning
        reasoning_match = re.search(r'"reasoning"\s*:\s*"([^"]+)"', response_text)
        if reasoning_match:
            result['reasoning'] = reasoning_match.group(1)
        
        result['parse_error'] = False
        return result
    except Exception:
        pass
    
    return default_response