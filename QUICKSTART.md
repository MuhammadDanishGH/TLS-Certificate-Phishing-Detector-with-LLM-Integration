# Quick Start Guide

Get started with the TLS Certificate Phishing Detector in 5 minutes.

## Prerequisites

- Python 3.8 or higher
- Google Gemini API key (free at https://makersuite.google.com/app/apikey)

## Installation

### 1. Set up virtual environment

```bash
# Create venv
python3 -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Set API key

```bash
# Linux/macOS
export GEMINI_API_KEY="your-api-key-here"

# Windows PowerShell
$env:GEMINI_API_KEY="your-api-key-here"
```

## Quick Demo

### Analyze a single certificate

```bash
python -m src.cli infer \
    --file sample_data/phishing/nazwaSSL_f134ad015f9b2b901c873e48c415207
```

Output:
```json
{
  "label": "phishing",
  "final_score": 0.87,
  "confidence": "high",
  "combined_reasons": [
    "[RULE] url_in_certificate",
    "[RULE] suspicious_keywords",
    "[LLM] Classified as phishing (confidence: 0.88)"
  ]
}
```

### Generate additional samples

```bash
bash scripts/download_sample.sh
```

### Process a directory of certificates

```bash
# Preprocess (parse + extract features)
python -m src.cli preprocess \
    --input sample_data/ \
    --output parsed_data/ \
    --sample-size 10

# Train a model
python -m src.cli train \
    --input parsed_data/ \
    --output models/baseline

# Evaluate
python -m src.cli evaluate \
    --model models/baseline \
    --test-data parsed_data/ \
    --output artifacts/
```

## Interactive Demo

Launch Jupyter notebook:

```bash
pip install jupyter
jupyter notebook notebooks/demo_infer.ipynb
```

## Common Commands

### Preprocess certificates
```bash
python -m src.cli preprocess \
    --input data/raw/ \
    --output data/parsed/ \
    --workers 4
```

### Train model
```bash
python -m src.cli train \
    --input data/parsed/ \
    --output models/my_model \
    --model-type logistic
```

### Batch inference
```bash
python -m src.cli batch-infer \
    --input-dir data/unknown/ \
    --output results.jsonl \
    --threshold 0.7
```

## Configuration

Edit `src/config.py` or create a YAML config file:

```yaml
# config.yaml
llm_model: "gemini-1.5-flash"
use_llm: true
ensemble_weights:
  rules: 0.25
  ml: 0.35
  llm: 0.40
phishing_threshold: 0.5
```

Then use it:
```bash
python -m src.cli --config config.yaml infer --file cert.pem
```

## Troubleshooting

### API Key Issues
```bash
# Verify key is set
echo $GEMINI_API_KEY

# Test connection
python -c "import google.generativeai as genai; genai.configure(api_key='$GEMINI_API_KEY'); print('OK')"
```

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Certificate Parsing Errors
```bash
# Check file type
file path/to/cert

# View raw content
head -n 50 path/to/cert
```

## Next Steps

1. **Read full documentation**: See [README.md](README.md)
2. **Understand prompts**: See [prompts.md](prompts.md)
3. **Check roadmap**: See [TODO.md](TODO.md)
4. **Run tests**: `pytest tests/ -v`

## Getting Help

- Check existing issues in repository
- Review documentation files
- Ensure all dependencies are installed
- Verify API key is valid and set

---

**Tip**: Start with sample data and gradually add your own certificates for testing!
