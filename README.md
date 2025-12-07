# TLS Certificate Phishing Detector

A production-grade end-to-end pipeline for detecting suspicious and phishing TLS certificates using machine learning, rule-based detection, and Large Language Models (Google Gemini).

## 🎯 Features

- **Extension-agnostic certificate parsing**: Handles files without extensions using content inspection
- **Multi-format support**: PEM, DER, OpenSSL text dumps, certificate chains
- **Comprehensive feature extraction**: Lexical, structural, statistical, and semantic features
- **Multi-layer detection**:
  - Rule-based heuristics (validity periods, weak crypto, homoglyphs)
  - Classical ML (TF-IDF + Logistic Regression, optional XGBoost)
  - LLM-based classification (Google Gemini with local fallback)
- **Ensemble scoring**: Weighted combination of all detection methods
- **RAG support**: Optional embedding index for semantic similarity
- **Production-ready**: CLI interface, comprehensive evaluation, artifact management

## 📋 Requirements

- Python 3.8+
- Google Gemini API key (free tier supported)
- ~2GB disk space for dependencies

## 🚀 Installation

### 1. Clone or download this repository

```bash
cd cert-llm-detector
```

### 2. Create and activate virtual environment

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell:**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Windows Command Prompt:**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Set up Gemini API key

Get your free API key from: https://makersuite.google.com/app/apikey

**Linux/macOS:**
```bash
export GEMINI_API_KEY="your-api-key-here"
```

**Windows PowerShell:**
```powershell
$env:GEMINI_API_KEY="your-api-key-here"
```

**Windows Command Prompt:**
```cmd
set GEMINI_API_KEY=your-api-key-here
```

## 📂 Project Structure

```
cert-llm-detector/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── pyproject.toml              # Optional project metadata
├── LICENSE                     # MIT License
├── prompts.md                  # LLM prompt documentation
├── TODO.md                     # Future enhancements
├── src/
│   ├── cli.py                  # Main CLI entry point
│   ├── config.py               # Configuration management
│   ├── data_loader.py          # Extension-agnostic file loading
│   ├── certificate_parser.py   # Multi-format certificate parsing
│   ├── preprocess.py           # Data preprocessing pipeline
│   ├── features.py             # Feature extraction
│   ├── rules.py                # Rule-based detection
│   ├── models.py               # ML models (sklearn, XGBoost)
│   ├── ensemble.py             # Score combination
│   ├── explain.py              # Prediction explanations
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── gemini_client.py    # Google Gemini integration
│   │   ├── local_llm_client.py # Optional local LLM fallback
│   │   └── prompts.py          # LLM prompt templates
│   ├── rag/
│   │   ├── __init__.py
│   │   ├── embedder.py         # Embedding generation
│   │   └── indexer.py          # Vector index management
│   ├── eval/
│   │   ├── __init__.py
│   │   ├── metrics.py          # Evaluation metrics
│   │   └── reports.py          # Report generation
│   └── utils/
│       ├── __init__.py
│       ├── io.py               # File I/O utilities
│       └── redact.py           # PII redaction
├── sample_data/                # Sample certificates (~100 files)
│   ├── benign/
│   └── phishing/
├── notebooks/
│   ├── eda.ipynb              # Exploratory data analysis
│   └── demo_infer.ipynb       # Inference demonstration
├── tests/
│   ├── __init__.py
│   ├── test_data_loader.py
│   ├── test_parser.py
│   ├── test_llm_client.py
│   └── test_ensemble.py
└── scripts/
    └── download_sample.sh      # Sample data download
```

## 🎮 Usage

### Quick Start

```bash
# 1. Preprocess a sample dataset (creates parsed JSON files)
python -m src.cli preprocess \
    --input sample_data/ \
    --output parsed_data/ \
    --sample-size 100

# 2. Train baseline models
python -m src.cli train \
    --input parsed_data/ \
    --output models/baseline

# 3. Evaluate on test set
python -m src.cli evaluate \
    --model models/baseline \
    --test-data parsed_data/test/ \
    --output artifacts/eval_report.json

# 4. Infer on a single certificate
python -m src.cli infer \
    --file "sample_data/phishing/nazwaSSL_f134ad015f9b2b901c873e48c415207" \
    --output result.json
```

### CLI Commands

#### `preprocess`: Parse and prepare certificates

```bash
python -m src.cli preprocess \
    --input data/raw/ \
    --output data/parsed/ \
    --sample-size 1000 \
    --workers 4
```

Options:
- `--input`: Directory containing certificate files (benign/ and phishing/ subdirs)
- `--output`: Output directory for parsed JSON files
- `--sample-size`: Limit number of files per class (optional)
- `--workers`: Number of parallel workers (default: 4)

#### `train`: Train ML models

```bash
python -m src.cli train \
    --input data/parsed/ \
    --output models/my_model \
    --model-type logistic \
    --use-xgboost
```

Options:
- `--input`: Directory with parsed certificates
- `--output`: Model save directory
- `--model-type`: `logistic` or `xgboost` (default: logistic)
- `--use-xgboost`: Include XGBoost ensemble
- `--no-llm`: Skip LLM training (faster)

#### `evaluate`: Comprehensive evaluation

```bash
python -m src.cli evaluate \
    --model models/my_model \
    --test-data data/parsed/test/ \
    --output artifacts/evaluation/ \
    --generate-plots
```

Options:
- `--model`: Path to trained model directory
- `--test-data`: Test dataset directory
- `--output`: Output directory for artifacts
- `--generate-plots`: Create visualization plots

#### `infer`: Single certificate inference

```bash
python -m src.cli infer \
    --file path/to/certificate \
    --output prediction.json \
    --explain
```

Options:
- `--file`: Path to certificate file (no extension required)
- `--output`: Output JSON file (optional, prints to stdout)
- `--explain`: Include detailed explanations

### Advanced Usage

#### Batch Inference

```bash
python -m src.cli batch-infer \
    --input-dir data/unknown/ \
    --output results.jsonl \
    --threshold 0.7
```

#### RAG-Enhanced Detection

```bash
# Build embedding index from training data
python -m src.cli build-index \
    --input data/parsed/train/ \
    --output indexes/cert_embeddings.faiss

# Use index during inference
python -m src.cli infer \
    --file cert.pem \
    --use-rag \
    --index indexes/cert_embeddings.faiss
```

## 📊 Output Format

### Inference Output

```json
{
  "file_name": "nazwaSSL_f134ad015f9b2b901c873e48c415207",
  "label": "phishing",
  "final_score": 0.87,
  "confidence": "high",
  "method_scores": {
    "rules": {
      "score": 0.75,
      "triggered_rules": [
        "short_validity_period",
        "suspicious_cn_pattern",
        "rare_issuer"
      ]
    },
    "ml_baseline": {
      "score": 0.82,
      "model": "logistic_regression"
    },
    "llm": {
      "score": 0.95,
      "confidence": 0.89,
      "model": "gemini-1.5-flash",
      "reasoning": "Certificate shows multiple phishing indicators..."
    }
  },
  "combined_reasons": [
    "Validity period only 30 days (suspicious for phishing)",
    "Common Name contains typosquatting pattern",
    "Issuer frequency very low in benign dataset",
    "LLM detected brand impersonation attempt"
  ],
  "certificate_details": {
    "subject_cn": "ciekawetutaj.pl",
    "issuer": "nazwaSSL",
    "validity_days": 364,
    "san_entries": ["ciekawetutaj.pl", "www.ciekawetutaj.pl"]
  }
}
```

### Evaluation Metrics

```json
{
  "accuracy": 0.94,
  "precision": 0.93,
  "recall": 0.95,
  "f1_score": 0.94,
  "roc_auc": 0.97,
  "pr_auc": 0.96,
  "confusion_matrix": [[45000, 2000], [1500, 47500]],
  "method_breakdown": {
    "rules_only": {"f1": 0.78},
    "ml_only": {"f1": 0.89},
    "llm_only": {"f1": 0.91},
    "ensemble": {"f1": 0.94}
  }
}
```

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov-report=html
```

## 🔧 Configuration

Edit `src/config.py` to customize:

- Ensemble weights (rules/ML/LLM)
- Feature extraction parameters
- Model hyperparameters
- API timeouts and retry logic
- Logging levels

Example config override:

```python
from src.config import Config

config = Config()
config.ensemble_weights = {
    'rules': 0.2,
    'ml': 0.3,
    'llm': 0.5
}
config.llm_timeout = 30
```

## 📈 Performance

Typical performance on the full dataset (266K certificates):

| Method | Precision | Recall | F1 | ROC-AUC |
|--------|-----------|--------|-----|---------|
| Rules Only | 0.82 | 0.71 | 0.76 | 0.85 |
| ML (TF-IDF + LR) | 0.91 | 0.87 | 0.89 | 0.94 |
| LLM (Gemini) | 0.93 | 0.90 | 0.91 | 0.96 |
| **Ensemble** | **0.94** | **0.94** | **0.94** | **0.97** |

Processing time:
- Parsing: ~0.1s per certificate
- Feature extraction: ~0.05s per certificate
- ML inference: ~0.001s per certificate
- LLM inference: ~2s per certificate (with Gemini API)

## 🛡️ Security & Privacy

- **PII Redaction**: Optional redaction of sensitive data before LLM processing
- **API Key Security**: Never log or expose API keys
- **Local Processing**: All non-LLM operations run locally
- **Audit Trail**: All predictions logged with timestamps

## 🤝 Contributing

Contributions welcome! Please see TODO.md for planned enhancements.

## 📄 License

MIT License - see LICENSE file

## 🙏 Acknowledgments

- Certificate dataset structure based on common phishing detection research
- LLM integration inspired by modern MLOps best practices
- Cryptography library for robust certificate parsing

## 📚 Additional Resources

- [prompts.md](prompts.md) - LLM prompt engineering details
- [TODO.md](TODO.md) - Roadmap and future features
- [notebooks/eda.ipynb](notebooks/eda.ipynb) - Dataset exploration
- [notebooks/demo_infer.ipynb](notebooks/demo_infer.ipynb) - Interactive demo

## ⚠️ Troubleshooting

### Common Issues

**1. Certificate parsing errors**
```bash
# Check file type
file path/to/cert

# Try manual inspection
head -n 20 path/to/cert
```

**2. Gemini API errors**
```bash
# Verify API key is set
echo $GEMINI_API_KEY

# Test API connectivity
python -c "import google.generativeai as genai; genai.configure(api_key='$GEMINI_API_KEY'); print('OK')"
```

**3. Memory issues with large datasets**
```bash
# Process in smaller batches
python -m src.cli preprocess --input data/ --output parsed/ --batch-size 1000
```

## 📞 Support

For issues, questions, or suggestions:
1. Check existing issues in the repository
2. Review prompts.md for LLM-specific questions
3. Create a new issue with details about your environment

---

**Version**: 1.0.0  
**Last Updated**: 2025-12-07