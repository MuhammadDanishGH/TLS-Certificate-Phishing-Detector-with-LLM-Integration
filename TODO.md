# TODO and Future Enhancements

## High Priority

### Performance Optimization
- [ ] Implement certificate caching (hash-based) to avoid re-parsing
- [ ] Add parallel processing for batch inference
- [ ] Optimize feature extraction (vectorization, precompiled regex)
- [ ] LLM response caching with TTL
- [ ] Lazy loading of optional dependencies (transformers, faiss)

### Robustness
- [ ] Better handling of corrupted/malformed certificates
- [ ] Graceful degradation when LLM API is unavailable
- [ ] Retry logic with exponential backoff for all API calls
- [ ] Input validation and sanitization
- [ ] More comprehensive error messages

### Model Improvements
- [ ] Ensemble hyperparameter tuning (grid search on validation set)
- [ ] Add XGBoost with hyperparameter optimization
- [ ] Implement SMOTE for handling class imbalance
- [ ] Feature selection using mutual information
- [ ] Calibration of probability outputs

## Medium Priority

### Features
- [ ] Real-time certificate monitoring (watch directory)
- [ ] Integration with CT logs (Certificate Transparency)
- [ ] Bulk certificate download from popular CAs
- [ ] Export to STIX/TAXII for threat intelligence sharing
- [ ] Configurable thresholds per use case (high security vs. low false positive)
- [ ] Multi-language support for domains (IDN handling)

### LLM Enhancements
- [ ] Support for additional LLM providers:
  - [ ] OpenAI GPT-4
  - [ ] Anthropic Claude
  - [ ] Azure OpenAI
  - [ ] AWS Bedrock
- [ ] Fine-tuning on certificate-specific dataset
- [ ] Chain-of-thought prompting for better reasoning
- [ ] Self-consistency sampling (multiple predictions, vote)
- [ ] Automatic prompt optimization with DSPy or similar

### RAG (Retrieval-Augmented Generation)
- [ ] Build comprehensive embedding index from training data
- [ ] Implement k-NN retrieval of similar certificates
- [ ] Provide LLM with top-k similar examples at inference time
- [ ] Hybrid retrieval (dense + sparse/BM25)
- [ ] Periodically update index with new detections

### Explainability
- [ ] SHAP values for ML model predictions
- [ ] LIME for local explanations
- [ ] Attention visualization for transformer models
- [ ] Rule trace visualization
- [ ] Interactive explanation UI (web dashboard)

## Low Priority

### Documentation
- [ ] Video tutorial for setup and usage
- [ ] API documentation (if exposing as service)
- [ ] Case studies and real-world examples
- [ ] Jupyter notebook with full walkthrough
- [ ] Architecture decision records (ADRs)

### Testing
- [ ] Increase test coverage to >90%
- [ ] Integration tests with real API calls (mocked by default)
- [ ] Property-based testing for parsers
- [ ] Stress testing with large batches
- [ ] Fuzzing for parser robustness

### Deployment
- [ ] Docker image for easy deployment
- [ ] REST API with FastAPI
- [ ] Kubernetes manifests
- [ ] GitHub Actions CI/CD pipeline
- [ ] Pre-commit hooks for code quality
- [ ] Automated release process

### UI/UX
- [ ] Web-based dashboard (React/Vue)
- [ ] Real-time visualization of detections
- [ ] Historical trend analysis
- [ ] Alerting and notifications
- [ ] User feedback loop for model improvement

## Research Ideas

### Novel Detection Techniques
- [ ] Graph neural networks on certificate chains
- [ ] Anomaly detection on certificate issuance patterns
- [ ] Time-series analysis of certificate lifespans
- [ ] Multi-modal learning (certificate + WHOIS + DNS)
- [ ] Transfer learning from pre-trained security models

### Dataset Enhancements
- [ ] Collect more diverse phishing certificates
- [ ] Label fine-grained phishing types (brand, typosquatting, etc.)
- [ ] Temporal splits for realistic evaluation
- [ ] Adversarial examples for robustness testing
- [ ] Synthetic certificate generation for data augmentation

### Advanced LLM Usage
- [ ] Multi-agent debate for difficult cases
- [ ] LLM-guided feature engineering
- [ ] Automatic rule generation from LLM insights
- [ ] Continual learning from LLM predictions
- [ ] LLM as a reinforcement learning reward model

## Bug Fixes and Known Issues

### Current Issues
- [ ] Handle certificates with non-UTF-8 encoding in subject fields
- [ ] Improve detection of IDN homograph attacks (more language coverage)
- [ ] Fix edge case where certificate chain parsing fails silently
- [ ] Better handling of expired certificates (don't skip)
- [ ] Normalize timestamp formats across different OpenSSL versions

### Performance Issues
- [ ] LLM inference can be slow (2-5s per cert)
  - Solution: Batch inference, caching, async processing
- [ ] Memory usage high for large datasets (>100K certs)
  - Solution: Streaming processing, chunking
- [ ] Feature extraction bottleneck for TF-IDF
  - Solution: Incremental vectorizer, pre-trained embeddings

## Community Requests

(To be filled as issues/PRs are received)

- [ ] Support for certificate revocation checking (CRL/OCSP)
- [ ] Integration with existing SIEM systems
- [ ] Support for S/MIME certificates
- [ ] Code signing certificate analysis
- [ ] Mobile app for on-the-go analysis

## Completed

- [x] Core certificate parsing (PEM, DER, OpenSSL text)
- [x] Extension-agnostic file loading
- [x] Rule-based detection engine
- [x] ML baseline (Logistic Regression)
- [x] Google Gemini LLM integration
- [x] Ensemble scoring
- [x] CLI interface
- [x] Comprehensive evaluation metrics
- [x] Few-shot prompting
- [x] JSON output format
- [x] Basic test suite

## Contributing

If you'd like to work on any of these items:

1. Check if there's an existing issue/PR
2. Comment on the issue to claim it (or create one)
3. Fork, implement, test
4. Submit PR with clear description
5. Ensure tests pass and code is documented

## Prioritization Criteria

**High Priority**: Core functionality, critical bugs, major performance issues  
**Medium Priority**: Nice-to-have features, usability improvements  
**Low Priority**: Long-term improvements, research ideas

---

**Last Updated**: 2025-12-07