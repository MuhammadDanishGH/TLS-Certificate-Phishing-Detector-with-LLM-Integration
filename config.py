"""
Configuration management for certificate phishing detector.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import yaml


@dataclass
class Config:
    """Main configuration class."""
    
    # Paths
    data_dir: str = "data"
    models_dir: str = "models"
    artifacts_dir: str = "artifacts"
    cache_dir: str = ".cache"
    
    # Data loading
    max_workers: int = 4
    sample_size: Optional[int] = None
    train_test_split: float = 0.7
    val_split: float = 0.15
    random_seed: int = 42
    
    # Feature extraction
    max_text_length: int = 10000
    tfidf_max_features: int = 5000
    tfidf_ngram_range: tuple = (1, 3)
    min_issuer_frequency: int = 5
    
    # Rule-based detection
    min_validity_days: int = 7
    max_validity_days: int = 398
    min_pubkey_bits: int = 2048
    weak_algorithms: list = field(default_factory=lambda: ["sha1", "md5"])
    
    # ML models
    ml_model_type: str = "logistic"  # "logistic" or "xgboost"
    use_xgboost: bool = False
    class_weight: str = "balanced"
    random_state: int = 42
    
    # LLM configuration
    use_llm: bool = True
    llm_provider: str = "gemini"  # "gemini" or "local"
    llm_model: str = "gemini-1.5-flash"  # or "gemini-1.5-pro"
    llm_timeout: int = 30
    llm_max_retries: int = 3
    llm_temperature: float = 0.1
    llm_cache_enabled: bool = True
    
    # Gemini-specific
    gemini_api_key: Optional[str] = None
    gemini_rpm_limit: int = 15  # Free tier: 15 requests per minute
    
    # Local LLM (optional)
    local_llm_model_path: Optional[str] = None
    local_llm_n_ctx: int = 4096
    
    # RAG configuration
    use_rag: bool = False
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    faiss_index_path: Optional[str] = None
    rag_top_k: int = 3
    
    # Ensemble weights
    ensemble_weights: Dict[str, float] = field(default_factory=lambda: {
        "rules": 0.25,
        "ml": 0.35,
        "llm": 0.40,
    })
    
    # Thresholds
    phishing_threshold: float = 0.5
    high_confidence_threshold: float = 0.8
    low_confidence_threshold: float = 0.3
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Privacy
    redact_pii: bool = False
    
    def __post_init__(self):
        """Load API key from environment if not set."""
        if self.gemini_api_key is None:
            self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        
        # Validate ensemble weights sum to 1.0
        weights_sum = sum(self.ensemble_weights.values())
        if abs(weights_sum - 1.0) > 0.01:
            raise ValueError(f"Ensemble weights must sum to 1.0, got {weights_sum}")
    
    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        """Load configuration from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def to_yaml(self, path: str):
        """Save configuration to YAML file."""
        data = {
            k: v for k, v in self.__dict__.items()
            if not k.startswith('_')
        }
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            k: v for k, v in self.__dict__.items()
            if not k.startswith('_')
        }


# Default global config instance
config = Config()


def get_config() -> Config:
    """Get global config instance."""
    return config


def set_config(new_config: Config):
    """Set global config instance."""
    global config
    config = new_config