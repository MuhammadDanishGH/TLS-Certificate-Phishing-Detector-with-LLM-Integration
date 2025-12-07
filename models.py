"""
Machine learning models for certificate classification.
"""
import logging
from typing import List, Dict, Any, Tuple
import pickle
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logging.warning("XGBoost not available")

logger = logging.getLogger(__name__)


class CertificateMLModel:
    """Machine learning model for certificate classification."""
    
    def __init__(self, config=None):
        """Initialize ML model."""
        from .config import get_config
        self.config = config or get_config()
        
        # Feature columns (numeric features only)
        self.feature_columns = [
            'validity_days', 'pubkey_bits', 'chain_length', 'san_count',
            'has_san', 'parse_warning_count', 'has_parse_warnings',
            'pubkey_is_rsa', 'pubkey_is_ecc', 'sig_is_sha256',
            'sig_is_sha1', 'sig_is_md5', 'subject_cn_length',
            'subject_cn_has_wildcard', 'subject_cn_digit_ratio',
            'subject_has_punycode', 'san_has_punycode', 'subject_has_homoglyphs',
            'max_brand_similarity', 'is_brand_typosquatting',
            'issuer_is_reputable', 'is_self_signed', 'url_count',
            'has_url', 'suspicious_keyword_count', 'ip_count',
            'validity_very_short', 'validity_short', 'validity_medium',
            'validity_standard', 'validity_long', 'issuer_frequency',
            'text_length', 'digit_ratio', 'upper_ratio',
            'special_char_ratio', 'entropy', 'non_ascii_ratio'
        ]
        
        # Models
        self.text_vectorizer = None
        self.numeric_scaler = None
        self.classifier = None
        self.model_type = self.config.ml_model_type
    
    def train(
        self,
        parsed_certs: List[Dict],
        features_list: List[Dict],
        labels: List[int]
    ):
        """
        Train model on certificate data.
        
        Args:
            parsed_certs: List of parsed certificates
            features_list: List of feature dictionaries
            labels: Binary labels (0=benign, 1=phishing)
        """
        logger.info(f"Training {self.model_type} model on {len(labels)} samples")
        
        # Extract text for TF-IDF
        texts = [cert.get('raw_text', '') or '' for cert in parsed_certs]
        
        # Build TF-IDF vectorizer
        self.text_vectorizer = TfidfVectorizer(
            max_features=self.config.tfidf_max_features,
            ngram_range=self.config.tfidf_ngram_range,
            min_df=2,
            max_df=0.9,
            strip_accents='unicode',
            lowercase=True
        )
        
        text_features = self.text_vectorizer.fit_transform(texts).toarray()
        logger.info(f"TF-IDF features: {text_features.shape[1]}")
        
        # Extract numeric features
        numeric_features = self._extract_numeric_features(features_list)
        logger.info(f"Numeric features: {numeric_features.shape[1]}")
        
        # Combine features
        X = np.hstack([numeric_features, text_features])
        logger.info(f"Total features: {X.shape[1]}")
        
        # Scale numeric features
        self.numeric_scaler = StandardScaler()
        X[:, :len(self.feature_columns)] = self.numeric_scaler.fit_transform(
            X[:, :len(self.feature_columns)]
        )
        
        # Train classifier
        if self.model_type == 'logistic':
            self.classifier = LogisticRegression(
                class_weight=self.config.class_weight,
                random_state=self.config.random_state,
                max_iter=1000,
                n_jobs=-1
            )
        elif self.model_type == 'xgboost' and XGBOOST_AVAILABLE:
            self.classifier = xgb.XGBClassifier(
                random_state=self.config.random_state,
                n_jobs=-1,
                use_label_encoder=False,
                eval_metric='logloss'
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        self.classifier.fit(X, labels)
        logger.info("Model training complete")
    
    def predict_proba(
        self,
        parsed_certs: List[Dict],
        features_list: List[Dict]
    ) -> np.ndarray:
        """
        Predict probabilities for certificates.
        
        Args:
            parsed_certs: List of parsed certificates
            features_list: List of feature dictionaries
            
        Returns:
            Array of probabilities [prob_benign, prob_phishing]
        """
        if self.classifier is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Extract and transform features
        texts = [cert.get('raw_text', '') or '' for cert in parsed_certs]
        text_features = self.text_vectorizer.transform(texts).toarray()
        
        numeric_features = self._extract_numeric_features(features_list)
        numeric_features = self.numeric_scaler.transform(numeric_features)
        
        X = np.hstack([numeric_features, text_features])
        
        # Predict probabilities
        probas = self.classifier.predict_proba(X)
        return probas
    
    def predict(
        self,
        parsed_certs: List[Dict],
        features_list: List[Dict]
    ) -> Tuple[List[int], List[float]]:
        """
        Predict labels and scores.
        
        Args:
            parsed_certs: List of parsed certificates
            features_list: List of feature dictionaries
            
        Returns:
            Tuple of (labels, scores)
        """
        probas = self.predict_proba(parsed_certs, features_list)
        labels = (probas[:, 1] > 0.5).astype(int)
        scores = probas[:, 1]
        return labels.tolist(), scores.tolist()
    
    def _extract_numeric_features(self, features_list: List[Dict]) -> np.ndarray:
        """Extract numeric features as array."""
        df = pd.DataFrame(features_list)
        
        # Ensure all feature columns exist
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Select and order columns
        X = df[self.feature_columns].fillna(0).values
        return X
    
    def save(self, path: str):
        """Save model to disk."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Save components
        with open(path / 'text_vectorizer.pkl', 'wb') as f:
            pickle.dump(self.text_vectorizer, f)
        
        with open(path / 'numeric_scaler.pkl', 'wb') as f:
            pickle.dump(self.numeric_scaler, f)
        
        with open(path / 'classifier.pkl', 'wb') as f:
            pickle.dump(self.classifier, f)
        
        # Save metadata
        metadata = {
            'model_type': self.model_type,
            'feature_columns': self.feature_columns,
            'tfidf_features': self.text_vectorizer.get_feature_names_out().tolist() if hasattr(self.text_vectorizer, 'get_feature_names_out') else []
        }
        with open(path / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {path}")
    
    @classmethod
    def load(cls, path: str, config=None):
        """Load model from disk."""
        path = Path(path)
        
        model = cls(config)
        
        # Load components
        with open(path / 'text_vectorizer.pkl', 'rb') as f:
            model.text_vectorizer = pickle.load(f)
        
        with open(path / 'numeric_scaler.pkl', 'rb') as f:
            model.numeric_scaler = pickle.load(f)
        
        with open(path / 'classifier.pkl', 'rb') as f:
            model.classifier = pickle.load(f)
        
        # Load metadata
        with open(path / 'metadata.json', 'r') as f:
            metadata = json.load(f)
            model.model_type = metadata['model_type']
            model.feature_columns = metadata['feature_columns']
        
        logger.info(f"Model loaded from {path}")
        return model