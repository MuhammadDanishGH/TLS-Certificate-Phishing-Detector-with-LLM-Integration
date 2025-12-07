"""
Evaluation metrics for certificate classification.
"""
import numpy as np
from typing import Dict, List, Any
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report
)


def calculate_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_scores: List[float]
) -> Dict[str, Any]:
    """
    Calculate comprehensive evaluation metrics.
    
    Args:
        y_true: True labels (0=benign, 1=phishing)
        y_pred: Predicted labels
        y_scores: Prediction scores (probabilities)
        
    Returns:
        Dictionary of metrics
    """
    metrics = {}
    
    # Basic metrics
    metrics['accuracy'] = accuracy_score(y_true, y_pred)
    metrics['precision'] = precision_score(y_true, y_pred, zero_division=0)
    metrics['recall'] = recall_score(y_true, y_pred, zero_division=0)
    metrics['f1_score'] = f1_score(y_true, y_pred, zero_division=0)
    
    # ROC and PR AUC
    try:
        metrics['roc_auc'] = roc_auc_score(y_true, y_scores)
        metrics['pr_auc'] = average_precision_score(y_true, y_scores)
    except ValueError:
        metrics['roc_auc'] = 0.0
        metrics['pr_auc'] = 0.0
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    metrics['confusion_matrix'] = cm.tolist()
    metrics['true_negatives'] = int(cm[0, 0])
    metrics['false_positives'] = int(cm[0, 1])
    metrics['false_negatives'] = int(cm[1, 0])
    metrics['true_positives'] = int(cm[1, 1])
    
    # False positive/negative rates
    metrics['false_positive_rate'] = metrics['false_positives'] / (
        metrics['false_positives'] + metrics['true_negatives']
    ) if (metrics['false_positives'] + metrics['true_negatives']) > 0 else 0
    
    metrics['false_negative_rate'] = metrics['false_negatives'] / (
        metrics['false_negatives'] + metrics['true_positives']
    ) if (metrics['false_negatives'] + metrics['true_positives']) > 0 else 0
    
    # Classification report
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    metrics['classification_report'] = report
    
    # Sample counts
    metrics['total_samples'] = len(y_true)
    metrics['positive_samples'] = int(sum(y_true))
    metrics['negative_samples'] = int(len(y_true) - sum(y_true))
    
    return metrics


def calculate_threshold_metrics(
    y_true: List[int],
    y_scores: List[float],
    thresholds: List[float] = None
) -> Dict[float, Dict[str, float]]:
    """
    Calculate metrics at different score thresholds.
    
    Args:
        y_true: True labels
        y_scores: Prediction scores
        thresholds: List of thresholds to evaluate
        
    Returns:
        Dictionary mapping threshold to metrics
    """
    if thresholds is None:
        thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    
    threshold_metrics = {}
    
    for threshold in thresholds:
        y_pred = [1 if score >= threshold else 0 for score in y_scores]
        
        threshold_metrics[threshold] = {
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1': f1_score(y_true, y_pred, zero_division=0),
            'accuracy': accuracy_score(y_true, y_pred)
        }
    
    return threshold_metrics
