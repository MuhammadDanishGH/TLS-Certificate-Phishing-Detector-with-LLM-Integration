"""
Report generation for evaluation results.
"""
import json
from typing import Dict, Any
from pathlib import Path


def generate_report(
    metrics: Dict[str, Any],
    output_path: str,
    model_name: str = "Certificate Detector"
):
    """
    Generate evaluation report.
    
    Args:
        metrics: Metrics dictionary from calculate_metrics
        output_path: Path to save report
        model_name: Name of model being evaluated
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    report = {
        'model_name': model_name,
        'metrics': metrics,
        'summary': {
            'accuracy': f"{metrics.get('accuracy', 0) * 100:.2f}%",
            'precision': f"{metrics.get('precision', 0) * 100:.2f}%",
            'recall': f"{metrics.get('recall', 0) * 100:.2f}%",
            'f1_score': f"{metrics.get('f1_score', 0) * 100:.2f}%",
        }
    }
    
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Also generate markdown summary
    md_path = output_path.parent / (output_path.stem + '.md')
    with open(md_path, 'w') as f:
        f.write(f"# Evaluation Report: {model_name}\n\n")
        f.write("## Summary\n\n")
        f.write(f"- **Accuracy**: {report['summary']['accuracy']}\n")
        f.write(f"- **Precision**: {report['summary']['precision']}\n")
        f.write(f"- **Recall**: {report['summary']['recall']}\n")
        f.write(f"- **F1 Score**: {report['summary']['f1_score']}\n")
        f.write(f"\n## Confusion Matrix\n\n")
        cm = metrics.get('confusion_matrix', [[0, 0], [0, 0]])
        f.write(f"|  | Predicted Benign | Predicted Phishing |\n")
        f.write(f"|---|---|---|\n")
        f.write(f"| **Actual Benign** | {cm[0][0]} | {cm[0][1]} |\n")
        f.write(f"| **Actual Phishing** | {cm[1][0]} | {cm[1][1]} |\n")
    
    return report
