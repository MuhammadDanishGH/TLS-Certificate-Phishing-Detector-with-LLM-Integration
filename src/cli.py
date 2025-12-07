"""
Command-line interface for certificate phishing detector.
"""
import sys
import json
import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import track
from tqdm import tqdm

console = Console()


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--config', '-c', type=click.Path(), help='Config file path')
def main(verbose, config):
    """TLS Certificate Phishing Detector with LLM Integration."""
    # Setup logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load config if provided
    if config:
        from .config import Config, set_config
        cfg = Config.from_yaml(config)
        set_config(cfg)


@main.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True),
              help='Input directory containing benign/ and phishing/ subdirectories')
@click.option('--output', '-o', required=True, type=click.Path(),
              help='Output directory for parsed certificates')
@click.option('--sample-size', '-n', type=int, help='Limit files per class')
@click.option('--workers', '-w', type=int, default=4, help='Number of parallel workers')
def preprocess(input, output, sample_size, workers):
    """Parse and preprocess certificate files."""
    from .data_loader import CertificateLoader
    from .certificate_parser import CertificateParser
    from .features import FeatureExtractor
    
    console.print(f"[bold]Preprocessing certificates from {input}[/bold]")
    
    # Load certificates
    loader = CertificateLoader(max_workers=workers)
    benign_data, phishing_data = loader.load_dataset(input, sample_size)
    
    all_data = benign_data + phishing_data
    console.print(f"Loaded {len(benign_data)} benign, {len(phishing_data)} phishing certificates")
    
    # Parse certificates
    parser = CertificateParser()
    parsed_certs = []
    
    console.print("[bold]Parsing certificates...[/bold]")
    for cert_data in track(all_data, description="Parsing"):
        parsed = parser.parse(
            cert_data['raw_content'],
            cert_data['file_type'],
            cert_data['file_name']
        )
        parsed['label'] = cert_data['label']
        parsed_certs.append(parsed)
    
    # Extract features
    console.print("[bold]Extracting features...[/bold]")
    extractor = FeatureExtractor()
    extractor.fit_issuer_frequencies(parsed_certs)
    
    for parsed in track(parsed_certs, description="Features"):
        features = extractor.extract_features(parsed)
        features['issuer_frequency'] = extractor.get_issuer_frequency(parsed)
        parsed['features'] = features
    
    # Save to output
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    benign_dir = output_path / 'benign'
    phishing_dir = output_path / 'phishing'
    benign_dir.mkdir(exist_ok=True)
    phishing_dir.mkdir(exist_ok=True)
    
    console.print(f"[bold]Saving to {output}...[/bold]")
    for parsed in parsed_certs:
        label = parsed.get('label', 'unknown')
        save_dir = benign_dir if label == 'benign' else phishing_dir
        
        filename = parsed['file_name'] + '.json'
        filepath = save_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(parsed, f, indent=2)
    
    console.print(f"[bold green]✓ Preprocessing complete![/bold green]")
    console.print(f"Saved {len(parsed_certs)} parsed certificates to {output}")


@main.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True),
              help='Directory with parsed certificates')
@click.option('--output', '-o', required=True, type=click.Path(),
              help='Model output directory')
@click.option('--model-type', type=click.Choice(['logistic', 'xgboost']),
              default='logistic', help='Model type')
@click.option('--no-llm', is_flag=True, help='Skip LLM in training')
def train(input, output, model_type, no_llm):
    """Train ML models on parsed certificates."""
    from .models import CertificateMLModel
    from .config import get_config, set_config, Config
    
    # Update config
    config = get_config()
    config.ml_model_type = model_type
    if no_llm:
        config.use_llm = False
    set_config(config)
    
    console.print(f"[bold]Training {model_type} model[/bold]")
    
    # Load parsed certificates
    input_path = Path(input)
    benign_files = list((input_path / 'benign').glob('*.json'))
    phishing_files = list((input_path / 'phishing').glob('*.json'))
    
    console.print(f"Found {len(benign_files)} benign, {len(phishing_files)} phishing files")
    
    parsed_certs = []
    features_list = []
    labels = []
    
    console.print("[bold]Loading data...[/bold]")
    for filepath in tqdm(benign_files + phishing_files):
        with open(filepath, 'r') as f:
            data = json.load(f)
            parsed_certs.append(data)
            features_list.append(data.get('features', {}))
            labels.append(1 if data.get('label') == 'phishing' else 0)
    
    # Train model
    model = CertificateMLModel(config)
    console.print(f"[bold]Training on {len(labels)} samples...[/bold]")
    model.train(parsed_certs, features_list, labels)
    
    # Save model
    output_path = Path(output)
    model.save(str(output_path))
    
    console.print(f"[bold green]✓ Model saved to {output}[/bold green]")


@main.command()
@click.option('--model', '-m', required=True, type=click.Path(exists=True),
              help='Path to trained model')
@click.option('--test-data', '-t', required=True, type=click.Path(exists=True),
              help='Test data directory')
@click.option('--output', '-o', required=True, type=click.Path(),
              help='Output directory for evaluation results')
def evaluate(model, test_data, output):
    """Evaluate model on test set."""
    from .models import CertificateMLModel
    from .eval.metrics import calculate_metrics
    from .eval.reports import generate_report
    
    console.print("[bold]Evaluating model...[/bold]")
    
    # Load model
    ml_model = CertificateMLModel.load(model)
    
    # Load test data
    test_path = Path(test_data)
    benign_files = list(test_path.glob('benign/*.json'))
    phishing_files = list(test_path.glob('phishing/*.json'))
    
    parsed_certs = []
    features_list = []
    y_true = []
    
    for filepath in tqdm(benign_files + phishing_files, desc="Loading test data"):
        with open(filepath, 'r') as f:
            data = json.load(f)
            parsed_certs.append(data)
            features_list.append(data.get('features', {}))
            y_true.append(1 if data.get('label') == 'phishing' else 0)
    
    # Make predictions
    console.print("[bold]Generating predictions...[/bold]")
    y_pred, y_scores = ml_model.predict(parsed_certs, features_list)
    
    # Calculate metrics
    metrics = calculate_metrics(y_true, y_pred, y_scores)
    
    # Generate report
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    report_path = output_path / 'evaluation_report.json'
    with open(report_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Print summary
    table = Table(title="Evaluation Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    for key, value in metrics.items():
        if isinstance(value, (int, float)):
            table.add_row(key, f"{value:.4f}")
    
    console.print(table)
    console.print(f"[bold green]✓ Full report saved to {report_path}[/bold green]")


@main.command()
@click.option('--file', '-f', required=True, type=click.Path(exists=True),
              help='Certificate file to analyze')
@click.option('--output', '-o', type=click.Path(), help='Output JSON file')
@click.option('--explain', is_flag=True, help='Include detailed explanations')
def infer(file, output, explain):
    """Analyze a single certificate file."""
    from .data_loader import load_single_file
    from .certificate_parser import parse_certificate
    from .features import FeatureExtractor
    from .ensemble import detect_certificate
    
    console.print(f"[bold]Analyzing {file}...[/bold]")
    
    # Load and parse
    file_data = load_single_file(file)
    parsed_cert = parse_certificate(
        file_data['raw_content'],
        file_data['file_type'],
        file_data['file_name']
    )
    
    # Extract features
    extractor = FeatureExtractor()
    features = extractor.extract_features(parsed_cert)
    
    # Detect
    result = detect_certificate(parsed_cert, features)
    
    # Output
    if output:
        with open(output, 'w') as f:
            json.dump(result, f, indent=2)
        console.print(f"[bold green]✓ Result saved to {output}[/bold green]")
    else:
        console.print_json(json.dumps(result, indent=2))


@main.command()
@click.option('--input-dir', '-i', required=True, type=click.Path(exists=True),
              help='Directory with certificates to analyze')
@click.option('--output', '-o', required=True, type=click.Path(),
              help='Output JSONL file')
@click.option('--threshold', '-t', type=float, default=0.5,
              help='Phishing score threshold')
def batch_infer(input_dir, output, threshold):
    """Batch inference on multiple certificates."""
    from .data_loader import CertificateLoader
    from .certificate_parser import CertificateParser
    from .features import FeatureExtractor
    from .ensemble import detect_certificate
    
    console.print(f"[bold]Batch inference on {input_dir}...[/bold]")
    
    # Load all files
    loader = CertificateLoader()
    files = loader.load_directory(input_dir, recursive=True)
    
    # Parse and detect
    parser = CertificateParser()
    extractor = FeatureExtractor()
    
    results = []
    phishing_count = 0
    
    with open(output, 'w') as f:
        for file_data in tqdm(files, desc="Processing"):
            try:
                parsed = parser.parse(
                    file_data['raw_content'],
                    file_data['file_type'],
                    file_data['file_name']
                )
                features = extractor.extract_features(parsed)
                result = detect_certificate(parsed, features)
                
                if result['final_score'] >= threshold:
                    phishing_count += 1
                
                f.write(json.dumps(result) + '\n')
                results.append(result)
            except Exception as e:
                console.print(f"[red]Error processing {file_data['file_name']}: {e}[/red]")
    
    console.print(f"[bold green]✓ Processed {len(results)} certificates[/bold green]")
    console.print(f"[bold yellow]Found {phishing_count} potential phishing certificates[/bold yellow]")
    console.print(f"Results saved to {output}")


if __name__ == '__main__':
    main()
