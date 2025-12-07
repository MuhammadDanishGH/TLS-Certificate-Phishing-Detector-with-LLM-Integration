"""
I/O utilities for file operations.
"""
import json
import pickle
from pathlib import Path
from typing import Any, Dict, List


def save_json(data: Any, filepath: str, indent: int = 2):
    """Save data as JSON."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=indent)


def load_json(filepath: str) -> Any:
    """Load JSON data."""
    with open(filepath, 'r') as f:
        return json.load(f)


def save_jsonl(data: List[Dict], filepath: str):
    """Save data as JSON Lines."""
    with open(filepath, 'w') as f:
        for item in data:
            f.write(json.dumps(item) + '\n')


def load_jsonl(filepath: str) -> List[Dict]:
    """Load JSON Lines data."""
    data = []
    with open(filepath, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return data


def save_pickle(data: Any, filepath: str):
    """Save data with pickle."""
    with open(filepath, 'wb') as f:
        pickle.dump(data, f)


def load_pickle(filepath: str) -> Any:
    """Load pickled data."""
    with open(filepath, 'rb') as f:
        return pickle.load(f)


def ensure_dir(path: str) -> Path:
    """Ensure directory exists."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
