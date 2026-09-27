"""Train Rakshak on 1,000 sanitized public-corpus emails from Hugging Face."""
from __future__ import annotations

import csv
import hashlib
import json
import random
import re
from pathlib import Path
from urllib.parse import urlencode

import httpx
import joblib
from sklearn.pipeline import FeatureUnion, make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / 'models'
DATASET_PATH = Path(__file__).with_name('public_email_sample.csv')
MODEL_PATH = MODEL_DIR / 'rakshak_tfidf_v2.joblib'
METADATA_PATH = MODEL_DIR / 'rakshak_tfidf_v2.json'
DATASET = 'puyang2025/seven-phishing-email-datasets'
SEED = 42
TARGETS = {'train': {0: 400, 1: 400}, 'test': {0: 100, 1: 100}}


def sanitize(value: object) -> str:
    text = str(value or '')
    text = re.sub(r'https?://\S+|www\.\S+', ' URLTOKEN ', text, flags=re.I)
    text = re.sub(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b', ' EMAILTOKEN ', text)
    text = re.sub(r'\b(?:\+?\d[\d ().-]{7,}\d)\b', ' PHONETOKEN ', text)
    text = re.sub(r'\b\d{6,}\b', ' NUMBERTOKEN ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:12000]


def fingerprint(subject: str, body: str) -> str:
    normalized = re.sub(r'\W+', '', (subject + body).lower())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def fetch_page(client: httpx.Client, split: str, offset: int) -> dict:
    query = urlencode({'dataset': DATASET, 'config': 'default', 'split': split, 'offset': offset, 'length': 100})
    response = client.get('https://datasets-server.huggingface.co/rows?' + query)
    response.raise_for_status()
    return response.json()


def collect_split(client: httpx.Client, split: str, wanted: dict[int, int], global_hashes: set[str]) -> list[dict]:
    first = fetch_page(client, split, 0)
    total = int(first['num_rows_total'])
    offsets = list(range(0, total, 100))
    random.Random(SEED + (0 if split == 'train' else 1)).shuffle(offsets)
    selected = {0: [], 1: []}
    for offset in offsets:
        page = first if offset == 0 else fetch_page(client, split, offset)
        for wrapped in page.get('rows', []):
            row = wrapped.get('row') or {}
            label = row.get('label')
            if label not in (0, 1) or len(selected[label]) >= wanted[label]:
                continue
            subject, body = sanitize(row.get('subject')), sanitize(row.get('text'))
            if len(subject + body) < 30:
                continue
            digest = fingerprint(subject, body)
            if digest in global_hashes:
                continue
            global_hashes.add(digest)
            selected[label].append({
                'subject': subject,
                'body': body,
                'label': label,
                'dataset_name': sanitize(row.get('dataset_name'))[:80],
                'split': split,
                'content_sha256': digest,
            })
        if all(len(selected[label]) >= wanted[label] for label in (0, 1)):
            break
    if any(len(selected[label]) < wanted[label] for label in (0, 1)):
        raise RuntimeError(f'Could not collect balanced {split} sample: ' + str({k: len(v) for k, v in selected.items()}))
    result = selected[0] + selected[1]
    random.Random(SEED).shuffle(result)
    return result


def main():
    hashes: set[str] = set()
    with httpx.Client(timeout=45, follow_redirects=True, headers={'User-Agent': 'Rakshak-research-training/1.0'}) as client:
        train = collect_split(client, 'train', TARGETS['train'], hashes)
        test = collect_split(client, 'test', TARGETS['test'], hashes)
    rows = train + test
    assert len(rows) == 1000 and sum(row['label'] for row in rows) == 500

    with DATASET_PATH.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=['subject', 'body', 'label', 'dataset_name', 'split', 'content_sha256'])
        writer.writeheader()
        writer.writerows(rows)

    features = FeatureUnion([
        ('words', TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=.98, max_features=18000, sublinear_tf=True, strip_accents='unicode')),
        ('characters', TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), min_df=3, max_features=18000, sublinear_tf=True)),
    ])
    pipeline = make_pipeline(features, LogisticRegression(C=2, class_weight='balanced', random_state=SEED, max_iter=1500))
    compose = lambda row: row['subject'] + '\n' + row['body']
    pipeline.fit([compose(row) for row in train], [row['label'] for row in train])
    truth = [row['label'] for row in test]
    predicted = pipeline.predict([compose(row) for row in test])
    precision, recall, f1, _ = precision_recall_fscore_support(truth, predicted, average='binary', zero_division=0)
    source_counts = {}
    for row in rows:
        source_counts[row['dataset_name']] = source_counts.get(row['dataset_name'], 0) + 1
    metadata = {
        'model': 'word and character TF-IDF + class-balanced logistic regression',
        'version': 2,
        'seed': SEED,
        'corpus_type': 'sanitized public email corpus',
        'dataset': DATASET,
        'total_examples': 1000,
        'phishing_or_spam_examples': 500,
        'benign_examples': 500,
        'training_examples': 800,
        'test_examples': 200,
        'split_method': 'official Hugging Face train and test splits; exact duplicates removed across splits',
        'privacy_processing': 'Email addresses, URLs, phone-like values and long numeric identifiers replaced before storage and training',
        'source_counts': dict(sorted(source_counts.items())),
        'accuracy': round(float(accuracy_score(truth, predicted)), 4),
        'precision': round(float(precision), 4),
        'recall': round(float(recall), 4),
        'f1': round(float(f1), 4),
        'confusion_matrix': confusion_matrix(truth, predicted).tolist(),
        'classification_report': classification_report(truth, predicted, output_dict=True, zero_division=0),
        'limitations': 'Positive labels combine spam and phishing. Metrics are from a 1,000-message sample and are not production accuracy.',
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
