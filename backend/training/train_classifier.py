"""Build Rakshak's reproducible 1,000-message synthetic training corpus."""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import make_pipeline


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / 'models'
DATASET_PATH = Path(__file__).with_name('generated_emails.csv')
MODEL_PATH = MODEL_DIR / 'rakshak_tfidf_v1.joblib'
METADATA_PATH = MODEL_DIR / 'rakshak_tfidf_v1.json'
SEED = 42

PHISHING_FAMILIES = [
    ('Account locked', 'Your {brand} account is locked. Sign in at {url} and confirm your password {urgency}.'),
    ('Mailbox suspension', 'Your mailbox will be suspended {deadline}. Verify your credentials at {url}.'),
    ('OTP theft', 'A login was detected. Send the OTP verification code to this address {urgency}.'),
    ('Password expiry', 'Your company password expires {deadline}. Keep access by logging in through {url}.'),
    ('Payment diversion', 'Our bank details changed. Transfer {amount} to the new beneficiary {urgency}.'),
    ('CEO fraud', 'I am the CEO and in a meeting. Buy gift cards worth {amount}. Do not call me.'),
    ('Fake invoice', 'Invoice {invoice} is overdue. Pay {amount} using the account shown at {url}.'),
    ('Payroll update', 'Payroll needs your bank account and password to release this month salary.'),
    ('Cloud share', '{sender} shared a protected document. Sign in at {url} to view it.'),
    ('Tax threat', 'Legal action and a penalty will follow unless you pay {amount} {urgency}.'),
    ('Delivery fee', 'Your parcel is held. Pay the small redelivery fee at {url} {urgency}.'),
    ('Security breach', 'A security breach affected your {brand} profile. Confirm credentials at {url}.'),
    ('Refund lure', 'A refund of {amount} is waiting. Enter your banking details at {url}.'),
    ('Benefits enrollment', 'Benefits enrollment closes {deadline}. Verify your identity and password at {url}.'),
    ('Shared voicemail', 'You received a confidential voicemail. Log in at {url} to listen.'),
    ('Procurement fraud', 'Confidential supplier change: send the next payment of {amount} to our new account.'),
    ('VPN reset', 'Your remote access will be deactivated. Validate your login at {url} immediately.'),
    ('Card alert', 'Unauthorized card activity detected. Confirm your account and OTP at {url}.'),
    ('Scholarship scam', 'Your grant was approved. Pay a processing charge of {amount} today to claim it.'),
    ('Subscription renewal', 'Your {brand} subscription failed. Update payment details at {url} within 12 hours.'),
]

BENIGN_FAMILIES = [
    ('Meeting agenda', 'Attached is the agenda for the {team} meeting on {date}. No action is required.'),
    ('Project review', 'The {project} project notes are ready for review before our next meeting.'),
    ('Shipping notice', 'Order {invoice} has shipped and delivery is scheduled for {date}.'),
    ('Newsletter', 'Here is the monthly {team} newsletter and community update.'),
    ('Paid invoice', 'Invoice {invoice} for {amount} was paid yesterday. Thank you for your business.'),
    ('Security advice', 'Never share your password or OTP verification code with anyone, including support.'),
    ('Lunch plan', 'Lunch is planned for noon on {date}. Let me know if you can join.'),
    ('Meeting minutes', 'The meeting minutes for {project} are attached. No urgent action is required.'),
    ('Password training', 'Security training explains how to identify fake login pages and protect passwords.'),
    ('Approved transfer', 'The transfer of {amount} was approved through our normal finance workflow.'),
    ('Invoice query', 'Can you confirm whether invoice {invoice} was received? Payment is not yet requested.'),
    ('IT maintenance', 'Planned maintenance for {team} systems begins on {date}. Use the normal company portal.'),
    ('Travel itinerary', 'Your approved travel itinerary is attached for the conference on {date}.'),
    ('Policy update', 'The updated remote-work policy is available on the internal staff site.'),
    ('Receipt', 'This is your receipt for {amount}. No further payment is due.'),
    ('Account confirmation', 'Your profile update was completed. If this was not you, contact support by phone.'),
    ('Benefits reminder', 'Benefits enrollment closes on {date}. Visit the bookmarked employee portal.'),
    ('Document collaboration', '{sender} added comments to the {project} planning document.'),
    ('Team recognition', 'Congratulations to the {team} team for completing the quarterly milestone.'),
    ('Support closure', 'Support ticket {invoice} is resolved. We will never ask for your password or OTP.'),
]


def render(template: str, index: int, rng: random.Random) -> str:
    values = {
        'brand': rng.choice(['Microsoft', 'Google', 'PayPal', 'Amazon', 'Apple']),
        'url': f'https://security-check-{index}.example/login',
        'urgency': rng.choice(['immediately', 'today', 'within 24 hours', 'as soon as possible']),
        'deadline': rng.choice(['today', 'tomorrow', 'within 12 hours', 'this Friday']),
        'amount': rng.choice(['INR 18,500', 'USD 740', 'INR 52,000', 'USD 1,250']),
        'invoice': f'INV-{2026000 + index}',
        'sender': rng.choice(['Aarav', 'Meera', 'Jordan', 'Priya', 'Sam']),
        'team': rng.choice(['security', 'engineering', 'finance', 'operations', 'research']),
        'project': rng.choice(['Orion', 'Atlas', 'Beacon', 'Nimbus', 'Rakshak']),
        'date': rng.choice(['Monday', '16 September', 'next Wednesday', '30 September']),
    }
    return template.format(**values) + f' Reference message {index:04d}.'


def build_dataset():
    rng = random.Random(SEED)
    rows = []
    for label, families in ((1, PHISHING_FAMILIES), (0, BENIGN_FAMILIES)):
        for family_index, (subject, template) in enumerate(families):
            split = 'train' if family_index < 16 else 'test'
            for variation in range(25):
                index = label * 500 + family_index * 25 + variation
                rows.append({
                    'id': f'RKS-{index:04d}',
                    'subject': f'{subject} - {variation + 1}',
                    'body': render(template, index, rng),
                    'label': label,
                    'family': subject,
                    'split': split,
                })
    rng.shuffle(rows)
    return rows


def main():
    rows = build_dataset()
    assert len(rows) == 1000
    assert sum(row['label'] for row in rows) == 500
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with DATASET_PATH.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=['id', 'subject', 'body', 'label', 'family', 'split'])
        writer.writeheader()
        writer.writerows(rows)

    train = [row for row in rows if row['split'] == 'train']
    test = [row for row in rows if row['split'] == 'test']
    text = lambda row: row['subject'] + '\n' + row['body']
    pipeline = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=12000),
        LogisticRegression(C=3, random_state=SEED, max_iter=1000),
    )
    pipeline.fit([text(row) for row in train], [row['label'] for row in train])
    truth = [row['label'] for row in test]
    predicted = pipeline.predict([text(row) for row in test])
    precision, recall, f1, _ = precision_recall_fscore_support(truth, predicted, average='binary', zero_division=0)
    matrix = confusion_matrix(truth, predicted).tolist()
    metadata = {
        'model': 'TF-IDF (1-2 grams) + logistic regression',
        'version': 1,
        'seed': SEED,
        'corpus_type': 'synthetic demonstration corpus',
        'total_examples': len(rows),
        'phishing_examples': 500,
        'benign_examples': 500,
        'training_examples': len(train),
        'test_examples': len(test),
        'split_method': 'held-out template families (16 train and 4 test families per class)',
        'accuracy': round(float(accuracy_score(truth, predicted)), 4),
        'precision': round(float(precision), 4),
        'recall': round(float(recall), 4),
        'f1': round(float(f1), 4),
        'confusion_matrix': matrix,
        'classification_report': classification_report(truth, predicted, output_dict=True, zero_division=0),
        'limitations': 'Metrics measure held-out synthetic families and are not real-world detection accuracy.',
    }
    joblib.dump(pipeline, MODEL_PATH)
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
