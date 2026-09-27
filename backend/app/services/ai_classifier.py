"""Transparent prototype classifier. Training examples are synthetic, not a validation set."""
import os
import re
import json
from pathlib import Path
from functools import lru_cache
import joblib
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

RULES = [
 ('Urgency', r'\b(urgent|immediately|within \d+ hours|act now|today only|asap)\b', 3),
 ('Account suspension', r'\b(suspend\w*|deactivat\w*|account (?:will be|is) (?:closed|locked)|lose access)\b', 5),
 ('Credential request', r'\b(password|credentials|sign in|log[ -]?in|verify your account)\b', 7),
 ('OTP request', r'\b(otp|one.time (?:password|code)|verification code)\b', 8),
 ('Payment instructions', r'\b(wire transfer|bank (?:account|details?|derails?)|payment details?|transfer (?:the )?(?:funds|money)|gift cards?|send (?:me )?(?:money|funds|\d[\d,]*\s*(?:rupees?|inr|usd|dollars?))|beneficiary|\d[\d,]*\s*(?:rupees?|inr|usd|dollars?))\b', 6),
 ('Invoice lure', r'\b(invoice|overdue payment|unpaid bill)\b', 3),
 ('Secrecy / authority', r'\b(confidential|do not (?:call|tell)|ceo|chief executive|keep this between|in a meeting)\b', 5),
 ('Threatening language', r'\b(legal action|arrest|penalty|unauthorized access|security breach)\b', 3),
 ('Brand reference', r'\b(paypal|microsoft|amazon|google|apple)\b', 1),
]
TRAINING = [
 ('Please verify your account password immediately or your account will be suspended',1),
 ('Urgent sign in to restore access to your Microsoft account',1),
 ('Send your OTP verification code now to prevent account suspension',1),
 ('Confidential CEO request wire transfer funds to new bank account today',1),
 ('Please pay this overdue invoice using our changed payment details',1),
 ('Your PayPal account is locked click login and confirm your credentials',1),
 ('Buy gift cards urgently I am in a meeting do not call me',1),
 ('Security breach verify your password or face legal action',1),
 ('Attached is the agenda for our team meeting tomorrow',0),
 ('Thanks for your help the project notes are ready for review',0),
 ('Your order has shipped delivery is scheduled for Friday',0),
 ('Here is the monthly newsletter and community update',0),
 ('The invoice was paid yesterday thank you for your business',0),
 ('Never share your password or verification code with anyone',0),
 ('Lunch at noon in the cafeteria see you there',0),
 ('Meeting minutes attached no action is required',0),
]

MODEL_PATH = Path(__file__).resolve().parents[2] / 'models' / 'rakshak_tfidf_v2.joblib'
METADATA_PATH = MODEL_PATH.with_suffix('.json')

@lru_cache(maxsize=1)
def model():
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    pipe = make_pipeline(TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True), LogisticRegression(C=3, random_state=42))
    pipe.fit([x for x,y in TRAINING], [y for x,y in TRAINING])
    return pipe

@lru_cache(maxsize=1)
def model_metadata():
    if METADATA_PATH.exists():
        try:
            return json.loads(METADATA_PATH.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            pass
    return {'total_examples':len(TRAINING),'training_examples':len(TRAINING),'corpus_type':'small synthetic fallback corpus'}

@lru_cache(maxsize=1)
def transformer():
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    path = os.environ['RAKSHAK_MODEL_PATH']
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(path, local_files_only=True, trust_remote_code=False, use_safetensors=True)
    return pipeline('text-classification', model=model, tokenizer=tokenizer)

def model_text(text):
    """Apply the same privacy-preserving normalization used during training."""
    text = re.sub(r'https?://\S+|www\.\S+', ' URLTOKEN ', text, flags=re.I)
    text = re.sub(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b', ' EMAILTOKEN ', text)
    text = re.sub(r'\b(?:\+?\d[\d ().-]{7,}\d)\b', ' PHONETOKEN ', text)
    text = re.sub(r'\b\d{6,}\b', ' NUMBERTOKEN ', text)
    return re.sub(r'\s+', ' ', text).strip()[:12000]

def classify(subject, body):
    text = (subject + '\n' + body)[:50000]
    sentences = re.split(r'(?<=[.!?])\s+|\n+', text)
    signals = []
    for name, pattern, weight in RULES:
        evidence = [s[:500] for s in sentences if re.search(pattern,s,re.I) and not re.search(r'\b(never share|do not share|don.t share)\b',s,re.I)][:3]
        if evidence: signals.append({'signal':name,'evidence':evidence,'weight':weight,'source':'subject / body'})
    from .multilingual import inspect
    local_signals, language = inspect(text)
    for signal in local_signals:
        existing = next((s for s in signals if s['signal']==signal['signal']),None)
        if existing: existing['evidence'] = list(dict.fromkeys(existing['evidence']+signal['evidence']))[:3]
        else: signals.append(signal)
    probability = float(model().predict_proba([model_text(text)])[0][1])
    metadata = model_metadata()
    engine = 'Rakshak TF-IDF + logistic regression + deterministic rules'
    model_status = (f"Model trained with {metadata['training_examples']} of "
                    f"{metadata['total_examples']} {metadata['corpus_type']} examples; "
                    'positive labels include phishing and spam, and probability is not calibrated production accuracy.')
    if os.getenv('RAKSHAK_MODEL_PATH'):
        try:
            result = transformer()(text[:4000], truncation=True)[0]
            label = result['label'].lower()
            if label not in ('phishing','benign'): raise ValueError('Model labels must be phishing and benign')
            probability = result['score'] if label == 'phishing' else 1-result['score']
            engine = 'Local transformer + deterministic rules'
            model_status = 'Local model probability; validate calibration before operational use.'
        except Exception:
            model_status += ' Transformer unavailable or invalid labels; scikit-learn fallback active.'
    names = {s['signal'] for s in signals}
    category = 'No strong content threat'
    if 'Payment instructions' in names and 'OTP request' in names: category = 'Financial / OTP Fraud'
    elif 'Credential request' in names or 'OTP request' in names: category = 'Credential Phishing'
    elif 'Payment instructions' in names and 'Secrecy / authority' in names: category = 'Business Email Compromise'
    elif 'Invoice lure' in names and ('Urgency' in names or 'Payment instructions' in names): category = 'Invoice / Financial Fraud'
    elif len(names) >= 2: category = 'Social Engineering'
    if not language['model_applicable']:
        model_status += ' Multilingual phrase rules active; English probability excluded from risk for this message.'
    return {'engine':engine, 'model_status':model_status, 'language':language, 'probability':round(probability,4), 'confidence':round(100*max(probability,1-probability),1) if language['model_applicable'] else None, 'category':category,'signals':signals, 'explanation':f'{len(signals)} content signals detected. Rules determine the category; model probability supplements risk where supported. Human review is required.'}
