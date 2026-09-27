# Rakshak AI Model Card

**Model name:** Rakshak AI Email Content Classifier  
**Model version:** 2  
**Model artifact:** `backend/models/rakshak_tfidf_v2.joblib`  
**Model metadata:** `backend/models/rakshak_tfidf_v2.json`  
**Model-card date:** 16 September 2026  
**Status:** Research and SIH prototype; human review required

## Model summary

Rakshak AI is a local binary text classifier that estimates whether an email's subject and readable body resemble the combined **phishing or spam** class in its training corpus. The classifier is paired with deterministic language rules that identify explainable signals such as urgency, credential requests, OTP requests, payment instructions, invoice lures, threatening language, and secrecy or authority cues.

Rakshak AI is one part of the wider Rakshak email investigation pipeline. The final risk score also considers sender and domain evidence, authentication, links, attachments, and configured threat-intelligence sources. The model probability is therefore not the final risk score and is not the probability that an email is malicious or safe.

## Intended use

Rakshak AI is intended to:

- assist a user or analyst reviewing an uploaded `.eml` file;
- identify language commonly associated with phishing, spam, credential theft, OTP fraud, financial fraud, fake invoices, BEC, and social engineering;
- provide evidence sentences and deterministic signal labels;
- contribute to an explainable email risk assessment;
- prioritize emails for further verification or human review.

It is not intended to:

- automatically block, delete, quarantine, accuse, or attribute an email;
- identify the person who sent an email or determine their physical location;
- replace a malware sandbox, cryptographic verification, threat-intelligence service, or trained analyst;
- certify that an email is safe;
- make employment, financial, legal, policing, or other high-impact decisions without independent evidence and human review.

## Architecture

The active classifier uses:

- word TF-IDF features with 1–2 word n-grams;
- character TF-IDF features with 3–5 character n-grams;
- a class-balanced logistic-regression classifier;
- deterministic regular-expression rules for explainable content signals;
- fixed random seed `42` for reproducibility.

The word and character vectorizers each permit up to 18,000 features. Logistic regression uses `C=2`, `class_weight="balanced"`, and up to 1,500 iterations.

The default application does not call a hosted LLM. An optional locally stored transformer can be configured with `RAKSHAK_MODEL_PATH`, but no transformer evaluation is claimed by this card. If that model is missing or has incompatible labels, the application continues with the scikit-learn classifier.

## Inputs and outputs

**Input:** The decoded email subject and readable plain-text/HTML-derived body. Active HTML is never rendered by the classifier.

Before inference, URLs, email addresses, phone-like values, and long numeric identifiers are replaced with placeholder tokens. Whitespace is normalized, and model input is limited to 12,000 characters.

The classifier returns:

- a binary phishing-or-spam probability;
- a model certainty value equal to the larger class probability;
- detected deterministic signals and their evidence sentences;
- a rule-based threat category;
- a short explanation and engine status.

Threat categories are assigned by deterministic rules. They currently include:

- Financial / OTP Fraud;
- Credential Phishing;
- Business Email Compromise;
- Invoice / Financial Fraud;
- Social Engineering;
- No strong content threat.

## Training data

The active model was trained from the public Hugging Face dataset `puyang2025/seven-phishing-email-datasets`.

The reproducible sample contains 1,000 emails:

| Split | Benign | Phishing or spam | Total |
|---|---:|---:|---:|
| Training | 400 | 400 | 800 |
| Test | 100 | 100 | 200 |
| Total | 500 | 500 | 1,000 |

Source collections represented in the sample are Assassin, CEAS-08, Enron, Ling, TREC-05, TREC-06, and TREC-07. The script uses the dataset's official train and test splits and removes exact normalized duplicates across those splits.

For privacy reduction, email addresses, URLs, phone-like values, and long numeric identifiers were replaced before the sampled data was stored and used for training. This reduces exposure but does not constitute a formal anonymization guarantee.

## Evaluation

Evaluation was performed once on the balanced 200-message held-out test sample.

| Metric | Result |
|---|---:|
| Accuracy | 93.50% |
| Positive-class precision | 93.94% |
| Positive-class recall | 93.00% |
| Positive-class F1 | 93.47% |

Confusion matrix, with rows as actual classes and columns as predicted classes:

|  | Predicted benign | Predicted phishing/spam |
|---|---:|---:|
| Actual benign | 94 | 6 |
| Actual phishing/spam | 7 | 93 |

These measurements are development results on a small, balanced public-corpus sample. They are **not production accuracy**, and they do not measure phishing-only performance. The probability output has not been calibrated against real-world prevalence.

## How the model contributes to the Rakshak score

Rakshak uses a versioned three-pillar risk policy:

| Pillar | Maximum contribution |
|---|---:|
| AI Text Analysis | 40 |
| Sender & Domain Reputation | 35 |
| Urgent Actions, Links & Attachments | 25 |

For the AI pillar, the system calculates model points from the classifier probability and rule points from deterministic content signals. It uses the stronger of the two values rather than adding them, which limits double-counting of the same textual evidence.

The final score is an evidence-weighted risk score:

- Low: 0–30;
- Medium: 31–70;
- High: 71–100.

Evidence coverage is calculated separately. Missing authentication, registration, geolocation, or reputation evidence can reduce coverage but does not automatically add risk.

## Explainability

For each contributing finding, Rakshak records:

- the scoring pillar;
- the points contributed;
- the detected signal;
- the evidence source;
- the supporting sentence or technical evidence.

This makes the displayed total reproducible from the visible contributions. Correlated findings are capped within their pillar so the total cannot exceed 100.

## Limitations and known risks

- The positive label combines phishing and spam, so model probability is not phishing-only probability.
- The evaluation sample is small and artificially balanced; live email prevalence and error rates will differ.
- The public source collections include older email, creating possible vocabulary and campaign drift.
- Performance has not been independently measured by language, region, provider, brand, attack type, or demographic group.
- Probability calibration, adversarial robustness, obfuscation resistance, and multilingual performance have not been validated.
- Benign security training, legitimate payment messages, and urgent business communication may resemble attack language.
- Sophisticated phishing with neutral wording may evade content analysis.
- Rules may miss spelling variants, new social-engineering language, or context-dependent intent.
- Header, domain, IP, attachment, and threat-intelligence checks are separate components and can be unavailable or inconclusive.
- A low score does not guarantee safety, and a high score does not prove malicious intent.

## Safety and operational controls

- The model runs locally and does not send message text to an external LLM.
- Uploaded attachments are hashed and inspected statically; they are never executed.
- Unsafe email HTML is not rendered directly.
- Model output is combined with deterministic and technical evidence.
- Unknown data remains `UNKNOWN`, `DATA NOT AVAILABLE`, `API NOT CONFIGURED`, or `LOOKUP FAILED` rather than being fabricated.
- The interface and PDF report state that human review and independent sender verification may be required.

## Reproducibility and maintenance

Training is implemented in `backend/training/train_real_classifier.py`. Running that script with the same accessible dataset and seed rebuilds the sampled corpus, model artifact, and evaluation metadata. Upstream dataset changes can still change the resulting sample and should trigger a new model version and evaluation review.

Recommended work before production deployment:

1. create a recent, phishing-specific, deduplicated evaluation set that is isolated from training;
2. measure performance by threat type, language, provider, and time period;
3. calibrate predicted probabilities and select thresholds using expected live prevalence and error costs;
4. perform adversarial and obfuscation testing;
5. add drift monitoring, model version tracking, rollback, and periodic human review;
6. review upstream dataset licenses and retention requirements before redistribution or commercial use.

## Responsible contact

This model is part of the Rakshak SIH prototype. Findings should be reviewed through the Rakshak evidence panel and retained with the case report when used in an investigation.
