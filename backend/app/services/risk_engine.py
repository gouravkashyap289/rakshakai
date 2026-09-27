"""Explainable three-pillar hybrid email threat scoring policy."""

CAPS = {
    'AI Text Analysis': 40,
    'Sender & Domain Reputation': 35,
    'Urgent Actions, Links & Attachments': 25,
}


def score(auth, sender, ai, urls, domains, attachments, intel):
    scores = {key: 0 for key in CAPS}
    evidence = []
    correlations = []

    def add(category, points, title, source, detail):
        contribution = min(max(0, int(round(points))), CAPS[category] - scores[category])
        if contribution:
            scores[category] += contribution
            evidence.append({
                'category': category,
                'contribution': contribution,
                'signal': title,
                'source': source,
                'evidence': detail,
            })

    # Pillar 1: AI text assessment. The rule score and model score describe the
    # same content, so the stronger one is used instead of adding both.
    meaningful_signals = [item for item in ai.get('signals', []) if item.get('signal') != 'Brand reference']
    signal_names = {item.get('signal') for item in meaningful_signals}
    model_applicable = ai.get('language',{}).get('model_applicable', True)
    model_points = round(float(ai.get('probability', 0)) * CAPS['AI Text Analysis']) if model_applicable else 0
    rule_points = min(CAPS['AI Text Analysis'], 2 * sum(int(item.get('weight', 0)) for item in meaningful_signals))
    ai_points = max(model_points, rule_points)
    if ai_points:
        signal_summary = ', '.join(sorted(signal_names)) or 'No deterministic language rule matched'
        add(
            'AI Text Analysis', ai_points, 'AI and language threat assessment', 'Rakshak AI',
            (f"Model phishing/spam probability {ai.get('probability', 0):.1%} -> {model_points}/40; " if model_applicable else 'English model probability excluded for this language; ')+
            f"deterministic language score {rule_points}/40; stronger value used to avoid double-counting. "
            f"Signals: {signal_summary}.",
        )

    # Pillar 2: sender identity, domain history, and trusted authentication.
    failures = [key for key, value in auth.items() if value.get('status') == 'FAIL']
    if failures:
        add('Sender & Domain Reputation', 10, 'Trusted authentication failure', 'Authentication-Results',
            ', '.join(failures) + ' failed. Related authentication failures are counted once.')

    lookalikes = [item for item in domains if item.get('lookalike')]
    if lookalikes:
        add('Sender & Domain Reputation', 20, 'Lookalike brand domain', 'Domain similarity',
            '; '.join(item['domain'] + ' resembles ' + item['lookalike'] for item in lookalikes))

    new_domains = [item for item in domains if isinstance(item.get('age_days'), int) and item['age_days'] < 30]
    if new_domains:
        add('Sender & Domain Reputation', 15, 'Newly registered domain', 'RDAP registration data',
            '; '.join(f"{item['domain']} is {item['age_days']} days old" for item in new_domains))

    for item in sorted(sender.get('signals', []), key=lambda value: -value.get('weight', 0)):
        if lookalikes and 'display-name' in item.get('signal', '').lower():
            continue
        add('Sender & Domain Reputation', item.get('weight', 0), item.get('signal', 'Sender mismatch'),
            item.get('source', 'Sender headers'), item.get('evidence', ''))

    # Pillar 3: dangerous requested actions, suspicious links, reputation, and files.
    url_signals = sorted({signal for item in urls for signal in item.get('signals', [])})
    if url_signals:
        add('Urgent Actions, Links & Attachments', 15, 'Suspicious link characteristics', 'URL analysis',
            ', '.join(url_signals))

    confirmed = [item for item in intel if item.get('malicious') is True]
    if confirmed:
        add('Urgent Actions, Links & Attachments', 15, 'Confirmed malicious reputation', 'Threat intelligence',
            '; '.join(item.get('provider', 'Provider') + ': ' + item.get('indicator', 'UNKNOWN') for item in confirmed))

    warnings = sorted({signal for item in attachments for signal in item.get('signals', [])})
    if warnings:
        dangerous = any('executable' in signal.lower() or 'double extension' in signal.lower() for signal in warnings)
        add('Urgent Actions, Links & Attachments', 10 if dangerous else 5, 'Attachment static warning',
            'Attachment metadata', '; '.join(warnings) + '; type alone does not establish maliciousness.')

    action_points = 0
    action_reason = ''
    if 'Payment instructions' in signal_names and 'OTP request' in signal_names:
        action_points = 10
        action_reason = 'Payment or bank-detail request combined with an OTP request'
    elif 'Payment instructions' in signal_names and 'Urgency' in signal_names:
        action_points = 8
        action_reason = 'Payment request combined with urgent language'
    elif ('Credential request' in signal_names or 'OTP request' in signal_names) and 'Urgency' in signal_names:
        action_points = 6
        action_reason = 'Credential or OTP request combined with urgent language'
    if action_points:
        correlations.append(action_reason)
        add('Urgent Actions, Links & Attachments', action_points, 'Correlated high-risk action',
            'Cross-signal correlation', action_reason)

    if lookalikes and ('Credential request' in signal_names or 'OTP request' in signal_names) and url_signals:
        reason = 'Lookalike domain combined with a credential request and suspicious link'
        correlations.append(reason)
        add('Urgent Actions, Links & Attachments', 10, 'Correlated phishing pattern',
            'Cross-signal correlation', reason)

    total = sum(scores.values())
    level = 'High' if total >= 71 else 'Medium' if total >= 31 else 'Low'

    known_auth = sum(value.get('status') != 'UNKNOWN' for value in auth.values()) / 3
    known_domains = sum(item.get('status') == 'AVAILABLE' for item in domains) / max(1, len(domains))
    known_intel = sum(item.get('status') == 'AVAILABLE' for item in intel) / max(1, len(intel))
    consistency = (1 if (total >= 31) == (ai.get('probability', 0) >= .5) else .4) if model_applicable else 0
    confidence = round(20 + 20 * known_auth + 15 * known_domains + 20 * known_intel
                       + (15 * max(ai.get('probability', 0), 1 - ai.get('probability', 0)) if model_applicable else 0) + 10 * consistency)
    return {
        'risk_score': total,
        'risk_level': level,
        'category_scores': scores,
        'category_caps': CAPS,
        'evidence': evidence,
        'correlations': correlations,
        'confidence': confidence,
        'confidence_explanation': (
            'Evidence coverage index, separate from risk: authentication, domain and intelligence availability, '
            'model certainty, and agreement. Missing evidence lowers coverage and never adds risk.'
        ),
    }
