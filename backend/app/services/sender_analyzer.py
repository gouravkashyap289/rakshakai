from email.utils import parseaddr
import re

BRANDS = {'paypal':'paypal.com', 'microsoft':'microsoft.com', 'google':'google.com', 'amazon':'amazon.com', 'apple':'apple.com'}
def domain(address):
    addr = parseaddr(address)[1]
    return addr.rsplit('@',1)[-1].lower() if '@' in addr else ''

def aligned(first, second):
    """Treat a domain and its subdomains as aligned for sender comparison."""
    return bool(first and second and (first == second or first.endswith('.'+second) or second.endswith('.'+first)))

def analyze_sender(email):
    domains = {k: domain(email[k]) for k in ('from','reply_to','return_path')}
    signals = []
    for key, title in [('reply_to','Reply-To domain mismatch'), ('return_path','Return-Path domain mismatch')]:
        if domains[key] and domains['from'] and not aligned(domains[key],domains['from']):
            signals.append({'signal': title, 'evidence': f"From: {domains['from']}; {key}: {domains[key]}", 'source': key, 'weight': 7 if key == 'reply_to' else 4})
    name = parseaddr(email['from'])[0].lower()
    recipient_domain=domain(email['to'])
    if re.search(r'\b(ceo|chief executive|managing director)\b',name) and recipient_domain and domains['from']!=recipient_domain and re.search(r'wire transfer|gift cards|transfer funds|beneficiary',email.get('body_text',''),re.I):
        signals.append({'signal':'External executive identity claim with payment request','evidence':f"Display name {name} uses {domains['from']} while requesting payment from {recipient_domain}; verify executive identity independently.",'source':'From / To / body','weight':8})
    for brand, official in BRANDS.items():
        if brand in name and not (domains['from'] == official or domains['from'].endswith('.'+official)):
            signals.append({'signal': 'Possible display-name impersonation', 'evidence': f'{name} uses {domains["from"]}, rather than {official}. This may also be an authorized service.', 'source':'From', 'weight':8})
    return {'domains': domains, 'signals': signals}
