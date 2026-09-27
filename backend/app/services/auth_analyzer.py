import re
from ..config import TRUSTED_AUTHSERV

def analyze_auth(email):
    results = {}
    for method in ('spf','dkim','dmarc'):
        reported, trusted = [], []
        for header in email['authentication_results']:
            values = re.findall(r'\b' + method + r'=(pass|fail|softfail|neutral|none|temperror|permerror)\b', header, re.I)
            reported.extend(values)
            server = header.split(';',1)[0].strip().lower()
            if server in TRUSTED_AUTHSERV: trusted.extend(values)
        def state(values):
            if values and all(v.lower() == 'pass' for v in values): return 'PASS'
            if values and all(v.lower() == 'fail' for v in values): return 'FAIL'
            return 'UNKNOWN'
        status = state(trusted)
        results[method.upper()] = {'status': status, 'reported_status': state(reported), 'source': 'trusted Authentication-Results' if trusted else 'untrusted uploaded headers', 'explanation': 'Receiver reported authentication success.' if status == 'PASS' else ('Receiver reported authentication failure or alignment failure.' if status == 'FAIL' else 'No trusted receiver result is available. Uploaded headers alone cannot prove authentication.'), 'evidence': email['authentication_results']}
    return results
