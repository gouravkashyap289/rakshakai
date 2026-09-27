import re
import ipaddress
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlsplit
import bleach

MAX_ITEMS = 80

def safe_filename(value):
    name = (value or 'email.eml').replace('\\', '/').rsplit('/', 1)[-1]
    return re.sub(r'[^\w. -]', '_', name)[:180] or 'email.eml'

class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(); self.text = []; self.urls = []; self.hidden = 0; self.links = []; self.anchor = None
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'): self.hidden += 1
        self.urls += [v for k, v in attrs if k in ('href', 'src', 'action', 'formaction', 'background', 'poster') and v]
        if tag == 'a': self.anchor = {'url':dict(attrs).get('href',''), 'visible_text':''}
    def handle_endtag(self, tag):
        if tag in ('script', 'style'): self.hidden = max(0, self.hidden - 1)
        if tag == 'a' and self.anchor:
            if len(self.links)<MAX_ITEMS: self.links.append(self.anchor)
            self.anchor = None
    def handle_data(self, data):
        if not self.hidden: self.text.append(data)
        if not self.hidden and self.anchor: self.anchor['visible_text'] = (self.anchor['visible_text']+data)[:500]

def parse_email(raw):
    if b'\x00' in raw[:4096]: raise ValueError('Invalid email: binary content in headers.')
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if not msg.get('From') or not any(msg.get(h) for h in ('To', 'Subject', 'Date')):
        raise ValueError('A valid .eml must contain From and at least one To, Subject, or Date header.')
    fields = {k.lower().replace('-', '_'): str(msg.get(k, ''))[:10000] for k in ['From','To','Cc','Reply-To','Return-Path','Subject','Date','Message-ID']}
    fields['received'] = [str(h)[:4000] for h in msg.get_all('Received', [])][:100]
    fields['authentication_results'] = [str(h)[:4000] for h in msg.get_all('Authentication-Results', [])][:30]
    fields['dkim_signatures'] = [str(h)[:4000] for h in msg.get_all('DKIM-Signature', [])][:10]
    # Some mail systems preserve a claimed client IP in a dedicated header.
    # Gmail normally omits it, particularly for messages sent from its apps/web UI.
    originating_headers = []
    for name in ('X-Originating-IP', 'X-Sender-IP', 'X-Client-IP', 'X-Source-IP'):
        for value in msg.get_all(name, []):
            originating_headers.append({'header': name, 'value': str(value)[:1000]})
    fields['originating_ip_headers'] = originating_headers[:20]
    text_parts, html_parts, attachments = [], [], []
    for i, part in enumerate(msg.walk()):
        if i > 300: raise ValueError('Email has too many MIME parts (maximum 300).')
        if part.is_multipart(): continue
        data = part.get_payload(decode=True) or b''
        if part.get_filename() or part.get_content_disposition() == 'attachment':
            attachments.append({'filename': safe_filename(part.get_filename() or 'unnamed'), 'mime_type': part.get_content_type(), 'data': data})
        elif part.get_content_type() in ('text/plain','text/html'):
            try: body = data.decode(part.get_content_charset() or 'utf-8', errors='replace')
            except LookupError: body = data.decode('utf-8', errors='replace')
            (text_parts if part.get_content_type() == 'text/plain' else html_parts).append(body[:250000])
    html = '\n'.join(html_parts)[:500000]
    parser = HTMLText(); parser.feed(html)
    fields['link_labels'] = parser.links
    body = '\n'.join(text_parts)[:500000] or ' '.join(parser.text)[:500000]
    # Analysis considers both MIME alternatives; neither is rendered as active HTML.
    analysis_text = body + '\n' + ' '.join(parser.text)[:500000]
    urls = sorted(set(u.rstrip('.,;)>]') for u in re.findall(r'https?://[^\s<>"\x27]+', fields['subject']+'\n'+analysis_text, re.I) + parser.urls if u.lower().startswith(('http://','https://'))))
    address_text = '\n'.join(str(fields[k]) for k in ('from','to','cc','reply_to','return_path')) + '\n' + body
    addresses = sorted(set(a.lower() for _, a in getaddresses([address_text]) if re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', a)))
    addresses += re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', address_text)
    addresses = sorted(set(addresses))[:MAX_ITEMS]
    domains = {a.rsplit('@',1)[1].lower().rstrip('.') for a in addresses}
    claimed_client_ip_text = '\n'.join(item['value'] for item in originating_headers)
    ip_text = re.sub(r'IPv6:', '', '\n'.join(fields['received']) + '\n' + claimed_client_ip_text + '\n' + analysis_text, flags=re.I)
    ip_candidates = re.findall(r'(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|[0-9a-fA-F]*:[0-9a-fA-F:]+', ip_text)
    for url in urls:
        try:
            host = urlsplit(url).hostname
            if host:
                try: ipaddress.ip_address(host); ip_candidates.append(host)
                except ValueError: domains.add(host.lower().rstrip('.'))
        except ValueError: pass
    ips = set()
    for candidate in ip_candidates:
        try:
            ip = ipaddress.ip_address(candidate)
            if ip.is_global: ips.add(str(ip))
        except ValueError: pass
    fields.update(body_text=body, analysis_text=analysis_text, html_body=bleach.clean(html, tags=['p','br','b','i','strong','em','ul','li'], attributes={}, strip=True), urls=urls[:MAX_ITEMS], domains=sorted(domains)[:MAX_ITEMS], email_addresses=addresses, ips=sorted(ips)[:MAX_ITEMS], attachments=attachments, truncated=len(urls)>MAX_ITEMS or len(domains)>MAX_ITEMS)
    return fields
