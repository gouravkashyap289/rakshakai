"""Email-controlled URLs are never fetched. Outbound HTTP is restricted to provider hosts."""
import re
import ipaddress
from urllib.parse import urlsplit
import httpx

ALLOWED_HOSTS = {'www.virustotal.com','api.abuseipdb.com','urlhaus-api.abuse.ch','otx.alienvault.com','rdap.verisign.com','rdap.publicinterestregistry.org','rdap.nixiregistry.in'}

def public_ip(value):
    try: return ipaddress.ip_address(value).is_global
    except ValueError: return False

def public_domain(value):
    try: host=value.rstrip('.').encode('idna').decode().lower()
    except (UnicodeError,AttributeError): return False
    if len(host)>253 or '.' not in host: return False
    if host in {'example.com','example.net','example.org'} or any(host==s or host.endswith('.'+s) for s in ['localhost','local','internal','test','invalid','example','onion','home','lan']): return False
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')): return False
    try: ipaddress.ip_address(host); return False
    except ValueError: return not host.rsplit('.',1)[-1].isdigit()

def provider_json(url, method='GET', **kwargs):
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.hostname not in ALLOWED_HOSTS or parsed.port not in (None,443) or parsed.username:
        raise ValueError('Outbound endpoint is not allowlisted.')
    with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
        with client.stream(method,url,**kwargs) as response:
            response.raise_for_status()
            content=bytearray()
            for block in response.iter_bytes():
                content.extend(block)
                if len(content)>2*1024*1024: raise ValueError('Provider response too large.')
            import json
            return json.loads(content)
