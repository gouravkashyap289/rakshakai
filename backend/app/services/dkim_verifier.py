"""Optional cryptographic verification against current public DNS; separate from imported claims."""
import dns.resolver
from .network import public_domain

def verify_dkim(raw):
    failures=[]
    def dnsfunc(name,timeout=2):
        value=name.decode().rstrip('.') if isinstance(name,bytes) else str(name).rstrip('.')
        signing_domain=value.split('._domainkey.',1)[-1]
        if '._domainkey.' not in value or not public_domain(signing_domain): failures.append('Reserved or invalid signing domain');return b''
        try:
            answer=dns.resolver.resolve(value,'TXT',lifetime=2,search=False)
            return b''.join(answer[0].strings)
        except Exception: failures.append('Signing key lookup failed');return b''
    try:
        import dkim
        valid=dkim.verify(raw,dnsfunc=dnsfunc)
        status='UNKNOWN' if failures else ('PASS' if valid else 'FAIL')
        return {'status':status,'source':'dkimpy cryptographic verification against current DNS','explanation':'; '.join(failures) if failures else ('DKIM signature verified.' if valid else 'DKIM signature did not verify. Message modification or invalid signing data can cause failure.')}
    except ImportError: return {'status':'UNKNOWN','source':'dkimpy','explanation':'DKIM verification library unavailable.'}
    except Exception: return {'status':'UNKNOWN','source':'dkimpy','explanation':'DKIM verification could not be completed.'}
