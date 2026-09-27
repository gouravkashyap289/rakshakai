"""Opt-in HEAD-only redirects with public-IP pinning on every hop."""
import http.client
import ipaddress
import os
import socket
import ssl
import time
from urllib.parse import urlsplit, urljoin
import dns.resolver

def public_addresses(host):
    try: addresses=[str(ipaddress.ip_address(host))]
    except ValueError:
        addresses=[]
        for kind in ('A','AAAA'):
            try: addresses += [str(v) for v in dns.resolver.resolve(host,kind,lifetime=2)]
            except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN): pass
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('Private, local, or unavailable destination blocked.')
    return addresses

class PinnedTLS(http.client.HTTPSConnection):
    def __init__(self,host,address,port):
        super().__init__(host,port,timeout=3,context=ssl.create_default_context())
        self.address=address
    def connect(self):
        sock=socket.create_connection((self.address,self.port),self.timeout)
        try: self.sock=self._context.wrap_socket(sock,server_hostname=self.host)
        except Exception: sock.close();raise

def preview(url):
    if os.getenv('ENABLE_URL_REDIRECT_CHECKS','false').lower()!='true':
        return {'status':'DISABLED','hops':[],'final_destination':None}
    hops=[];seen=set();deadline=time.monotonic()+18
    try:
        for _ in range(5):
            if len(url)>4096 or any(ord(c)<32 or ord(c)==127 for c in url): raise ValueError('Invalid URL.')
            p=urlsplit(url)
            if p.scheme not in ('https','http') or not p.hostname or p.username or p.password: raise ValueError('Unsupported URL.')
            host=p.hostname.encode('idna').decode('ascii')
            if host.endswith(('.local','.localhost','.internal')) or host=='localhost': raise ValueError('Internal hostname blocked.')
            port=p.port or (443 if p.scheme=='https' else 80)
            if port != (443 if p.scheme=='https' else 80): raise ValueError('Nonstandard port blocked.')
            if url in seen: raise ValueError('Redirect loop.')
            if time.monotonic()>deadline: raise ValueError('Redirect time budget reached.')
            seen.add(url)
            address=public_addresses(host)[0]
            connection=PinnedTLS(host,address,port) if p.scheme=='https' else http.client.HTTPConnection(address,port,timeout=3)
            try:
                target=(p.path or '/')+('?' + p.query if p.query else '')
                connection.request('HEAD',target,headers={'Host':'['+host+']' if ':' in host else host,'User-Agent':'Rakshak-Redirect-Preview/1.0','Connection':'close'})
                response=connection.getresponse()
                hops.append({'url':url,'status_code':response.status})
                location=response.getheader('Location')
                if response.status in (301,302,303,307,308) and location:
                    url=urljoin(url,location);continue
                return {'status':'OBSERVED' if response.status<400 else 'DESTINATION REJECTED HEAD','hops':hops,'final_destination':url,'note':'HEAD response only; no page or file content fetched. This is not a safety verdict.'}
            finally: connection.close()
        return {'status':'HOP LIMIT REACHED','hops':hops,'final_destination':None}
    except (ValueError,OSError,http.client.HTTPException,dns.exception.DNSException):
        return {'status':'BLOCKED OR LOOKUP FAILED','hops':hops,'final_destination':None}
