import ipaddress
import re
from urllib.parse import urlsplit, unquote

def analyze_urls(urls, labels=None):
    output = []
    for url in urls:
        signals = []
        try:
            parsed = urlsplit(url); host = parsed.hostname or ''; port = parsed.port
            try:
                ipaddress.ip_address(host); signals.append('IP-based URL')
            except ValueError: pass
            if host in {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly'}: signals.append('URL shortener')
            if port and port not in (80,443): signals.append('Unusual port')
            if host.count('.') > 3: signals.append('Excessive subdomains')
            if re.search(r'login|verify|payment|secure|account|signin', unquote(parsed.path+'?'+parsed.query), re.I): signals.append('Sensitive action URL')
            if re.search(r'%[0-9a-f]{2}', url, re.I) or 'xn--' in host: signals.append('Encoded URL or internationalized domain')
            if parsed.username: signals.append('Misleading URL user information')
            if parsed.scheme == 'http': signals.append('Unencrypted HTTP')
            visible = [item['visible_text'].strip() for item in (labels or []) if item['url']==url and item['visible_text'].strip()]
            for label in visible:
                if label.startswith(('https://','http://')):
                    try:
                        if urlsplit(label).hostname != host: signals.append('Visible link domain differs from destination')
                    except ValueError: pass
            output.append({'url':url,'visible_text':visible or [url],'domain':host,'signals':list(dict.fromkeys(signals)),'redirect_status':'NOT FETCHED — active URL retrieval disabled for safety','final_destination':None})
        except ValueError:
            output.append({'url':url,'domain':None,'signals':['Malformed URL'],'redirect_status':'BLOCKED','final_destination':None})
    return output
