import os
import base64
import ipaddress
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit
from concurrent.futures import ThreadPoolExecutor
from .network import provider_json, public_domain, public_ip
from ..config import NETWORK_ENABLED

PROVIDERS={'VirusTotal':'VIRUSTOTAL_API_KEY','AbuseIPDB':'ABUSEIPDB_API_KEY','URLhaus':'URLHAUS_API_KEY','AlienVault OTX':'OTX_API_KEY'}

def lookup(provider,kind,value,enabled=None):
    enabled=NETWORK_ENABLED if enabled is None else enabled
    key=os.getenv(PROVIDERS[provider])
    row={'provider':provider,'type':kind,'indicator':value,'status':'DATA NOT AVAILABLE','malicious':None,'details':{},'queried_at':None}
    if not key: return {**row,'configuration':'API NOT CONFIGURED','reason':'API key is not configured.'}
    if not enabled: return {**row,'configuration':'CONFIGURED','reason':'Network enrichment disabled.'}
    if provider=='AbuseIPDB' and kind!='ip': return {**row,'reason':'Provider supports public IPs only.'}
    if kind=='domain' and not public_domain(value): return {**row,'reason':'Reserved or local indicator; external lookup blocked.'}
    if kind=='ip' and not public_ip(value): return {**row,'reason':'Non-public IP; lookup blocked.'}
    if kind=='url':
        try:
            host=urlsplit(value).hostname
            if not host or not (public_domain(host) or public_ip(host)): return {**row,'reason':'Non-public URL; lookup blocked.'}
        except ValueError: return {**row,'reason':'Malformed URL.'}
    row['queried_at']=datetime.now(timezone.utc).isoformat()
    try:
        if provider=='VirusTotal':
            resource={'domain':'domains','ip':'ip_addresses','url':'urls','hash':'files'}[kind]
            identifier=base64.urlsafe_b64encode(value.encode()).decode().rstrip('=') if kind=='url' else value
            data=provider_json('https://www.virustotal.com/api/v3/'+resource+'/'+quote(identifier,safe=''),headers={'x-apikey':key})
            stats=data['data']['attributes'].get('last_analysis_stats')
            if not stats: return {**row,'reason':'No analysis statistics returned.'}
            row.update(status='AVAILABLE',malicious=stats.get('malicious',0)>0,details={'analysis_stats':stats,'interpretation':'Engine verdict counts; zero detections do not prove safety.'})
        elif provider=='AbuseIPDB':
            data=provider_json('https://api.abuseipdb.com/api/v2/check',params={'ipAddress':value,'maxAgeInDays':90},headers={'Key':key,'Accept':'application/json'})['data']
            confidence=data.get('abuseConfidenceScore')
            if confidence is None: return {**row,'reason':'No abuse score returned.'}
            row.update(status='AVAILABLE',malicious=confidence>=75,details={k:data.get(k) for k in ['abuseConfidenceScore','totalReports','countryCode','isp','usageType','isTor']})
            row['details']['policy']='75+ abuse confidence is treated as a high reputation signal; lower values remain review context.'
        elif provider=='URLhaus':
            endpoint='url' if kind=='url' else ('payload' if kind=='hash' else 'host')
            field='url' if kind=='url' else ('sha256_hash' if kind=='hash' else 'host')
            data=provider_json('https://urlhaus-api.abuse.ch/v1/'+endpoint+'/',method='POST',data={field:value},headers={'Auth-Key':key})
            status=data.get('query_status')
            if status=='no_results': return {**row,'status':'AVAILABLE','malicious':False,'details':{'query_status':status,'interpretation':'No record found; not a safety verdict.'}}
            if status!='ok': return {**row,'status':'LOOKUP FAILED','reason':'Provider did not return a valid result.'}
            row.update(status='AVAILABLE',malicious=True,details={k:data[k] for k in ['query_status','url_status','threat','date_added','tags','url_count'] if k in data})
        else:
            indicator_type={'domain':'domain','ip':('IPv6' if ':' in value else 'IPv4'),'url':'url','hash':'file'}[kind]
            data=provider_json('https://otx.alienvault.com/api/v1/indicators/'+indicator_type+'/'+quote(value,safe='')+'/general',headers={'X-OTX-API-KEY':key})
            pulses=data.get('pulse_info',{}).get('count')
            if pulses is None: return {**row,'reason':'No pulse context returned.'}
            row.update(status='AVAILABLE',malicious=None,details={'pulse_count':pulses,'interpretation':'Pulse membership is contextual evidence, not a maliciousness verdict.'})
    except Exception:
        row.update(status='LOOKUP FAILED',reason='Provider request failed, was rate limited, or returned unusable data.')
    return row

def analyze_intel(domains,ips,urls,attachments):
    # Prefer URL/sender infrastructure in the bounded query budget; no files or email bodies are submitted.
    indicators=[('url',u['url']) for u in urls]+[('domain',d['domain']) for d in domains]+[('ip',i['ip']) for i in ips]+[('hash',a['sha256']) for a in attachments]
    indicators=list(dict.fromkeys(indicators))
    tasks=[(p,k,v) for k,v in indicators[:10] for p in PROVIDERS if not(p=='AbuseIPDB' and k!='ip')]
    if not tasks: return [{ 'provider':p,'type':'none','indicator':'No eligible indicator','status':'DATA NOT AVAILABLE','malicious':None,'configuration':'CONFIGURED' if os.getenv(env) else 'API NOT CONFIGURED','reason':'No indicator to query.'} for p,env in PROVIDERS.items()]
    with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(lambda task:lookup(*task),tasks))
    for k,v in indicators[10:]: results.append({'provider':'Query budget','type':k,'indicator':v,'status':'DATA NOT AVAILABLE','malicious':None,'reason':'Maximum 10 indicators per investigation.'})
    return results
