from datetime import datetime, timezone
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
import dns.resolver
from .network import public_domain, provider_json
from .sender_analyzer import BRANDS
from ..config import NETWORK_ENABLED

def levenshtein(a,b):
    row=list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        new=[i]
        for j,cb in enumerate(b,1): new.append(min(new[-1]+1,row[j]+1,row[j-1]+(ca!=cb)))
        row=new
    return row[-1]

def similarity(host):
    host=host.lower().rstrip('.')
    labels=host.split('.')
    for brand,official in BRANDS.items():
        if host==official or host.endswith('.'+official): continue
        for label in labels[:-1]:
            normalized=label.translate(str.maketrans({'0':'o','1':'l','3':'e','5':'s','7':'t'}))
            candidate=normalized
            for suffix in ('-login','-secure','-account','-verify','-support','-payments'):
                candidate=candidate.replace(suffix,'')
            distance=levenshtein(candidate,brand)
            ratio=SequenceMatcher(None,candidate,brand).ratio()
            if distance<=1 or (brand in candidate and any(s in label for s in ('login','secure','account','verify'))) or ratio>=.86:
                return {'lookalike':official,'similarity':round(ratio*100,1),'edit_distance':distance,'similarity_reason':f'Label {label} normalizes to {candidate}; resembles {brand}. Similarity is a heuristic, not proof of impersonation.'}
    return {'lookalike':None,'similarity':None,'edit_distance':None,'similarity_reason':'No configured brand match.'}

def analyze_domain(host, enabled=None):
    enabled=NETWORK_ENABLED if enabled is None else enabled
    result={'domain':host,**similarity(host),'status':'DATA NOT AVAILABLE','dns':{},'rdap_status':'DATA NOT AVAILABLE','registrar':None,'registrant_organization':None,'registrant_country':None,'creation_date':None,'age_days':None,'nameservers':[],'reputation':'DATA NOT AVAILABLE'}
    if not enabled or not public_domain(host):
        result['reason']='Network enrichment disabled.' if not enabled else 'Reserved, local, or invalid domain; no external query.'
        return result
    resolver=dns.resolver.Resolver(); resolver.lifetime=2; resolver.timeout=1
    for kind in ('A','AAAA','MX','NS','TXT'):
        try:
            values=[r.to_text()[:1000] for r in resolver.resolve(host,kind,lifetime=2,search=False)][:20]
            result['dns'][kind]={'status':'AVAILABLE','values':values}; result['status']='AVAILABLE'
            if kind=='NS': result['nameservers']=values
        except dns.resolver.NoAnswer: result['dns'][kind]={'status':'NO RECORD','values':[]}
        except dns.resolver.NXDOMAIN:
            result['dns'][kind]={'status':'NXDOMAIN','values':[]}
        except Exception: result['dns'][kind]={'status':'LOOKUP FAILED','values':[]}
    if result['status']!='AVAILABLE': result['status']='LOOKUP FAILED'
    parts=host.split('.'); tld=parts[-1]; registered='.'.join(parts[-2:])
    bases={'com':'https://rdap.verisign.com/com/v1/domain/','net':'https://rdap.verisign.com/net/v1/domain/','org':'https://rdap.publicinterestregistry.org/rdap/domain/','in':'https://rdap.nixiregistry.in/rdap/domain/'}
    if tld in bases:
        try:
            data=provider_json(bases[tld]+quote(registered,safe=''))
            result['rdap_status']='AVAILABLE'
            result['rdap_source']=bases[tld]+registered
            for event in data.get('events',[]):
                if event.get('eventAction')=='registration':
                    value=event.get('eventDate'); date=datetime.fromisoformat(value.replace('Z','+00:00'))
                    result['creation_date']=value; result['age_days']=max(0,(datetime.now(timezone.utc)-date).days)
            for entity in data.get('entities',[]):
                roles=entity.get('roles',[])
                cards=entity.get('vcardArray',[None,[]])
                fields=cards[1] if isinstance(cards,list) and len(cards)>1 else []
                if 'registrar' in roles:
                    result['registrar']=next((v[3] for v in fields if v[0]=='fn' and v[3]),entity.get('handle'))
                if 'registrant' in roles:
                    result['registrant_organization']=next((v[3] for v in fields if v[0]=='org' and v[3]),None)
                    address=next((v for v in fields if v[0]=='adr'),None)
                    if address:
                        result['registrant_country']=address[1].get('cc') or (address[3][6] if isinstance(address[3],list) and len(address[3])>6 else None)
            result['nameservers']=sorted(set(result['nameservers']+[n.get('ldhName','') for n in data.get('nameservers',[]) if n.get('ldhName')]))
        except Exception: result['rdap_status']='LOOKUP FAILED'
    else: result['rdap_reason']='No RDAP registry adapter is configured for this top-level domain.'
    return result

def analyze_domains(domains, enabled=None):
    with ThreadPoolExecutor(max_workers=6) as pool: results=list(pool.map(lambda d:analyze_domain(d,enabled),domains[:12]))
    results += [{**analyze_domain(d,False),'reason':'Enrichment limit reached (12 domains); static similarity still evaluated.'} for d in domains[12:]]
    return results
