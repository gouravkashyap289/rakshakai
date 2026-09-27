from datetime import datetime, timezone
from uuid import uuid4
import hashlib
import time
import os
from .email_parser import parse_email, safe_filename
from .auth_analyzer import analyze_auth
from .sender_analyzer import analyze_sender
from .ai_classifier import classify
from .url_analyzer import analyze_urls
from .attachment_analyzer import analyze_attachments
from .risk_engine import score
from .domain_analyzer import analyze_domains
from .ip_analyzer import analyze_ips
from .threat_intel import analyze_intel
from .ioc_extractor import extract_iocs
from .campaign_correlator import correlate
from .forensic_graph import build_graph
from ..database import save_case, list_cases

def analyze(raw, filename, demo=False, visitor=None):
    timeline = []
    def stage(name, operation):
        start = time.perf_counter(); value = operation()
        timeline.append({'stage':name,'status':'COMPLETE','duration_ms':round((time.perf_counter()-start)*1000),'timestamp':datetime.now(timezone.utc).isoformat()})
        return value
    email = stage('Email parsing', lambda:parse_email(raw))
    auth = stage('Authentication headers', lambda:analyze_auth(email))
    if email['dkim_signatures'] and os.getenv('VERIFY_DKIM','false').lower()=='true':
        from ..config import NETWORK_ENABLED
        if NETWORK_ENABLED:
            from .dkim_verifier import verify_dkim
            checked=stage('DKIM cryptographic verification',lambda:verify_dkim(raw))
            auth['DKIM'].update(checked)
    sender = stage('Sender analysis', lambda:analyze_sender(email))
    ai = stage('Rakshak AI', lambda:classify(email['subject'],email['analysis_text']))
    urls = stage('URL analysis', lambda:analyze_urls(email['urls'],email.get('link_labels',[])))
    attachments = stage('Attachment static analysis', lambda:analyze_attachments(email['attachments']))
    domains = stage('Domain / DNS / RDAP intelligence', lambda:analyze_domains(email['domains']))
    ips = stage('Public IP intelligence', lambda:analyze_ips(email['ips'],domains))
    intel = stage('Threat intelligence adapters', lambda:analyze_intel(domains,ips,urls,attachments))
    for ip in ips:
        for record in intel:
            if record.get('indicator')==ip['ip'] and record.get('provider')=='AbuseIPDB' and record['status']=='AVAILABLE':
                details=record['details'];ip['isp']=details.get('isp');ip['country_code']=details.get('countryCode')
                if isinstance(details.get('isTor'),bool): ip['tor']='YES' if details['isTor'] else 'NO'
                ip['usage_type']=details.get('usageType')
                if 'data center' in str(details.get('usageType','')).lower(): ip['datacenter']='YES'
                ip['reputation_source']='AbuseIPDB';ip['risk']='High' if record['malicious'] else 'Unverified'
    risk = stage('Explainable risk assessment', lambda:score(auth,sender,ai,urls,domains,attachments,intel))
    email.pop('attachments'); email.pop('analysis_text')
    case = {'case_id':'CASE-'+uuid4().hex[:10].upper(),'created_at':datetime.now(timezone.utc).isoformat(),'filename':safe_filename(filename),'email_sha256':hashlib.sha256(raw).hexdigest(),'demo':demo,'subject':email['subject'],'sender':email['from'],'threat_category':ai['category'],'email':email,'auth':auth,'sender_analysis':sender,'ai':ai,'urls':urls,'domains':domains,'ips':[{'ip':ip,'status':'DATA NOT AVAILABLE'} for ip in email['ips']],'attachments':attachments,'threat_intel':intel,'iocs':[],'campaigns':[],'timeline':timeline,**risk}
    case['date']=email['date']
    case['ips']=ips
    from .origin_analyzer import trace_origin
    case['origin']=stage('Sender route reconstruction',lambda:trace_origin(email,ips))
    case['iocs']=stage('IOC extraction',lambda:extract_iocs(case))
    case['limitations']=['Imported authentication headers are untrusted by default.','AI probability comes from a prototype model and is not calibrated accuracy.','Missing reputation does not establish safety.','External lookups are disabled unless explicitly enabled on the server.','URL targets and redirect chains are not fetched.','Attachment analysis is static; files are not executed or extracted.','Geolocation concerns approximate observed infrastructure, not a person.','DNS and reputation reflect lookup time, which may differ from email receipt time.','Enrichment is bounded to 12 domains and 10 reputation indicators per case.','HTML/text analysis and extracted indicator lists have explicit size limits.']
    case['limitations']=[item.replace('URL targets and redirect chains are not fetched.','URL targets are not fetched during analysis; an optional user-requested HEAD-only redirect check is separate.') for item in case['limitations']]
    if not ai.get('language',{}).get('model_applicable',True): case['limitations'].append(ai['language']['coverage'])
    case['campaigns']=stage('Rakshak Campaign Intelligence',lambda:correlate(case,list_cases(200,visitor=visitor)))
    case['graph']=stage('Forensic graph construction',lambda:build_graph(case))
    case['risk_policy_version']='2.0 - three-pillar hybrid'
    save_case(case,visitor)
    return case
