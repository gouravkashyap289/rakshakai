from difflib import SequenceMatcher
from urllib.parse import urlsplit

COMMON={'gmail.com','outlook.com','yahoo.com','microsoft.com','google.com','amazon.com','paypal.com','apple.com'}
def infrastructure(case):
    hosts={u.get('domain') for u in case['urls'] if u.get('domain')}
    sender=case['sender_analysis']['domains'].get('from')
    if sender: hosts.add(sender)
    return {'domain':hosts-COMMON,'url':{u['url'] for u in case['urls']},'ip':{i['ip'] for i in case['ips']},'hash':{a['sha256'] for a in case['attachments']},'asn':{str(i['asn']) for i in case['ips'] if i.get('asn')}}

def correlate(current,previous):
    matches=[]; a=infrastructure(current)
    for old in previous:
        if current['email_sha256']==old['email_sha256']:
            matches.append({'case_id':old['case_id'],'subject':old['subject'],'score':100,'relationship':'Duplicate email evidence','shared_indicators':[{'type':'Email SHA-256','value':current['email_sha256']}],'reason':'Identical raw email; not independent campaign corroboration.'})
            continue
        b=infrastructure(old); shared=[]; overlap={k:a[k]&b[k] for k in a}
        for kind,values in overlap.items(): shared += [{'type':kind,'value':v} for v in sorted(values)]
        # A URL, its host, and its DNS address are related; their combined infrastructure score is capped.
        infra=min(40,30*bool(overlap['url'])+20*bool(overlap['domain'])+25*bool(overlap['ip'])+5*bool(overlap['asn']))
        artifact=50*bool(overlap['hash'])
        subject_ratio=SequenceMatcher(None,current['subject'].lower(),old['subject'].lower()).ratio()
        subject=10 if subject_ratio>=.8 else 0
        if subject: shared.append({'type':'Subject similarity','value':f'{subject_ratio:.0%}: {old["subject"]}'})
        same_category=current['threat_category']==old['threat_category'] and current['threat_category']!='No strong content threat'
        category=5*same_category
        if category: shared.append({'type':'Threat category','value':current['threat_category']})
        structure=(len(current['urls']),len(current['attachments']),bool(current['email'].get('html_body')))==(len(old['urls']),len(old['attachments']),bool(old['email'].get('html_body')))
        structure_score=5 if structure and infra else 0
        if structure_score: shared.append({'type':'Email structure','value':'Matching URL / attachment counts and HTML presence'})
        score=min(100,infra+artifact+subject+category+structure_score)
        independent=bool(artifact) or (bool(infra) and bool(subject or category))
        if score>=50 and independent:
            matches.append({'case_id':old['case_id'],'subject':old['subject'],'score':score,'relationship':'Possible Related Phishing Campaign','shared_indicators':shared,'reason':'Shared infrastructure/artifacts plus supporting content similarities. Relationship requires analyst review.'})
    return sorted(matches,key=lambda x:-x['score'])[:10]
