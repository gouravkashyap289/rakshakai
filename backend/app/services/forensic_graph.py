import hashlib

def build_graph(case):
    nodes={}; edges={}; counts={}; limit=160; truncated=False
    def node(kind,value,level,details=None):
        nonlocal truncated
        key=hashlib.sha256((kind+':'+str(value)).encode()).hexdigest()[:20]
        if key not in nodes:
            if len(nodes)>=limit: truncated=True; return None
            count=counts.get(level,0); counts[level]=count+1
            label=str(value)
            nodes[key]={'id':key,'position':{'x':level*300,'y':count*130},'data':{'label':label[:65]+('…' if len(label)>65 else ''),'type':kind,'value':value,**(details or {})},'style':{'background':'#1b2029','border':'1px solid '+('#c58a59' if kind=='Email' else '#436b78'),'color':'#e0e5ef','borderRadius':8,'width':230,'fontSize':12}}
        return key
    def edge(source,target,label):
        if source and target: edges[source+':'+target]={'id':source+':'+target,'source':source,'target':target,'label':label,'style':{'stroke':'#62717f'},'labelStyle':{'fill':'#adb8c8','fontSize':10}}
    root=node('Email',case['case_id'],0,{'subject':case['subject'],'risk_score':case['risk_score']})
    sender=node('Sender',case['sender'],1);edge(root,sender,'sent as')
    from_domain=case['sender_analysis']['domains'].get('from')
    if from_domain: edge(sender,node('Domain',from_domain,2),'uses domain')
    for url in case['urls']:
        u=node('URL',url['url'],1,{'signals':url['signals']});edge(root,u,'contains')
        if url['domain']: edge(u,node('Domain',url['domain'],2),'hosted at')
    for domain in case['domains']:
        d=node('Domain',domain['domain'],2,{'lookalike':domain.get('lookalike'),'source':'parsed email / DNS'})
        for kind in ('A','AAAA'):
            for ip in domain.get('dns',{}).get(kind,{}).get('values',[]):
                if any(i['ip']==ip for i in case['ips']): edge(d,node('IP',ip,3),'resolves to')
    for ip in case['ips']:
        i=node('IP',ip['ip'],3,{'country':ip['country'],'source':ip['source']})
        if any('Email' in s for s in ip['source']): edge(root,i,'observed')
        if ip.get('asn'):
            asn=node('ASN',str(ip['asn']),4);edge(i,asn,'announced by')
            if ip.get('organization'): edge(asn,node('Organization',ip['organization'],5),'registered to')
    for attachment in case['attachments']:
        a=node('Attachment',attachment['filename'],1,{'size':attachment['size'],'signals':attachment['signals']});edge(root,a,'contains')
        edge(a,node('SHA-256',attachment['sha256'],2),'fingerprint')
    mappings={'domain':('Domain',2),'url':('URL',1),'ip':('IP',3),'hash':('SHA-256',2),'asn':('ASN',4)}
    for related in case['campaigns']:
        r=node('Email',related['case_id'],0,{'relationship':related['relationship']})
        edge(r,root,'duplicate' if related['relationship'].startswith('Duplicate') else 'correlated')
        for shared in related['shared_indicators']:
            if shared['type'] in mappings:
                kind,level=mappings[shared['type']];edge(r,node(kind,shared['value'],level),'shares')
    return {'nodes':list(nodes.values()),'edges':list(edges.values()),'truncated':truncated}
