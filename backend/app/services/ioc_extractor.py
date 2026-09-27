def extract_iocs(case):
    rows=[]
    verified={x['indicator'] for x in case['threat_intel'] if x.get('malicious') is True}
    def add(kind,value,source,suspicious,reason):
        confirmed=value in verified
        rows.append({'type':kind,'value':value,'source':source,'risk':'High' if confirmed else ('Medium' if suspicious else 'Unverified'),'reason':reason,'confidence':case['confidence'],'verified':confirmed})
    for u in case['urls']: add('URL',u['url'],'Email body / HTML href',bool(u['signals']),'; '.join(u['signals']) or 'Observed URL; no structural warning.')
    for d in case['domains']: add('Domain',d['domain'],'Email address / URL',bool(d.get('lookalike')),d.get('similarity_reason','Observed domain.'))
    for ip in case['ips']: add('IP',ip['ip'],'; '.join(ip['source']),False,'Observed public infrastructure. Attribution unknown.')
    for email in case['email']['email_addresses']: add('Email address',email,'Email metadata / body',False,'Observed address; recipient addresses may be benign context.')
    for attachment in case['attachments']:
        add('SHA-256',attachment['sha256'],'Attachment: '+attachment['filename'],bool(attachment['signals']),'Static attachment fingerprint; hash alone is not a threat verdict.')
        if attachment['signals']: add('Suspicious attachment',attachment['filename'],'MIME attachment',True,'; '.join(attachment['signals']))
    return rows
