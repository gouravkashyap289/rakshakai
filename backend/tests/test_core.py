from fastapi.testclient import TestClient
from app.main import app
from app.config import ROOT

def test_safe_and_phishing_persist_and_explain():
    with TestClient(app) as client:
        cases=[]
        for name in ('safe_email','phishing_email'):
            response=client.post('/api/analyze-email',files={'file':(name+'.eml',(ROOT/'demo_emails'/f'{name}.eml').read_bytes(),'message/rfc822')})
            assert response.status_code==200, response.text
            case=response.json(); cases.append(case)
            assert case['risk_score']==sum(e['contribution'] for e in case['evidence'])==sum(case['category_scores'].values())
            assert all(v<=case['category_caps'][k] for k,v in case['category_scores'].items())
            assert client.get('/api/investigations/'+case['case_id']).json()['email_sha256']==case['email_sha256']
        assert cases[0]['risk_score']<30
        assert cases[1]['risk_score']>=30
        assert cases[1]['risk_score']>cases[0]['risk_score']
        assert all(a['status']=='UNKNOWN' for a in cases[1]['auth'].values())
        assert len(client.get('/api/investigations').json())>=2

def test_invalid_uploads():
    with TestClient(app) as client:
        assert client.post('/api/analyze-email',files={'file':('evil.exe',b'abc','application/octet-stream')}).status_code==400
        assert client.post('/api/analyze-email',files={'file':('bad.eml',b'not an email','message/rfc822')}).status_code==400
        assert client.post('/api/analyze-email',files={'file':('bad.eml',b'x'*(10*1024*1024+1),'message/rfc822')}).status_code==413
        assert client.post('/api/demo/not-real').status_code==404

def test_parser_sanitization_and_attachment():
    from app.services.email_parser import parse_email, safe_filename
    assert safe_filename('../../bad.eml')=='bad.eml'
    email=parse_email(b'From: a@example.com\nSubject: Test\nContent-Type: text/html\n\n<script>alert(1)</script><a href="http://127.0.0.1/a">test</a>')
    assert '<script>' not in email['html_body']
    assert '127.0.0.1' not in email['ips']
    with TestClient(app) as client:
        case=client.post('/api/demo/suspicious_attachment').json()
        assert 'Misleading double extension' in case['attachments'][0]['signals']
        assert len(case['attachments'][0]['sha256'])==64

def test_ipv6_received_and_private_exclusion():
    from app.services.email_parser import parse_email
    email = parse_email(b'From: a@example.com\nSubject: Header test\nReceived: from relay ([IPv6:2606:4700::1111]) by local [10.0.0.1]\n\nMeeting notes')
    assert '2606:4700::1111' in email['ips']
    assert '10.0.0.1' not in email['ips']

def test_missing_auth_never_fails_and_legitimate_advice():
    from app.services.ai_classifier import classify
    from app.services.auth_analyzer import analyze_auth
    assert all(v['status']=='UNKNOWN' for v in analyze_auth({'authentication_results':[]}).values())
    advice = classify('Security guidance','Never share your password or verification code with anyone.')
    assert not advice['signals']
    assert advice['category']=='No strong content threat'

def test_bundled_classifier_uses_1000_message_corpus():
    from app.services.ai_classifier import classify, model_metadata
    metadata = model_metadata()
    assert metadata['total_examples'] == 1000
    assert metadata['training_examples'] == 800
    safe = classify('Team meeting', 'Agenda for tomorrow. No action is required.')
    phishing = classify('Account alert', 'Verify your password immediately or your account will be suspended.')
    assert safe['probability'] < phishing['probability']
    assert 'Rakshak TF-IDF' in phishing['engine']

def test_sender_subdomain_alignment_is_not_a_mismatch():
    from app.services.sender_analyzer import analyze_sender
    result = analyze_sender({'from':'support@swiggy.in','reply_to':'help@swiggy.in','return_path':'bounce@fwdkim.swiggy.in','to':'user@example.net','body_text':'Order update'})
    assert result['signals'] == []


def test_subject_and_html_attribute_urls():
    from email.message import EmailMessage
    from app.services.email_parser import parse_email
    message=EmailMessage()
    message['From']='sender@training.example'
    message['Subject']='Review https://subject.example/verify'
    message.set_content('<form action="https://form.example/login"><img src="https://image.example/pixel"></form>', subtype='html')
    parsed=parse_email(message.as_bytes())
    assert len(parsed['urls'])==3
    assert '<form' not in parsed['html_body']
    assert '<img' not in parsed['html_body']
