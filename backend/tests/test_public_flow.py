from fastapi.testclient import TestClient
from app.main import app
from app.services.origin_analyzer import trace_origin


def test_browser_sessions_cannot_read_change_or_correlate_other_visitors():
    with TestClient(app) as first, TestClient(app) as second:
        case = first.post('/api/demo/phishing_email').json()
        path = '/api/investigations/' + case['case_id']
        assert first.get(path).status_code == 200
        audit=first.get(path).json()['audit_trail']
        assert len(audit)==1 and audit[0]['previous_hash']=='0'*64 and len(audit[0]['event_hash'])==64
        assert first.get(path+'/report').status_code==200
        audit=first.get(path).json()['audit_trail']
        assert [event['action'] for event in audit]==['ANALYSIS COMPLETED','FORENSIC REPORT GENERATED']
        assert 'HttpOnly' in first.get('/api/health').headers.get('set-cookie', '') or first.cookies.get('rakshak-visitor')
        assert second.get('/api/investigations').json() == []
        for suffix in ('', '/report', '/feedback'):
            assert second.get(path + suffix).status_code == 404
        assert second.post(path+'/feedback',json={'verdict':'benign'}).status_code == 404
        assert second.delete(path).status_code == 404
        duplicate = second.post('/api/demo/phishing_email').json()
        assert not duplicate['campaigns']
        assert second.get('/api/metrics').json()['emails_analyzed'] == 1
        mine = first.post('/api/demo/phishing_email').json()
        assert any(c['case_id'] == case['case_id'] for c in mine['campaigns'])
        assert first.delete(path).status_code == 200
        assert first.get(path).status_code == 404
        assert first.get(path+'/report').status_code == 404
        cleaned = first.get('/api/investigations/'+mine['case_id']).json()
        assert not any(c['case_id'] == case['case_id'] for c in cleaned['campaigns'])


def test_origin_uses_sending_side_of_headers_and_never_body_ip():
    email={'received':[
        'from relay.example ([8.8.8.8]) by receiver.example [9.9.9.9]; Tue, 1 Sep 2026 10:10:00 +0000',
        'from older.example ([IPv6:2606:4700::1111]) by relay.example; Tue, 1 Sep 2026 10:09:00 +0000',
        'from private.example ([10.0.0.2]) by older.example; Tue, 1 Sep 2026 10:08:00 +0000',
    ],'ips':['1.1.1.1']}
    result=trace_origin(email,[])
    assert result['earliest_observed_ip']=='2606:4700::1111'
    assert result['source_hop']==2
    assert result['reliable_origin_ip'] is None
    assert result['sender_location']=='UNKNOWN'
    assert result['sender_device_ip'] is None
    assert result['sender_device_ip_status']=='NOT PROVIDED BY EMAIL SERVICE'
    assert result['hops'][2]['public_ips']==['8.8.8.8']
    assert trace_origin({'received':[],'ips':['1.1.1.1']},[])['earliest_observed_ip'] is None


def test_report_contains_observed_ip_route_and_evidence():
    message=b'From: alerts@fictional.example\nTo: reader@example.com\nSubject: Please verify your account\nReceived: from sending.example ([8.8.8.8]) by inbox.example; Tue, 1 Sep 2026 10:10:00 +0000\n\nVerify your account immediately. Enter your password at https://verify.example/login'
    with TestClient(app) as client:
        c=client.post('/api/analyze-email',files={'file':('route.eml',message,'message/rfc822')}).json()
        assert c['origin']['earliest_observed_ip']=='8.8.8.8'
        response=client.get('/api/investigations/'+c['case_id']+'/report')
        assert response.status_code==200 and response.content.startswith(b'%PDF-')
        text=' '.join(page.extract_text() for page in PdfReader(BytesIO(response.content)).pages)
        assert len(PdfReader(BytesIO(response.content)).pages) == 2
        for value in ('8.8.8.8','Origin and email-delivery route','Sender phone/computer IP','Sender authentication','Domain registration details','IP infrastructure geolocation','Attachments','Limits:','UNKNOWN'):
            assert value in text


def test_claimed_originating_ip_is_separate_from_mail_server_location():
    message=b'From: sender@example.com\nTo: reader@example.com\nSubject: hello\nX-Originating-IP: [1.1.1.1]\nReceived: from mail.example ([8.8.8.8]) by inbox.example; Tue, 1 Sep 2026 10:10:00 +0000\n\nhello'
    from app.services.email_parser import parse_email
    email=parse_email(message)
    result=trace_origin(email,[{'ip':'1.1.1.1','country':'Australia','region':'Queensland','city':'South Brisbane'},{'ip':'8.8.8.8','country':'United States','region':'California','city':'Mountain View'}])
    assert result['sender_device_ip']=='1.1.1.1'
    assert result['earliest_observed_ip']=='8.8.8.8'
    assert result['sender_location']=='South Brisbane, Queensland, Australia'
    assert result['sender_device_ip_status']=='PRESENT IN UNVERIFIED EMAIL HEADER'
from io import BytesIO
from pypdf import PdfReader
