import time
from datetime import datetime, timezone, timedelta
import base64
import json
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet
from sqlalchemy import select
from app.main import app
from app.database import Investigation, Session
from app.mailboxes import Mailbox, Notice

def register(client):
    response=client.post('/api/auth/register',json={'email':uuid4().hex+'@example.test','password':'correct horse battery staple'})
    assert response.status_code==200,response.text
    return response.json()

def test_account_isolation_logout_and_login():
    with TestClient(app) as one, TestClient(app) as two:
        user=register(one); register(two)
        case=one.post('/api/demo/safe_email').json()
        assert one.get('/api/investigations/'+case['case_id']).status_code==200
        assert two.get('/api/investigations/'+case['case_id']).status_code==404
        assert two.post('/api/investigations/'+case['case_id']+'/summary').status_code==404
        assert one.post('/api/auth/logout').status_code==200
        assert one.get('/api/investigations/'+case['case_id']).status_code==404
        assert one.post('/api/auth/login',json={'email':user['email'],'password':'correct horse battery staple'}).status_code==200
        assert one.get('/api/investigations/'+case['case_id']).status_code==200

def test_csrf_and_invalid_credentials():
    with TestClient(app) as client:
        assert client.post('/api/auth/register',json={'email':'a@example.test','password':'too short'}).status_code==422
        assert client.post('/api/auth/logout',headers={'Origin':'https://attacker.invalid'}).status_code==403
        assert client.post('/api/auth/login',json={'email':'absent@example.test','password':'incorrect password here'}).status_code==401
        assert client.get('/api/mailboxes').status_code==401

def test_retention_and_report_privacy_preferences():
    with TestClient(app) as client:
        user=register(client)
        assert client.get('/api/auth/preferences').json()=={'retention_days':30,'mask_reports':False}
        case=client.post('/api/demo/safe_email').json()
        with Session.begin() as db: db.get(Investigation,case['case_id']).created_at=datetime.now(timezone.utc)-timedelta(days=8)
        saved=client.put('/api/auth/preferences',json={'retention_days':7,'mask_reports':True})
        assert saved.status_code==200 and saved.json()['mask_reports'] is True
        assert client.get('/api/investigations/'+case['case_id']).status_code==404

def test_oauth_state_binding_encryption_and_replay(monkeypatch):
    import app.mailboxes as mb
    monkeypatch.setenv('TOKEN_ENCRYPTION_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('GOOGLE_CLIENT_ID','test-client')
    monkeypatch.setenv('GOOGLE_CLIENT_SECRET','test-secret')
    monkeypatch.setattr(mb,'json_fetch',lambda *a,**k:{'access_token':'private-access','refresh_token':'private-refresh','expires_in':3600})
    with TestClient(app) as one, TestClient(app) as two:
        user=register(one);register(two)
        started=one.post('/api/mailboxes/gmail/connect').json()
        params=parse_qs(urlsplit(started['url']).query)
        assert params['scope']==['https://www.googleapis.com/auth/gmail.readonly']
        assert params['code_challenge_method']==['S256']
        callback='/api/mailboxes/gmail/callback?state='+params['state'][0]+'&code=code'
        assert two.get(callback,follow_redirects=False).status_code==400
        assert one.get(callback,follow_redirects=False).status_code==303
        assert one.get(callback,follow_redirects=False).status_code==400
        with Session() as db:
            row=db.scalar(select(Mailbox).where(Mailbox.user_id==user['id']))
            assert 'private-access' not in row.tokens
        assert 'private-access' not in one.get('/api/mailboxes').text

def test_google_login_uses_verified_email_and_one_time_state(monkeypatch):
    import app.mailboxes as mb
    monkeypatch.setenv('TOKEN_ENCRYPTION_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('GOOGLE_CLIENT_ID','test-client')
    monkeypatch.setenv('GOOGLE_CLIENT_SECRET','test-secret')
    monkeypatch.setattr(mb,'json_fetch',lambda url,**kwargs: {'access_token':'login-access'} if 'token' in url else {'email':'verified@example.test','email_verified':True})
    with TestClient(app) as client:
        started=client.post('/api/mailboxes/google-login/connect')
        assert started.status_code==200
        params=parse_qs(urlsplit(started.json()['url']).query)
        assert params['scope']==['openid email profile']
        callback='/api/mailboxes/gmail/callback?state='+params['state'][0]+'&code=code'
        assert client.get(callback,follow_redirects=False).status_code==303
        assert client.get('/api/auth/me').json()['user']['email']=='verified@example.test'
        assert client.get(callback,follow_redirects=False).status_code==400

def test_google_login_keeps_state_when_provider_is_unreachable(monkeypatch):
    import app.mailboxes as mb
    monkeypatch.setenv('TOKEN_ENCRYPTION_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('GOOGLE_CLIENT_ID','test-client')
    monkeypatch.setenv('GOOGLE_CLIENT_SECRET','test-secret')
    monkeypatch.setattr(mb,'json_fetch',lambda *a,**k: (_ for _ in ()).throw(mb.HTTPException(502,'Provider unavailable.')))
    with TestClient(app) as client:
        params=parse_qs(urlsplit(client.post('/api/mailboxes/google-login/connect').json()['url']).query)
        callback='/api/mailboxes/gmail/callback?state='+params['state'][0]+'&code=code'
        assert client.get(callback,follow_redirects=False).status_code==502
        assert client.get(callback,follow_redirects=False).status_code==502

@pytest.mark.parametrize('provider',['gmail','outlook'])
def test_mail_import_dedup_monitor_and_alerts(monkeypatch,provider):
    import app.mailboxes as mb
    monkeypatch.setenv('TOKEN_ENCRYPTION_KEY',Fernet.generate_key().decode())
    raw=b'From: attacker@example.test\nTo: user@example.test\nSubject: urgent\n\nSend money urgently.'
    calls=[]
    def analyze(raw,filename,visitor=None):
        calls.append(visitor)
        return {'case_id':'CASE-'+uuid4().hex,'risk_score':85}
    monkeypatch.setattr('app.services.pipeline.analyze',analyze)
    monkeypatch.setattr(mb,'json_fetch',lambda *a,**k:{'raw':base64.urlsafe_b64encode(raw).decode()})
    monkeypatch.setattr(mb,'fetch',lambda *a,**k:raw)
    monkeypatch.setattr(mb,'messages',lambda row:[{'id':'message/1'}])
    with TestClient(app) as client:
        user=register(client);identifier=uuid4().hex
        with Session.begin() as db:
            db.add(Mailbox(id=identifier,user_id=user['id'],provider=provider,tokens=mb.cipher().encrypt(json.dumps({'access_token':'access','expires_at':time.time()+3600}).encode()).decode(),monitoring=True,checked_at=0,last_status='CONNECTED'))
        checked=client.post('/api/mailboxes/'+identifier+'/check')
        assert checked.status_code==200 and checked.json()['checked_at']>0
        mb.check_mailbox(identifier)
        assert len(calls)==1
        alerts=client.get('/api/mailboxes/alerts/list').json()
        assert len(alerts)==1
        assert client.post('/api/mailboxes/alerts/'+alerts[0]['id']+'/read').status_code==200
        assert client.get('/api/mailboxes/alerts/list').json()[0]['read'] is True
        assert client.delete('/api/mailboxes/'+identifier).status_code==200
        with Session() as db: assert db.get(Mailbox,identifier) is None

def test_unconfigured_provider(monkeypatch):
    monkeypatch.delenv('GOOGLE_CLIENT_ID',raising=False)
    with TestClient(app) as client:
        register(client)
        assert client.post('/api/mailboxes/gmail/connect').status_code==503
