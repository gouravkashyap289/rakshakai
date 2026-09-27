import json
import pytest
from app.services.email_parser import parse_email
from app.services.url_analyzer import analyze_urls
from app.services.ai_classifier import classify
from app.services.risk_engine import score
from app.services.gemini_summary import summarize_case

def test_visible_link_mismatch():
    raw=b'From: a@example.test\nTo: b@example.test\nSubject: hello\nContent-Type: text/html\n\n<a href="https://bad.example/login">https://bank.example</a>'
    mail=parse_email(raw)
    result=analyze_urls(mail['urls'],mail['link_labels'])
    link=next(r for r in result if r['domain']=='bad.example')
    assert link['visible_text']==['https://bank.example']
    assert 'Visible link domain differs from destination' in link['signals']

@pytest.mark.parametrize('text',['तुरंत पैसे भेजें और ओटीपी बताएं','jaldi paise bhejo otp batao','உடனே கடவுச்சொல் அனுப்பு','వెంటనే డబ్బు పంపండి','এখনই টাকা পাঠান'])
def test_multilingual_rules(text):
    value=classify('',text)
    assert value['signals']
    assert value['language']['model_applicable'] is False
    assert value['confidence'] is None
    result=score({}, {}, value, [], [], [], [])
    assert result['risk_score']==sum(r['contribution'] for r in result['evidence'])

def test_hindi_safety_advice():
    value=classify('','अपना ओटीपी कभी किसी को मत बताएं।')
    assert 'OTP request' not in {s['signal'] for s in value['signals']}

def test_summary_missing_key(monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY',raising=False)
    assert summarize_case({})['status']=='API NOT CONFIGURED'

@pytest.mark.parametrize('url',['http://127.0.0.1/','http://[::1]/','http://169.254.169.254/','http://localhost/','http://10.0.0.1/','file:///etc/passwd','https://user:pass@example.com','http://8.8.8.8:8080/'])
def test_redirect_blocks_internal_targets(monkeypatch,url):
    from app.services.redirect_preview import preview
    monkeypatch.setenv('ENABLE_URL_REDIRECT_CHECKS','true')
    assert preview(url)['status']=='BLOCKED OR LOOKUP FAILED'

def test_redirect_pins_address_and_revalidates_next_hop(monkeypatch):
    import app.services.redirect_preview as rp
    monkeypatch.setenv('ENABLE_URL_REDIRECT_CHECKS','true')
    monkeypatch.setattr(rp,'public_addresses',lambda host:['8.8.8.8'] if host=='public.example' else (_ for _ in ()).throw(ValueError()))
    captured=[]
    class Conn:
        def __init__(self,address,port,timeout): captured.append(address)
        def request(self,method,target,headers): captured.append((method,headers['Host']))
        def getresponse(self): return self
        status=302
        def getheader(self,key): return 'http://127.0.0.1/private'
        def close(self): pass
    monkeypatch.setattr(rp.http.client,'HTTPConnection',Conn)
    result=rp.preview('http://public.example/')
    assert result['status']=='BLOCKED OR LOOKUP FAILED'
    assert captured==['8.8.8.8',('HEAD','public.example')]

def test_summary_redacts_content_and_uses_header(monkeypatch):
    import httpx
    captured={}
    def post(self,url,**kwargs):
        captured.update(kwargs)
        return httpx.Response(200,json={'candidates':[{'content':{'parts':[{'text':'Summary'}]}}]})
    monkeypatch.setenv('GEMINI_API_KEY','private-key')
    monkeypatch.setattr(httpx.Client,'post',post)
    case={'email':{'from':'person@example.com','body_text':'Private bank account'},'risk_score':3,'risk_level':'Low','confidence':41,'category_scores':{'AI Text Analysis':3},'category_caps':{'AI Text Analysis':40},'evidence':[{'category':'AI Text Analysis','signal':'Urgency','source':'Rakshak AI','evidence':'personal-secret','contribution':3}]}
    assert summarize_case(case,'Hindi')['summary']=='Summary'
    encoded=json.dumps(captured['json'])
    assert 'person@example.com' not in encoded and 'personal-secret' not in encoded and 'Private bank account' not in encoded
    assert captured['headers']['x-goog-api-key']=='private-key'
    assert 'Hindi' in encoded and 'score_breakdown' in encoded and 'evidence coverage' in encoded
