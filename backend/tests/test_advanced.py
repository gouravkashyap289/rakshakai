from fastapi.testclient import TestClient
from app.main import app
from app.services.campaign_correlator import correlate
from copy import deepcopy

def test_report_feedback_graph_and_duplicate():
    with TestClient(app) as client:
        first=client.post('/api/demo/phishing_email').json()
        second=client.post('/api/demo/phishing_email').json()
        assert any(m['case_id']==first['case_id'] and m['relationship']=='Duplicate email evidence' for m in second['campaigns'])
        assert second['graph']['nodes'] and second['graph']['edges']
        ids={n['id'] for n in second['graph']['nodes']}
        assert all(e['source'] in ids and e['target'] in ids for e in second['graph']['edges'])
        response=client.post('/api/investigations/'+second['case_id']+'/feedback',json={'verdict':'malicious','notes':'Training review'})
        assert response.status_code==200
        assert client.get('/api/investigations/'+second['case_id']+'/feedback').json()['notes']=='Training review'
        pdf=client.get('/api/investigations/'+second['case_id']+'/report')
        assert pdf.status_code==200 and pdf.content.startswith(b'%PDF-')
        assert len(pdf.content)>3000

def test_campaign_shared_infrastructure_but_not_recipient_only():
    with TestClient(app) as client:
        first=client.post('/api/demo/phishing_email').json()
        second=deepcopy(first);second['case_id']='CASE-RELATED';second['email_sha256']='different'
        assert correlate(second,[first])[0]['relationship']=='Possible Related Phishing Campaign'
        safe=client.post('/api/demo/safe_email').json()
        assert correlate(safe,[first])==[]

def test_unknown_evidence_lowers_confidence_without_risk_increase():
    from app.services.risk_engine import score
    from app.services.auth_analyzer import analyze_auth
    from app.services.ai_classifier import classify
    auth=analyze_auth({'authentication_results':[]})
    args=[auth,{'signals':[]},classify('Meeting','Lunch tomorrow'),[],[],[],[]]
    absent=score(*args)
    args[0]={k:{'status':'PASS'} for k in ['SPF','DKIM','DMARC']}
    present=score(*args)
    assert absent['risk_score']==present['risk_score']
    assert absent['confidence']<present['confidence']

def test_three_pillar_score_escalates_money_and_otp_request():
    from app.services.risk_engine import score
    from app.services.auth_analyzer import analyze_auth
    from app.services.ai_classifier import classify
    auth=analyze_auth({'authentication_results':[]})
    ai=classify('Urgent need of money','Please send me 20000 rupees and send me your bank Derails. Share your OTP when I ask.')
    result=score(auth,{'signals':[]},ai,[],[],[],[])
    assert result['category_caps']=={'AI Text Analysis':40,'Sender & Domain Reputation':35,'Urgent Actions, Links & Attachments':25}
    assert result['risk_score']>=31
    assert result['risk_level']=='Medium'
    assert 'Payment instructions' in {signal['signal'] for signal in ai['signals']}
    assert 'Payment or bank-detail request combined with an OTP request' in result['correlations']
