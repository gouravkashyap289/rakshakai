from app.services.domain_analyzer import similarity, analyze_domain
from app.services.network import public_domain, public_ip, provider_json
from app.services.threat_intel import lookup
import pytest

def test_domain_similarity_and_reserved_domains():
    assert similarity('paypa1.com')['lookalike']=='paypal.com'
    assert similarity('micros0ft-login.com')['lookalike']=='microsoft.com'
    assert similarity('login.microsoft.com')['lookalike'] is None
    assert analyze_domain('paypa1-login.example',True)['status']=='DATA NOT AVAILABLE'

def test_in_domain_rdap_registration_details(monkeypatch):
    import dns.resolver
    import app.services.domain_analyzer as domains
    monkeypatch.setattr(dns.resolver.Resolver,'resolve',lambda *args,**kwargs: (_ for _ in ()).throw(dns.resolver.NoAnswer()))
    monkeypatch.setattr(domains,'provider_json',lambda url:{
        'events':[{'eventAction':'registration','eventDate':'2014-06-19T19:14:26.696Z'}],
        'entities':[
            {'roles':['registrar'],'handle':'146','vcardArray':['vcard',[['fn',{},'text','GoDaddy']]]},
            {'roles':['registrant'],'vcardArray':['vcard',[['org',{},'text','Bundl Technologies Private Limited'],['adr',{'cc':'IN'},'text',['','','','','','','']]]]},
        ],
        'nameservers':[],
    })
    result=domains.analyze_domain('swiggy.in',True)
    assert result['creation_date'].startswith('2014-06-19')
    assert result['age_days'] > 4000
    assert result['registrar']=='GoDaddy'
    assert result['registrant_organization']=='Bundl Technologies Private Limited'
    assert result['registrant_country']=='IN'

@pytest.mark.parametrize('domain',['localhost','foo.local','evil.internal','127.0.0.1','2130706433','foo.example','example.com','a/b.com','a.com@localhost'])
def test_internal_domain_rejection(domain):
    assert not public_domain(domain)

def test_fixed_endpoint_ssrf_protection():
    assert not public_ip('::1')
    assert not public_ip('169.254.169.254')
    assert not public_ip('192.168.1.1')
    with pytest.raises(ValueError): provider_json('http://127.0.0.1/admin')
    with pytest.raises(ValueError): provider_json('https://evil.example/path')

def test_unavailable_intelligence_is_not_clean(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY',raising=False)
    row=lookup('VirusTotal','domain','suspicious.example',True)
    assert row['status']=='DATA NOT AVAILABLE'
    assert row['malicious'] is None
    assert row['configuration']=='API NOT CONFIGURED'

def test_provider_mapping_with_fixture(monkeypatch):
    import app.services.threat_intel as intel
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','test-key')
    monkeypatch.setattr(intel,'provider_json',lambda *a,**k:{'data':{'attributes':{'last_analysis_stats':{'malicious':2,'harmless':30}}}})
    row=intel.lookup('VirusTotal','domain','suspicious-domain.com',True)
    assert row['status']=='AVAILABLE' and row['malicious'] is True
    monkeypatch.setenv('OTX_API_KEY','test-key')
    monkeypatch.setattr(intel,'provider_json',lambda *a,**k:{'pulse_info':{'count':4}})
    assert intel.lookup('AlienVault OTX','domain','suspicious-domain.com',True)['malicious'] is None
