import os
import copy
import hmac
import time
import asyncio
import secrets
import hashlib
from urllib.parse import urlsplit
from contextlib import suppress
from http.cookies import SimpleCookie
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .config import MAX_UPLOAD, API_KEY, NETWORK_ENABLED, ROOT
from .database import init_db, list_cases, get_case, delete_case, Session, Feedback, CaseAccess, add_audit, list_audit, preferences, purge_expired
from .services.pipeline import analyze
from .accounts import router as accounts_router, session_user
from .mailboxes import router as mailboxes_router, monitor_loop

class SecurityMiddleware:
    def __init__(self, app):
        self.app = app; self.hits = defaultdict(deque)
    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http': return await self.app(scope,receive,send)
        headers = dict(scope['headers']); path = scope['path']
        if scope['method'] in ('POST','PUT','PATCH','DELETE'):
            origin = headers.get(b'origin',b'').decode('latin-1')
            allowed = {os.getenv('PUBLIC_BASE_URL','http://127.0.0.1:5173').rstrip('/'), 'http://localhost:5173','http://127.0.0.1:5174'}
            host = headers.get(b'host',b'').decode('latin-1')
            if headers.get(b'sec-fetch-site') == b'cross-site' or (origin and origin not in allowed and urlsplit(origin).netloc != host):
                return await JSONResponse({'detail':'Cross-site changes are blocked.'},status_code=403)(scope,receive,send)
        cookie = SimpleCookie()
        try: cookie.load(headers.get(b'cookie',b'').decode('latin-1'))
        except Exception: pass
        token = cookie.get('rakshak-visitor')
        token = token.value if token else ''
        new_visitor = len(token) != 64 or any(c not in '0123456789abcdef' for c in token)
        if new_visitor: token = secrets.token_hex(32)
        scope.setdefault('state',{})['visitor'] = hashlib.sha256(token.encode()).hexdigest()
        login = cookie.get('rakshak-login')
        user = await run_in_threadpool(session_user, login.value if login else '')
        scope['state']['user'] = user
        if user: scope['state']['visitor'] = user['id']
        async def error(status, message):
            await JSONResponse({'detail':message}, status_code=status)(scope,receive,send)
        if API_KEY and path.startswith('/api/') and path != '/api/health' and not path.endswith('/callback'):
            if not hmac.compare_digest(headers.get(b'x-api-key',b'').decode(), API_KEY): return await error(401,'Valid API key required.')
        if scope['method'] == 'POST':
            now = time.monotonic(); ip = scope.get('client',('unknown',0))[0]
            # Bound per-process state; reverse proxies must apply shared rate limits for multi-worker deployment.
            if len(self.hits)>10000: self.hits.clear()
            bucket = self.hits[ip]
            while bucket and bucket[0]<now-60: bucket.popleft()
            if len(bucket)>=20: return await error(429,'Rate limit reached. Try again in one minute.')
            bucket.append(now)
            size = 0; chunks = []
            while True:
                try: chunk = await asyncio.wait_for(receive(),timeout=15)
                except TimeoutError: return await error(408,'Upload timed out.')
                if chunk['type'] == 'http.disconnect': return
                size += len(chunk.get('body',b''))
                if size>MAX_UPLOAD+65536: return await error(413,'Upload exceeds the 10 MB limit.')
                chunks.append(chunk)
                if not chunk.get('more_body',False): break
            iterator = iter(chunks)
            async def limited_receive():
                return next(iterator, {'type':'http.request','body':b'','more_body':False})
        else: limited_receive = receive
        async def secure_send(message):
            if message['type']=='http.response.start':
                message.setdefault('headers',[]).extend([(b'x-content-type-options',b'nosniff'),(b'x-frame-options',b'DENY'),(b'referrer-policy',b'no-referrer'),(b'cache-control',b'no-store')])
                if new_visitor and path.startswith('/api/'):
                    secure = '; Secure' if os.getenv('COOKIE_SECURE','false').lower()=='true' else ''
                    message['headers'].append((b'set-cookie',f'rakshak-visitor={token}; Path=/; HttpOnly; SameSite=Strict{secure}'.encode()))
            await send(message)
        await self.app(scope,limited_receive,secure_send)

@asynccontextmanager
async def lifespan(app):
    init_db()
    app.state.analysis_slots = analysis_slots
    monitor_task = None
    # A Vercel Function ends after the request, so an in-process polling loop
    # cannot provide reliable mailbox monitoring there. Manual inbox browsing
    # remains available; production monitoring belongs in a scheduled worker.
    if not os.getenv('VERCEL'):
        monitor_task = asyncio.create_task(monitor_loop(app))
    try:
        yield
    finally:
        if monitor_task:
            monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await monitor_task

app = FastAPI(title='RAKSHAK Forensic API',version='1.0.0',lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=['http://127.0.0.1:5173','http://localhost:5173'], allow_methods=['GET','POST','DELETE'],allow_headers=['Content-Type','X-API-Key'])
app.add_middleware(SecurityMiddleware)
analysis_slots = asyncio.Semaphore(2)
app.include_router(accounts_router)
app.include_router(mailboxes_router)

@app.get('/api/health')
def health(): return {'status':'ok','engine':'Rakshak AI'}

@app.post('/api/analyze-email')
async def analyze_email(request:Request, file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith('.eml'): raise HTTPException(400,'Only .eml files are supported.')
    if file.content_type not in ('message/rfc822','application/octet-stream','text/plain',''): raise HTTPException(415,'Unsupported MIME type.')
    raw = await file.read(MAX_UPLOAD+1); await file.close()
    if len(raw)>MAX_UPLOAD: raise HTTPException(413,'Upload exceeds the 10 MB limit.')
    try:
        async with analysis_slots: return await run_in_threadpool(analyze,raw,file.filename,False,request.state.visitor)
    except ValueError as e: raise HTTPException(400,str(e)) from e

DEMOS = ['safe_email','phishing_email','brand_impersonation','fake_invoice','bec_email','suspicious_attachment']
@app.get('/api/demos')
def demos(): return DEMOS

@app.post('/api/demo/{name}')
async def demo(name: str,request:Request):
    if name not in DEMOS: raise HTTPException(404,'Demo not found.')
    async with analysis_slots:
        return await run_in_threadpool(analyze,(ROOT/'demo_emails'/f'{name}.eml').read_bytes(),f'{name}.eml',True,request.state.visitor)

@app.get('/api/investigations')
def investigations(request:Request,limit:int=Query(200,ge=1,le=500),offset:int=Query(0,ge=0)):
    if request.state.user:
        pref=preferences(request.state.user['id']); purge_expired(request.state.user['id'],pref['retention_days'])
    keys = ['case_id','created_at','filename','subject','sender','risk_score','risk_level','confidence','threat_category','demo']
    return [{k:c[k] for k in keys} for c in list_cases(limit,offset,request.state.visitor)]

@app.get('/api/investigations/{case_id}')
def investigation(case_id:str,request:Request):
    case = get_case(case_id,request.state.visitor)
    if not case: raise HTTPException(404,'Investigation not found.')
    return {**case,'audit_trail':list_audit(case_id)}

@app.delete('/api/investigations/{case_id}')
def remove_investigation(case_id:str,request:Request):
    if not delete_case(case_id,request.state.visitor): raise HTTPException(404,'Investigation not found.')
    return {'status':'deleted'}

@app.get('/api/settings')
def settings():
    return {'network_lookups':NETWORK_ENABLED,'max_upload_mb':10,'api_key_required':bool(API_KEY),'providers':{label:('CONFIGURED' if os.getenv(key) else 'API NOT CONFIGURED') for label,key in [('VirusTotal','VIRUSTOTAL_API_KEY'),('AbuseIPDB','ABUSEIPDB_API_KEY'),('URLhaus','URLHAUS_API_KEY'),('AlienVault OTX','OTX_API_KEY'),('Gemini summary','GEMINI_API_KEY')]},'geolite_city':'CONFIGURED' if os.getenv('GEOLITE2_CITY_PATH') else 'DATA NOT AVAILABLE','geolite_asn':'CONFIGURED' if os.getenv('GEOLITE2_ASN_PATH') else 'DATA NOT AVAILABLE'}

class FeedbackInput(BaseModel):
    verdict: str = Field(pattern='^(malicious|benign|uncertain)$')
    notes: str = Field(default='',max_length=2000)

class RedirectInput(BaseModel):
    url: str = Field(max_length=4096)

@app.post('/api/investigations/{case_id}/redirect-preview')
async def redirect_preview(case_id:str,value:RedirectInput,request:Request):
    case=investigation(case_id,request)
    if value.url not in [item['url'] for item in case['urls']]: raise HTTPException(400,'URL is not part of this investigation.')
    from .services.redirect_preview import preview
    async with analysis_slots: return await run_in_threadpool(preview,value.url)

@app.post('/api/investigations/{case_id}/feedback')
def feedback(case_id:str,value:FeedbackInput,request:Request):
    investigation(case_id,request)
    with Session.begin() as db: db.merge(Feedback(case_id=case_id,**value.model_dump()))
    add_audit(case_id,'ANALYST FEEDBACK SAVED',{'verdict':value.verdict})
    return {'status':'saved',**value.model_dump()}

@app.get('/api/investigations/{case_id}/feedback')
def get_feedback(case_id:str,request:Request):
    investigation(case_id,request)
    with Session() as db:
        row=db.get(Feedback,case_id)
        return {'verdict':row.verdict,'notes':row.notes} if row else None

@app.get('/api/investigations/{case_id}/report')
def forensic_report(case_id:str,request:Request):
    from .services.report_generator import report
    case=investigation(case_id,request)
    add_audit(case_id,'FORENSIC REPORT GENERATED')
    if request.state.user and preferences(request.state.user['id'])['mask_reports']:
        case=copy.deepcopy(case); case['subject']='[REDACTED BY PRIVACY SETTING]'; case['sender']='[REDACTED]'
        for key in ('from','to','cc','reply_to','return_path','subject'): case.get('email',{})[key]='[REDACTED]'
    content=report(case,get_feedback(case_id,request))
    return Response(content,media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="{case_id}-forensic-report.pdf"'})

@app.post('/api/investigations/{case_id}/summary')
def investigation_summary(case_id:str,request:Request,language:str=Query('English',pattern='^(English|Hindi|Bengali|Tamil|Telugu|Marathi|Gujarati|Kannada|Malayalam|Punjabi)$')):
    from .services.gemini_summary import summarize_case
    return summarize_case(investigation(case_id,request),language)

@app.get('/api/metrics')
def metrics(request:Request):
    from sqlalchemy import select,func
    from .database import Investigation
    with Session() as db:
        base=select(func.count()).select_from(Investigation).join(CaseAccess,CaseAccess.case_id==Investigation.case_id).where(CaseAccess.visitor==request.state.visitor)
        total=db.scalar(base)
        threats=db.scalar(base.where(Investigation.risk_score>=30))
    return {'emails_analyzed':total,'threats_detected':threats,'detection_accuracy':None,'accuracy_reason':'Independent labeled evaluation has not been performed.'}

# Serve the compiled React application from the same origin as the API.  This
# keeps local sign-in cookies and relative /api requests working without a
# separate development proxy.
FRONTEND_DIST = Path(__file__).resolve().parents[2] / 'frontend' / 'dist'
if not os.getenv('VERCEL') and FRONTEND_DIST.is_dir():
    app.mount('/', StaticFiles(directory=FRONTEND_DIST, html=True), name='frontend')
