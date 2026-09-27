"""Read-only Gmail / Microsoft Graph connectors and bounded inbox monitoring."""
import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
import threading
from urllib.parse import urlencode, quote
from uuid import uuid4
import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import String, Text, Float, Boolean, select, delete
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base, Session
from .accounts import google_user, require_user
from .config import MAX_UPLOAD

router = APIRouter(prefix='/api/mailboxes')
MAILBOX_LOCK = threading.RLock()
PROVIDERS = {
 'gmail': {'prefix':'GOOGLE', 'authorize':'https://accounts.google.com/o/oauth2/v2/auth', 'token':'https://oauth2.googleapis.com/token', 'scope':'https://www.googleapis.com/auth/gmail.readonly'},
 'outlook': {'prefix':'MICROSOFT', 'authorize':'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', 'token':'https://login.microsoftonline.com/common/oauth2/v2.0/token', 'scope':'offline_access https://graph.microsoft.com/Mail.Read'},
}

class Mailbox(Base):
    __tablename__ = 'mailboxes'
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    tokens: Mapped[str] = mapped_column(Text)
    monitoring: Mapped[bool] = mapped_column(Boolean, default=False)
    checked_at: Mapped[float] = mapped_column(Float, default=0)
    last_status: Mapped[str] = mapped_column(String(100), default='CONNECTED')

class OAuthState(Base):
    __tablename__ = 'oauth_states'
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(20))
    verifier: Mapped[str] = mapped_column(Text)
    expires: Mapped[float] = mapped_column(Float)

class MailMessage(Base):
    __tablename__ = 'mail_messages'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(40), index=True)
    case_id: Mapped[str] = mapped_column(String(40), default='')

class Notice(Base):
    __tablename__ = 'notifications'
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    case_id: Mapped[str] = mapped_column(String(40))
    created: Mapped[float] = mapped_column(Float)
    read: Mapped[bool] = mapped_column(Boolean, default=False)

def cipher():
    try: return Fernet(os.environ['TOKEN_ENCRYPTION_KEY'].encode())
    except (KeyError, ValueError): raise HTTPException(503, 'Mailbox token encryption is not configured.')

def config(provider):
    if provider not in PROVIDERS: raise HTTPException(404, 'Unknown provider.')
    p = PROVIDERS[provider]
    client = os.getenv(p['prefix']+'_CLIENT_ID', '')
    secret = os.getenv(p['prefix']+'_CLIENT_SECRET', '')
    project_host = os.getenv('VERCEL_PROJECT_PRODUCTION_URL') or os.getenv('VERCEL_URL')
    base = os.getenv('PUBLIC_BASE_URL') or (('https://' + project_host) if project_host else 'http://127.0.0.1:5173')
    base = base.rstrip('/')
    return p, client, secret, base+'/api/mailboxes/'+provider+'/callback'

def configured(provider):
    _, client, secret, _ = config(provider)
    try: cipher()
    except HTTPException: return False
    return bool(client and secret)

def fetch(url, token=None, method='GET', data=None):
    headers = {'Authorization':'Bearer '+token} if token else {}
    # All URLs are constructed from fixed provider origins; message IDs are quoted.
    try:
        with httpx.Client(timeout=20, follow_redirects=False) as client:
            with client.stream(method, url, headers=headers, data=data) as response:
                if response.status_code >= 400: raise HTTPException(502, 'Mailbox provider rejected the request. Reconnect or retry later.')
                if response.status_code >= 300: raise HTTPException(502, 'Unexpected provider redirect.')
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_UPLOAD*2: raise HTTPException(413, 'Provider response exceeds the size limit.')
                return bytes(content)
    except httpx.RequestError as exc:
        raise HTTPException(502, 'Google or Microsoft could not be reached. Check the server network connection and retry.') from exc

def json_fetch(url, **kwargs): return json.loads(fetch(url, **kwargs))

def owned(mailbox_id, user_id):
    with Session() as db:
        row = db.get(Mailbox, mailbox_id)
        if not row or row.user_id != user_id: raise HTTPException(404, 'Mailbox not found.')
        db.expunge(row)
        return row

def access_token(row):
    try: value = json.loads(cipher().decrypt(row.tokens.encode()))
    except (InvalidToken, ValueError): raise HTTPException(503, 'Cannot unlock mailbox. Restore encryption key or reconnect.')
    if value.get('expires_at', 0) > time.time()+60: return value['access_token']
    if not value.get('refresh_token'): raise HTTPException(401, 'Mailbox consent expired. Reconnect this mailbox.')
    p, client, secret, _ = config(row.provider)
    try:
        with httpx.Client(timeout=20, follow_redirects=False) as provider:
            response = provider.post(p['token'], data={'client_id':client,'client_secret':secret,'grant_type':'refresh_token','refresh_token':value['refresh_token']})
    except httpx.RequestError as exc:
        raise HTTPException(502, 'Google or Microsoft could not be reached. Check the server network connection and retry.') from exc
    try: fresh = response.json()
    except ValueError: fresh = {}
    if response.status_code >= 400:
        if fresh.get('error') in ('invalid_grant', 'invalid_token'):
            raise HTTPException(401, 'Mailbox authorization expired or was revoked. Disconnect and reconnect this mailbox.')
        if fresh.get('error') in ('invalid_client', 'unauthorized_client'):
            raise HTTPException(503, 'Mailbox OAuth credentials were rejected. Check the provider configuration.')
        raise HTTPException(502, 'Mailbox provider rejected the token refresh. Reconnect this mailbox.')
    if not fresh.get('access_token'):
        raise HTTPException(502, 'Mailbox provider did not return a refreshed access token.')
    value.update(fresh)
    value['expires_at'] = time.time()+int(fresh.get('expires_in',3600))
    encrypted = cipher().encrypt(json.dumps(value).encode()).decode()
    with Session.begin() as db:
        current = db.get(Mailbox,row.id)
        if not current: raise HTTPException(404,'Mailbox disconnected.')
        current.tokens = encrypted
    return value['access_token']

def messages(row):
    token = access_token(row)
    if row.provider == 'gmail':
        listing = json_fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20&labelIds=INBOX',token=token)
        result = []
        for item in listing.get('messages',[]):
            detail = json_fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/'+quote(item['id'],safe='')+'?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date',token=token)
            headers = {h['name'].lower():h['value'] for h in detail.get('payload',{}).get('headers',[])}
            result.append({'id':item['id'],'subject':headers.get('subject','No subject'),'sender':headers.get('from',''),'date':headers.get('date','')})
        return result
    data = json_fetch('https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=20&$select=id,subject,from,receivedDateTime&$orderby=receivedDateTime%20desc',token=token)
    return [{'id':m['id'],'subject':m.get('subject','No subject'),'sender':(m.get('from') or {}).get('emailAddress',{}).get('address',''),'date':m.get('receivedDateTime','')} for m in data.get('value',[])]

def analyze_message(row, message_id):
    with MAILBOX_LOCK:
        owned(row.id,row.user_id)
        return _analyze_message(row,message_id)

def _analyze_message(row, message_id):
    from .services.pipeline import analyze
    key = hashlib.sha256((row.id+':'+message_id).encode()).hexdigest()
    with Session() as db:
        saved = db.get(MailMessage,key)
        if saved and saved.case_id=='DELETED': return {'case_id':None,'duplicate':True,'deleted':True}
        if saved and saved.case_id: return {'case_id':saved.case_id,'duplicate':True}
    token = access_token(row)
    identifier = quote(message_id,safe='')
    if row.provider == 'gmail':
        data = json_fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/'+identifier+'?format=raw',token=token)
        raw = base64.urlsafe_b64decode(data['raw']+'===')
    else: raw = fetch('https://graph.microsoft.com/v1.0/me/messages/'+identifier+'/$value',token=token)
    if len(raw)>MAX_UPLOAD: raise HTTPException(413,'Email exceeds the 10 MB analysis limit.')
    # Do not automatically trust Authentication-Results merely because API transport is authenticated.
    case = analyze(raw, row.provider+'-message.eml', visitor=row.user_id)
    with Session.begin() as db:
        current = db.get(MailMessage,key)
        if current: current.case_id = case['case_id']
        else: db.add(MailMessage(key=key,mailbox_id=row.id,case_id=case['case_id']))
        if case['risk_score']>=71: db.add(Notice(id=uuid4().hex,user_id=row.user_id,case_id=case['case_id'],created=time.time(),read=False))
    return {'case_id':case['case_id'],'duplicate':False}

@router.get('')
def list_mailboxes(request: Request):
    user = require_user(request)
    with Session() as db:
        rows = db.scalars(select(Mailbox).where(Mailbox.user_id==user['id'])).all()
        return {'providers':{p:configured(p) for p in PROVIDERS}, 'mailboxes':[{'id':r.id,'provider':r.provider,'monitoring':r.monitoring,'checked_at':r.checked_at,'status':r.last_status} for r in rows]}

@router.post('/google-login/connect')
def google_login_connect():
    if not configured('gmail'): raise HTTPException(503,'Google login is not configured by the operator.')
    p, client, _, redirect = config('gmail')
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    with Session.begin() as db:
        db.execute(delete(OAuthState).where(OAuthState.expires < time.time()))
        db.add(OAuthState(digest=hashlib.sha256(state.encode()).hexdigest(),user_id='',provider='google-login',verifier=cipher().encrypt(verifier.encode()).decode(),expires=time.time()+600))
    params = dict(client_id=client,redirect_uri=redirect,response_type='code',scope='openid email profile',state=state,code_challenge=challenge,code_challenge_method='S256',prompt='select_account')
    return {'url':p['authorize']+'?'+urlencode(params)}

@router.post('/{provider}/connect')
def connect(provider: str, request: Request):
    user = require_user(request)
    if not configured(provider): raise HTTPException(503,'Provider OAuth credentials and token encryption must be configured by the operator.')
    p, client, _, redirect = config(provider)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    with Session.begin() as db:
        db.execute(delete(OAuthState).where(OAuthState.expires < time.time()))
        db.add(OAuthState(digest=hashlib.sha256(state.encode()).hexdigest(),user_id=user['id'],provider=provider,verifier=cipher().encrypt(verifier.encode()).decode(),expires=time.time()+600))
    params = dict(client_id=client,redirect_uri=redirect,response_type='code',scope=p['scope'],state=state,code_challenge=challenge,code_challenge_method='S256')
    if provider=='gmail': params.update(access_type='offline',prompt='consent')
    return {'url':p['authorize']+'?'+urlencode(params)}

@router.get('/{provider}/callback')
def callback(provider: str, request: Request, state: str='', code: str='', error: str=''):
    state_digest = hashlib.sha256(state.encode()).hexdigest()
    with Session.begin() as db:
        row = db.get(OAuthState,state_digest)
        if not row or row.expires<time.time(): raise HTTPException(400,'Invalid or expired OAuth state.')
        login_flow = provider=='gmail' and row.provider=='google-login'
        user = None if login_flow else require_user(request)
        if not login_flow and (row.user_id!=user['id'] or row.provider!=provider): raise HTTPException(400,'Invalid or expired OAuth state.')
        verifier = cipher().decrypt(row.verifier.encode()).decode()
    if error or not code:
        with Session.begin() as db: db.execute(delete(OAuthState).where(OAuthState.digest==state_digest))
        return RedirectResponse('/?login=cancelled' if login_flow else '/?mailbox=cancelled',status_code=303)
    p, client, secret, redirect = config(provider)
    value = json_fetch(p['token'],method='POST',data={'grant_type':'authorization_code','client_id':client,'client_secret':secret,'redirect_uri':redirect,'code':code,'code_verifier':verifier})
    if not value.get('access_token'): raise HTTPException(502,'Provider did not return an access token.')
    if login_flow:
        profile = json_fetch('https://openidconnect.googleapis.com/v1/userinfo',token=value['access_token'])
        if not profile.get('email') or profile.get('email_verified') is not True: raise HTTPException(403,'Google did not provide a verified email address.')
        with Session.begin() as db: db.execute(delete(OAuthState).where(OAuthState.digest==state_digest))
        response = RedirectResponse('/?login=success',status_code=303)
        google_user(profile['email'],response)
        return response
    value['expires_at'] = time.time()+int(value.get('expires_in',3600))
    with Session.begin() as db:
        db.execute(delete(OAuthState).where(OAuthState.digest==state_digest))
        db.add(Mailbox(id=uuid4().hex,user_id=user['id'],provider=provider,tokens=cipher().encrypt(json.dumps(value).encode()).decode(),monitoring=False,checked_at=0,last_status='CONNECTED'))
    return RedirectResponse('/?mailbox=connected',status_code=303)

@router.get('/{mailbox_id}/messages')
def inbox(mailbox_id: str, request: Request): return messages(owned(mailbox_id,require_user(request)['id']))

class MessageInput(BaseModel):
    message_id: str

@router.post('/{mailbox_id}/analyze')
async def analyze_selected(mailbox_id: str, data: MessageInput, request: Request):
    from fastapi.concurrency import run_in_threadpool
    row = owned(mailbox_id,require_user(request)['id'])
    if not data.message_id or len(data.message_id)>2048: raise HTTPException(422,'Invalid message ID.')
    async with request.app.state.analysis_slots:
        return await run_in_threadpool(analyze_message,row,data.message_id)

class MonitorInput(BaseModel):
    enabled: bool

@router.post('/{mailbox_id}/monitor')
def monitor(mailbox_id: str, data: MonitorInput, request: Request):
    owned(mailbox_id,require_user(request)['id'])
    with Session.begin() as db:
        row=db.get(Mailbox,mailbox_id); row.monitoring=data.enabled
    return {'enabled':data.enabled}

@router.post('/{mailbox_id}/check')
async def check_now(mailbox_id: str, request: Request):
    row=owned(mailbox_id,require_user(request)['id'])
    async with request.app.state.analysis_slots: await run_in_threadpool(check_mailbox,row.id,True)
    current=owned(row.id,row.user_id)
    return {'status':current.last_status,'checked_at':current.checked_at}

@router.delete('/{mailbox_id}')
def disconnect(mailbox_id: str, request: Request):
    owned(mailbox_id,require_user(request)['id'])
    with MAILBOX_LOCK, Session.begin() as db:
        db.execute(delete(MailMessage).where(MailMessage.mailbox_id==mailbox_id))
        db.delete(db.get(Mailbox,mailbox_id))
    return {'status':'Disconnected; local tokens removed. You can also revoke app access in your provider account.'}

def check_mailbox(mailbox_id, force=False):
    with Session() as db:
        row=db.get(Mailbox,mailbox_id)
        if not row or (not force and not row.monitoring): return
        db.expunge(row)
    try:
        batch=messages(row)
        failed=0
        for item in batch:
            with Session() as db:
                current=db.get(Mailbox,row.id)
                if not current or (not force and not current.monitoring): return
            try: analyze_message(row,item['id'])
            except Exception: failed+=1
        status='PARTIAL CHECK — some messages could not be analyzed' if failed else 'CHECKED LATEST 20 INBOX MESSAGES'
    except HTTPException as exc:
        status = 'AUTHORIZATION EXPIRED — reconnect mailbox' if exc.status_code == 401 else 'LOOKUP FAILED — retry or reconnect'
    except Exception: status='LOOKUP FAILED — retry or reconnect'
    with Session.begin() as db:
        current=db.get(Mailbox,row.id)
        if current: current.checked_at=time.time(); current.last_status=status

async def monitor_loop(app):
    from fastapi.concurrency import run_in_threadpool
    while True:
        await asyncio.sleep(120)
        with Session() as db: ids=list(db.scalars(select(Mailbox.id).where(Mailbox.monitoring==True)))
        for identifier in ids:
            async with app.state.analysis_slots: await run_in_threadpool(check_mailbox,identifier)

@router.get('/alerts/list')
def alerts(request: Request):
    user=require_user(request)
    with Session() as db:
        return [{'id':r.id,'case_id':r.case_id,'created':r.created,'read':r.read,'message':'High-risk email detected'} for r in db.scalars(select(Notice).where(Notice.user_id==user['id']).order_by(Notice.created.desc()).limit(100))]

@router.post('/alerts/{notice_id}/read')
def read_notice(notice_id: str, request: Request):
    user=require_user(request)
    with Session.begin() as db:
        row=db.get(Notice,notice_id)
        if not row or row.user_id!=user['id']: raise HTTPException(404,'Alert not found.')
        row.read=True
    return {'status':'read'}
