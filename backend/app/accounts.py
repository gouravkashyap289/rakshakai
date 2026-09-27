"""Local accounts with scrypt passwords and revocable opaque sessions."""
import hashlib
import hmac
import os
import re
import secrets
import time
from uuid import uuid4
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import String, Text, Float, select, delete
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.exc import IntegrityError
from .database import Base, Session, preferences, save_preferences

router = APIRouter(prefix='/api/auth')

class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password: Mapped[str] = mapped_column(Text)

class LoginSession(Base):
    __tablename__ = 'login_sessions'
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    expires: Mapped[float] = mapped_column(Float)

class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)

class PreferenceInput(BaseModel):
    retention_days: int = Field(default=30)
    mask_reports: bool = False

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest

def session_user(token):
    if not token or len(token) > 200: return None
    with Session() as db:
        row = db.get(LoginSession, hashlib.sha256(token.encode()).hexdigest())
        if not row or row.expires < time.time(): return None
        user = db.get(User, row.user_id)
        return {'id': user.id, 'email': user.email} if user else None

def require_user(request):
    user = getattr(request.state, 'user', None)
    if not user: raise HTTPException(401, 'Sign in to connect a mailbox.')
    return user

def issue_session(user, response):
    token = secrets.token_urlsafe(48)
    with Session.begin() as db:
        db.execute(delete(LoginSession).where(LoginSession.expires < time.time()))
        db.add(LoginSession(digest=hashlib.sha256(token.encode()).hexdigest(), user_id=user['id'], expires=time.time()+604800))
    response.set_cookie('rakshak-login', token, httponly=True, secure=os.getenv('COOKIE_SECURE','false')=='true', samesite='lax', max_age=604800)
    return user

def google_user(email, response):
    """Open an account only after Google has returned a verified email."""
    address = email_value(email)
    with Session.begin() as db:
        row = db.scalar(select(User).where(User.email == address))
        if not row:
            row = User(id=uuid4().hex, email=address, password=password_hash(secrets.token_urlsafe(32)))
            db.add(row)
        user = {'id': row.id, 'email': row.email}
    return issue_session(user, response)

def email_value(value):
    value = value.strip().lower()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value): raise HTTPException(422, 'Enter a valid email address.')
    return value

@router.post('/register')
def register(data: Credentials, response: Response):
    user = {'id': uuid4().hex, 'email': email_value(data.email)}
    try:
        with Session.begin() as db: db.add(User(**user, password=password_hash(data.password)))
    except IntegrityError: raise HTTPException(409, 'Registration unavailable for this address. Try signing in.')
    return issue_session(user, response)

@router.post('/login')
def login(data: Credentials, response: Response):
    with Session() as db:
        user = db.scalar(select(User).where(User.email == email_value(data.email)))
        saved = user.password if user else password_hash('dummy comparison password', '0'*32)
        check = password_hash(data.password, saved.split(':')[0])
        if not hmac.compare_digest(saved, check) or not user: raise HTTPException(401, 'Email or password is incorrect.')
        value = {'id': user.id, 'email': user.email}
    return issue_session(value, response)

@router.get('/me')
def me(request: Request):
    return {'user': getattr(request.state, 'user', None)}

@router.get('/preferences')
def get_preferences(request: Request):
    return preferences(require_user(request)['id'])

@router.put('/preferences')
def update_preferences(data: PreferenceInput, request: Request):
    user=require_user(request)
    if data.retention_days not in (0,7,30,90,365): raise HTTPException(422,'Choose a supported retention period.')
    return save_preferences(user['id'],data.retention_days,data.mask_reports)

@router.post('/logout')
def logout(request: Request, response: Response):
    token = request.cookies.get('rakshak-login', '')
    with Session.begin() as db: db.execute(delete(LoginSession).where(LoginSession.digest == hashlib.sha256(token.encode()).hexdigest()))
    response.delete_cookie('rakshak-login')
    return {'status': 'signed out'}
