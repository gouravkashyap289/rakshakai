from datetime import datetime, timezone, timedelta
import hashlib
import json
from sqlalchemy import create_engine, String, Integer, JSON, DateTime, Boolean, select, delete
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import DATABASE_URL

class Base(DeclarativeBase):
    pass

class Investigation(Base):
    __tablename__ = 'investigations'
    case_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=lambda: datetime.now(timezone.utc))
    risk_score: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)

class Feedback(Base):
    __tablename__ = 'feedback'
    case_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(30))
    notes: Mapped[str] = mapped_column(String(2000))

class CaseAccess(Base):
    __tablename__ = 'case_access'
    case_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    visitor: Mapped[str] = mapped_column(String(64), index=True)

class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(40), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    action: Mapped[str] = mapped_column(String(60))
    actor: Mapped[str] = mapped_column(String(60))
    details: Mapped[dict] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)

class UserPreference(Base):
    __tablename__ = 'user_preferences'
    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    mask_reports: Mapped[bool] = mapped_column(Boolean, default=False)

engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
Session = sessionmaker(engine)

def init_db():
    Base.metadata.create_all(engine)

def add_audit(case_id, action, details=None, actor='Rakshak service'):
    occurred = datetime.now(timezone.utc)
    details = details or {}
    with Session.begin() as db:
        previous = db.scalar(select(AuditEvent).where(AuditEvent.case_id==case_id).order_by(AuditEvent.id.desc()).limit(1))
        previous_hash = previous.event_hash if previous else '0'*64
        content = '|'.join((previous_hash,case_id,occurred.isoformat(),action,actor,json.dumps(details,sort_keys=True,separators=(',',':'))))
        event_hash = hashlib.sha256(content.encode()).hexdigest()
        db.add(AuditEvent(case_id=case_id,occurred_at=occurred,action=action,actor=actor,details=details,previous_hash=previous_hash,event_hash=event_hash))

def list_audit(case_id):
    with Session() as db:
        rows=db.scalars(select(AuditEvent).where(AuditEvent.case_id==case_id).order_by(AuditEvent.id)).all()
        return [{'timestamp':r.occurred_at.isoformat(),'action':r.action,'actor':r.actor,'details':r.details,'previous_hash':r.previous_hash,'event_hash':r.event_hash} for r in rows]

def preferences(user_id):
    with Session() as db:
        row=db.get(UserPreference,user_id)
        return {'retention_days':row.retention_days,'mask_reports':row.mask_reports} if row else {'retention_days':30,'mask_reports':False}

def save_preferences(user_id, retention_days, mask_reports):
    with Session.begin() as db: db.merge(UserPreference(user_id=user_id,retention_days=retention_days,mask_reports=mask_reports))
    purge_expired(user_id,retention_days)
    return preferences(user_id)

def purge_expired(visitor, days):
    if not days: return 0
    cutoff=datetime.now(timezone.utc)-timedelta(days=days)
    with Session() as db:
        ids=list(db.scalars(select(Investigation.case_id).join(CaseAccess,CaseAccess.case_id==Investigation.case_id).where(CaseAccess.visitor==visitor,Investigation.created_at<cutoff)))
    return sum(delete_case(case_id,visitor) for case_id in ids)

def save_case(case, visitor=None):
    with Session.begin() as db:
        db.add(Investigation(case_id=case['case_id'], risk_score=case['risk_score'], payload=case))
        if visitor:
            db.add(CaseAccess(case_id=case['case_id'], visitor=visitor))
    add_audit(case['case_id'],'ANALYSIS COMPLETED',{'email_sha256':case.get('email_sha256'),'risk_score':case.get('risk_score'),'filename':case.get('filename')})

def get_case(case_id, visitor=None):
    with Session() as db:
        if visitor:
            access = db.get(CaseAccess, case_id)
            if not access or access.visitor != visitor: return None
        row = db.get(Investigation, case_id)
        return row.payload if row else None

def list_cases(limit=200, offset=0, visitor=None):
    with Session() as db:
        query = select(Investigation)
        if visitor:
            query = query.join(CaseAccess, CaseAccess.case_id == Investigation.case_id).where(CaseAccess.visitor == visitor)
        return [r.payload for r in db.scalars(query.order_by(Investigation.created_at.desc()).limit(limit).offset(offset))]

def delete_case(case_id, visitor):
    with Session.begin() as db:
        access = db.get(CaseAccess, case_id)
        if not access or access.visitor != visitor: return False
        # Related-case payloads may contain shared indicators from this email.
        for row in db.scalars(select(Investigation).join(CaseAccess, CaseAccess.case_id == Investigation.case_id).where(CaseAccess.visitor == visitor)):
            if row.case_id != case_id:
                payload = dict(row.payload)
                payload['campaigns'] = [c for c in payload.get('campaigns', []) if c['case_id'] != case_id]
                from .services.forensic_graph import build_graph
                payload['graph'] = build_graph(payload)
                row.payload = payload
        feedback = db.get(Feedback, case_id)
        if feedback: db.delete(feedback)
        db.execute(delete(AuditEvent).where(AuditEvent.case_id==case_id))
        from .mailboxes import MailMessage, Notice
        for item in db.scalars(select(MailMessage).where(MailMessage.case_id==case_id)):
            item.case_id='DELETED'
        for item in db.scalars(select(Notice).where(Notice.case_id==case_id)): db.delete(item)
        row = db.get(Investigation, case_id)
        if row: db.delete(row)
        db.delete(access)
        return True
