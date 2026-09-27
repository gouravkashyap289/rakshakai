from io import BytesIO
from xml.sax.saxutils import escape
import re
from pathlib import Path
from functools import lru_cache

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


@lru_cache(maxsize=1)
def font_name():
    for location in ('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 'C:/Windows/Fonts/arial.ttf'):
        if Path(location).exists():
            pdfmetrics.registerFont(TTFont('RakshakSans', location))
            return 'RakshakSans'
    return 'Helvetica'


def report(case, feedback=None):
    """Generate a concise, public-facing two-page email security report."""
    buffer = BytesIO()
    font = font_name()
    styles = getSampleStyleSheet()
    ink, accent = colors.HexColor('#132437'), colors.HexColor('#a35b2d')
    pale, line, muted = colors.HexColor('#f3f5f6'), colors.HexColor('#d0d8df'), colors.HexColor('#657587')
    styles.add(ParagraphStyle(name='RTitle', fontName=font, fontSize=20, leading=23, textColor=ink, spaceAfter=3))
    styles.add(ParagraphStyle(name='RSub', fontName=font, fontSize=8, leading=11, textColor=muted, spaceAfter=8))
    styles.add(ParagraphStyle(name='RHeading', fontName=font, fontSize=11, leading=13, textColor=accent, spaceBefore=7, spaceAfter=4, keepWithNext=True))
    styles.add(ParagraphStyle(name='RBody', fontName=font, fontSize=7.7, leading=10.2, textColor=ink, spaceAfter=2.5, wordWrap='CJK'))
    styles.add(ParagraphStyle(name='RSmall', fontName=font, fontSize=6.7, leading=8.6, textColor=muted, spaceAfter=1.5, wordWrap='CJK'))

    def clean(value):
        text = str(value) if value not in (None, '') else 'UNKNOWN'
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
        return escape(text.replace('\u2014', '-').replace('\u2192', '->').replace('\u2260', '!='))

    def p(value, style='RBody'):
        return Paragraph(clean(value), styles[style])

    def rich(value, style='RBody'):
        return Paragraph(value, styles[style])

    def val(data, *keys):
        current = data
        for key in keys:
            current = current.get(key) if isinstance(current, dict) else None
        return 'UNKNOWN' if current in (None, '', []) else current

    def field(label, value, small=False):
        return rich(f'<b>{clean(label)}:</b> {clean(value)}', 'RSmall' if small else 'RBody')

    def section(title, items):
        return KeepTogether([p(title, 'RHeading')] + items)

    def styled_table(rows, widths, header=True):
        table = Table(rows, colWidths=widths)
        rules = [('BOX', (0, 0), (-1, -1), .5, line), ('INNERGRID', (0, 0), (-1, -1), .25, line),
                 ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 6),
                 ('RIGHTPADDING', (0, 0), (-1, -1), 6), ('TOPPADDING', (0, 0), (-1, -1), 4),
                 ('BOTTOMPADDING', (0, 0), (-1, -1), 4)]
        if header:
            rules.append(('BACKGROUND', (0, 0), (-1, 0), pale))
        table.setStyle(TableStyle(rules))
        return table

    def domain_age(days):
        if not isinstance(days, int):
            return 'UNKNOWN'
        years, remainder = divmod(days, 365)
        months = remainder // 30
        return f'{years}y {months}m' if years else f'{months}m'

    email, auth = case.get('email') or {}, case.get('auth') or {}
    sender = case.get('sender_analysis') or {}
    from .origin_analyzer import trace_origin
    origin = case.get('origin') or trace_origin(email, case.get('ips') or [])

    story = [p('RAKSHAK - Email Security Report', 'RTitle'),
             p(f"Case {case.get('case_id', 'UNKNOWN')} | {case.get('created_at', 'UNKNOWN')} | {case.get('filename', 'UNKNOWN')}", 'RSub')]
    story.append(styled_table([
        [p('SECURITY RISK', 'RSmall'), p('EVIDENCE COVERAGE', 'RSmall'), p('ASSESSMENT', 'RSmall')],
        [p(f"{case.get('risk_score', 0)}/100 - {case.get('risk_level', 'UNKNOWN')}"), p(f"{case.get('confidence', 0)}%"), p(case.get('threat_category', 'UNKNOWN'))],
    ], [155, 155, 195]))

    identity = styled_table([
        [field('From', email.get('from')), field('To', email.get('to'))],
        [field('Reply-To', email.get('reply_to')), field('Return-Path', email.get('return_path'))],
        [field('Subject', email.get('subject')), field('Date', email.get('date'))],
    ], [252, 253], header=False)
    story.append(section('Who sent the email, and to whom?', [identity]))

    auth_rows = [[p('CHECK', 'RSmall'), p('RESULT', 'RSmall'), p('EXPLANATION', 'RSmall')]]
    for protocol in ('SPF', 'DKIM', 'DMARC'):
        result = auth.get(protocol, 'UNKNOWN')
        if isinstance(result, dict):
            status = result.get('status') or result.get('result') or 'UNKNOWN'
            explanation = result.get('explanation') or result.get('reason') or ''
        else:
            status, explanation = result, ''
        auth_rows.append([p(protocol, 'RSmall'), p(status), p(explanation, 'RSmall')])
    story.append(section('Sender authentication', [styled_table(auth_rows, [70, 90, 345])]))

    sender_items = []
    for signal in sender.get('signals') or []:
        sender_items.append(rich(f"<b>{clean(signal.get('signal'))}</b> - {clean(signal.get('evidence'))}", 'RSmall'))
    story.append(section('Sender identity checks', sender_items or [p('No sender mismatch evidence was found.', 'RSmall')]))

    evidence = sorted(case.get('evidence') or [], key=lambda x: x.get('contribution', 0) if isinstance(x, dict) else 0, reverse=True)[:7]
    evidence_items = []
    for item in evidence:
        if isinstance(item, dict):
            points = item.get('contribution', 0)
            title = item.get('title') or item.get('signal') or item.get('reason') or 'Finding'
            detail = item.get('evidence') or item.get('explanation') or item.get('source') or ''
            evidence_items.append(rich(f'<b>+{clean(points)} {clean(title)}</b> - {clean(detail)}', 'RSmall'))
    story.append(section('Why Rakshak assigned this score', evidence_items or [p('No weighted suspicious evidence was found.', 'RSmall')]))

    story += [PageBreak(), p('Email infrastructure and evidence', 'RTitle'),
              p("Mail-server location is not sender location. If the email provider omits the sender device IP, the writer's physical location cannot be determined.", 'RSub')]
    location = ' / '.join(str(val(origin, key)) for key in ('country', 'region', 'city'))
    story.append(section('Origin and email-delivery route', [
        field('Sender phone/computer IP', f"{val(origin, 'sender_device_ip')} ({val(origin, 'sender_device_ip_status')})"),
        field('Person location', val(origin, 'sender_location') if origin.get('sender_device_ip') else 'CANNOT BE DETERMINED'),
        field('Mail-delivery server IP', val(origin, 'earliest_observed_ip')),
        field('Mail-server country / region / city', location),
        field('Hosting ASN / network', f"{val(origin, 'asn')} / {val(origin, 'organization')}"),
    ]))

    domain_rows = [[p('DOMAIN', 'RSmall'), p('REGISTERED', 'RSmall'), p('AGE', 'RSmall'), p('REGISTRAR', 'RSmall'), p('REGISTRANT / COUNTRY', 'RSmall')]]
    for entry in (case.get('domains') or [])[:4]:
        if isinstance(entry, dict):
            registered = str(entry.get('creation_date') or 'UNKNOWN').split('T')[0]
            registrant = ' / '.join(str(value) for value in (entry.get('registrant_organization'), entry.get('registrant_country')) if value) or 'UNKNOWN'
            domain_rows.append([p(entry.get('domain') or entry.get('value')), p(registered, 'RSmall'), p(domain_age(entry.get('age_days')), 'RSmall'), p(entry.get('registrar'), 'RSmall'), p(registrant, 'RSmall')])
    if len(domain_rows) == 1:
        domain_rows.append([p('DATA NOT AVAILABLE', 'RSmall'), '', '', '', ''])
    story.append(section('Domain registration details', [styled_table(domain_rows, [125, 75, 52, 93, 160])]))

    ip_rows = [[p('IP ADDRESS', 'RSmall'), p('INFRASTRUCTURE LOCATION', 'RSmall'), p('ASN / NETWORK', 'RSmall'), p('INDICATORS', 'RSmall')]]
    for entry in (case.get('ips') or [])[:5]:
        if isinstance(entry, dict):
            geo = ' / '.join(str(entry.get(k) or 'UNKNOWN') for k in ('country', 'region', 'city'))
            network = entry.get('asn') or entry.get('organization') or entry.get('isp') or 'UNKNOWN'
            flags = ', '.join(k.upper() for k in ('vpn', 'proxy', 'tor', 'hosting') if entry.get(k) is True) or 'None reported'
            ip_rows.append([p(entry.get('ip') or entry.get('value')), p(geo, 'RSmall'), p(network, 'RSmall'), p(flags, 'RSmall')])
    if len(ip_rows) == 1:
        ip_rows.append([p('DATA NOT AVAILABLE', 'RSmall'), '', '', ''])
    story.append(section('IP infrastructure geolocation (not person location)', [styled_table(ip_rows, [125, 145, 140, 95])]))

    attachments = []
    for item in (case.get('attachments') or [])[:4]:
        if isinstance(item, dict):
            attachments.append(rich(f"<b>{clean(item.get('filename'))}</b> | {clean(item.get('mime_type'))} | {clean(item.get('size'))} bytes | SHA-256: {clean(item.get('sha256'))} | Risk: {clean(item.get('risk') or item.get('risk_level'))}", 'RSmall'))
    story.append(section('Attachments', attachments or [p('No attachments found.', 'RSmall')]))

    advice = 'Do not open links or attachments until the sender is verified through a trusted channel.' if case.get('risk_score', 0) >= 31 else 'No strong threat pattern was found; independently verify unexpected requests before acting.'
    story.append(section('Recommended action', [p(advice, 'RSmall'), p('Preserve the original .eml file for any incident review.', 'RSmall')]))
    story.append(p('Limits: Header routes can be forged; geolocation is approximate; unavailable data is shown as UNKNOWN or DATA NOT AVAILABLE.', 'RSmall'))

    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=45, leftMargin=45, topMargin=42, bottomMargin=42,
                            title='Rakshak Email Security Report', author='Rakshak AI')

    def footer(canvas, doc):
        canvas.setStrokeColor(line)
        canvas.line(45, 30, A4[0] - 45, 30)
        canvas.setFont(font, 7)
        canvas.setFillColor(muted)
        canvas.drawString(45, 18, f"{case.get('case_id', 'UNKNOWN')} | RAKSHAK")
        canvas.drawRightString(A4[0] - 45, 18, f'Page {doc.page} of 2')

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
