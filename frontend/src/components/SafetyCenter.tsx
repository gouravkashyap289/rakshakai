import { AlertTriangle, BadgeIndianRupee, CheckCircle2, ExternalLink, KeyRound, MessageSquareWarning, PhoneCall, QrCode, ShieldCheck } from 'lucide-react';

const scams = [
  {icon:BadgeIndianRupee,title:'Payment and UPI fraud',body:'Treat unexpected payment requests, changed bank details, collect requests and “refund” links as high-risk until independently verified.'},
  {icon:KeyRound,title:'KYC and account warnings',body:'Banks and public services should never need your password, card PIN or OTP by email. Open the official app yourself instead.'},
  {icon:QrCode,title:'QR-code traps',body:'A QR code can hide a web address or payment request. Do not scan one from an unexpected email before verifying its source.'},
  {icon:MessageSquareWarning,title:'Urgency and authority',body:'Threats of arrest, account closure, lost parcels or executive pressure are designed to prevent careful verification.'},
];

export default function SafetyCenter(){
  return <div className="page-shell wrap">
    <section className="page-hero safety-hero"><div><span className="eyebrow">RAKSHAK SAFETY CENTER</span><h1>Know the pattern.<br/><span>Break the scam.</span></h1><p>Practical guidance for suspicious emails, written for everyday users—not security specialists.</p></div><div className="trust-orbit"><ShieldCheck size={42}/><strong>Pause</strong><span>Verify through a channel you already trust</span></div></section>
    <section className="safety-grid" aria-label="Common scam patterns">{scams.map(({icon:Icon,title,body})=><article key={title}><Icon/><h2>{title}</h2><p>{body}</p></article>)}</section>
    <section className="response-playbook"><div><span className="eyebrow">IF YOU ALREADY INTERACTED</span><h2>Act in the right order.</h2><p>Preserve the original email and the Rakshak report. Do not continue the conversation with the sender.</p></div><ol><li><strong>Entered a password?</strong><span>Change it from the official service, end other sessions and enable two-step verification.</span></li><li><strong>Shared an OTP or paid?</strong><span>Contact your bank immediately using the number on its official site or your card.</span></li><li><strong>Opened a file?</strong><span>Disconnect the device from sensitive accounts and run an updated security scan.</span></li><li><strong>Need to report it?</strong><span>Keep the email, payment reference, phone number and downloaded forensic report together.</span></li></ol></section>
    <section className="verification-card"><AlertTriangle/><div><h2>Verify outside the message</h2><p>Search for the organization independently or use its official application. Never use the phone number, reply address or login link supplied by the suspicious email itself.</p></div><a href="#analyze">Check an email <ExternalLink size={15}/></a></section>
    <section className="safe-signals"><div><CheckCircle2/><span><strong>Rakshak reports evidence</strong><small>It does not claim to identify a person’s physical location.</small></span></div><div><PhoneCall/><span><strong>Independent verification wins</strong><small>A known phone number is stronger than a convincing display name.</small></span></div></section>
  </div>;
}
