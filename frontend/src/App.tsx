import { useEffect, useRef, useState } from 'react';
import { ArrowRight, ArrowUpRight, BookOpen, Check, ChevronDown, FileText, Fingerprint, History, Inbox, LoaderCircle, LockKeyhole, Mail, Paperclip, ShieldCheck, Sparkles, Trash2, Upload, UserCircle, X } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import { api, upload } from './services/api';
import PublicResult from './components/PublicResult';
import AccountPanel from './components/AccountPanel';
import SafetyCenter from './components/SafetyCenter';

type Page='analyze'|'investigations'|'mailboxes'|'safety'|'privacy';

export default function App() {
  const [file,setFile]=useState<File|null>(null), [result,setResult]=useState<any>(null);
  const [busy,setBusy]=useState(false), [progress,setProgress]=useState(0), [error,setError]=useState('');
  const [dragging,setDragging]=useState(false), [samples,setSamples]=useState(false), [checks,setChecks]=useState<any[]>([]);
  const [settings,setSettings]=useState<any>(null), [ready,setReady]=useState(false), [confirmDelete,setConfirmDelete]=useState('');
  const [deleting,setDeleting]=useState(''), [page,setPage]=useState<Page>(()=>{
    const value=location.hash.slice(1) as Page; return ['analyze','investigations','mailboxes','safety','privacy'].includes(value)?value:'analyze';
  });
  const input=useRef<HTMLInputElement>(null), resultRef=useRef<HTMLDivElement>(null);
  useEffect(()=>{const change=()=>{const value=location.hash.slice(1) as Page;if(['analyze','investigations','mailboxes','safety','privacy'].includes(value))setPage(value);};addEventListener('hashchange',change);return()=>removeEventListener('hashchange',change);},[]);
  function go(next:Page){location.hash=next;setPage(next);scrollTo({top:0,behavior:'smooth'});}
  function accountChanged(){setResult(null);sessionStorage.removeItem('rakshak-current');void api('/investigations').then(setChecks).catch(e=>setError(e.message));}
  useEffect(()=>{let active=true; (async()=>{
    try {
      const config=await api('/settings'); if(!active)return; setSettings(config);
      const saved=await api('/investigations'); if(!active)return; setChecks(saved);
      const last=sessionStorage.getItem('rakshak-current');
      if(last&&saved.some((c:any)=>c.case_id===last)){const c=await api('/investigations/'+last);if(active)setResult(c);}
      if(active)setReady(true);
    }catch(e){if(active)setError((e as Error).message);}
  })();return()=>{active=false;};},[]);
  function choose(next:File) {
    if(!next.name.toLowerCase().endsWith('.eml')){setError('Please choose an original email file ending in .eml.');return;}
    if(next.size>10*1024*1024){setError('This email is larger than 10 MB. Please choose a smaller .eml file.');return;}
    if(next.size===0){setError('This file is empty. Download the original email and try again.');return;}
    setFile(next);setError('');
  }
  async function analyze(sample?:string) {
    if(busy||!ready||(!file&&!sample))return;
    setBusy(true);setProgress(0);setError('');
    try {
      const next=sample?await api('/demo/'+sample,{method:'POST'}):await upload(file!,setProgress);
      setResult(next);sessionStorage.setItem('rakshak-current',next.case_id);setFile(null);setSamples(false);setPage('investigations');location.hash='investigations';
      setChecks(await api('/investigations'));
      requestAnimationFrame(()=>resultRef.current?.scrollIntoView({behavior:'smooth',block:'start'}));
    }catch(e){setError((e as Error).message);}finally{setBusy(false);}
  }
  async function open(id:string){try{setResult(await api('/investigations/'+id));sessionStorage.setItem('rakshak-current',id);setPage('investigations');location.hash='investigations';requestAnimationFrame(()=>resultRef.current?.scrollIntoView({behavior:'smooth'}));}catch(e){setError((e as Error).message);}}
  async function remove(id:string){setDeleting(id);try{await api('/investigations/'+id,{method:'DELETE'});setChecks(await api('/investigations'));if(result?.case_id===id){setResult(null);sessionStorage.removeItem('rakshak-current');}else if(result){setResult(await api('/investigations/'+result.case_id));}setConfirmDelete('');}catch(e){setError((e as Error).message);}finally{setDeleting('');}}
  const nav:[Page,string,React.ReactNode][]=[['analyze','Analyze',<ShieldCheck size={16}/>],['investigations','My checks',<History size={16}/>],['mailboxes','Mailboxes',<Inbox size={16}/>],['safety','Safety center',<BookOpen size={16}/>],['privacy','Account',<UserCircle size={16}/>]];
  return <div className="public-app">
    <header className="site-header"><button className="wordmark" onClick={()=>go('analyze')} aria-label="Rakshak home"><span><ShieldCheck size={25}/></span>RAKSHAK<span className="brand-divider"/><small>Email safety, explained.</small></button><nav aria-label="Main navigation">{nav.map(([id,label,icon])=><button key={id} className={page===id?'nav-active':''} onClick={()=>go(id)}>{icon}{label}</button>)}</nav><span className="live-status"><i/> Protection ready</span></header>
    <main>
      {page==='analyze'&&<>
      <section className="hero wrap" id="check">
        <div className="hero-copy"><div className="eyebrow"><span className="orange-dot"/> A LITTLE CAUTION. A LOT MORE CLARITY.</div><h1>A suspicious email?<br/>Let’s take a<br/><span>closer look.</span></h1><p className="hero-description">Before you click, reply, or download. Let Rakshak check the message, trace its sending route, and explain the warning signs.</p><div className="hero-checks"><span><Check size={16}/> Understand the risk</span><span><Check size={16}/> Get the evidence</span><span><Check size={16}/> Download your report</span></div><div className="engine-note"><span className="engine-icon"><Sparkles size={21}/></span><div><strong>Powered by Rakshak AI</strong><small>Content analysis meets email forensics.</small></div></div></div>
        <div className="upload-panel"><div className="upload-heading"><span className="step-label">01 / START HERE</span><span className="private-tag"><LockKeyhole size={12}/> Your private check</span></div><h2>Check your email</h2><p>Upload the original email. We’ll take it from here.</p>
          <input ref={input} id="email-file" className="visually-hidden" type="file" accept=".eml,message/rfc822" disabled={busy} onChange={e=>{if(e.target.files?.[0])choose(e.target.files[0]);e.target.value='';}}/>
          <button type="button" className={`dropzone ${dragging?'dragging':''} ${file?'has-file':''}`} disabled={busy} onClick={()=>input.current?.click()} onDragOver={e=>{e.preventDefault();if(!busy)setDragging(true);}} onDragLeave={()=>setDragging(false)} onDrop={e=>{e.preventDefault();setDragging(false);if(!busy&&e.dataTransfer.files[0])choose(e.dataTransfer.files[0]);}}>
            <span className="file-symbol">{file?<FileText size={29}/>:<Upload size={29}/>}</span><strong>{file?file.name:'Drop your email here'}</strong><span>{file?`${(file.size/1024).toFixed(1)} KB · Click to choose another file`:<>or <u>browse files</u> on your device</>}</span><small>.EML FILES ONLY <i/> UP TO 10 MB</small>
          </button>
          <button className="primary analyze-button" disabled={busy||!file||!ready} onClick={()=>void analyze()}>{busy?<><LoaderCircle className="spin" size={18}/>{progress>0&&progress<100?`Uploading ${progress}%`:'Analyzing your email…'}</>:<>Analyze email <ArrowRight size={18}/></>}</button>
          {busy&&<div className="analysis-status" role="status"><div className="busy-track"><motion.span animate={{x:['-100%','330%']}} transition={{repeat:Infinity,duration:1.5,ease:'linear'}}/></div><small>Checking content, headers, links and attachments. Please keep this page open.</small></div>}
          <div className="upload-footnote"><ShieldCheck size={15}/><span>Attachments are inspected without opening or running them.</span></div>
          <details className="download-help"><summary>How do I get an .eml file? <ChevronDown size={14}/></summary><p>Open the email in your mail app and look for <strong>Download message</strong>, <strong>Download original</strong>, or <strong>Save as</strong>. Choose the .eml format. Forwarding or taking a screenshot loses important header evidence.</p></details>
          <div className="sample-row"><span>Just exploring?</span><button className="text-button" disabled={busy||!ready} onClick={()=>setSamples(!samples)}>Try a sample email <ArrowUpRight size={14}/></button></div>
          {samples&&<div className="sample-options"><button disabled={busy} onClick={()=>void analyze('safe_email')}>Everyday message</button><button disabled={busy} onClick={()=>void analyze('phishing_email')}>Phishing example</button><button disabled={busy} onClick={()=>void analyze('suspicious_attachment')}>Attachment warning</button><small>Fictional messages, analyzed by the same engine.</small></div>}
          <p className="processing-note">Your email is processed on this server. {settings?.network_lookups?'Extracted indicators may be checked with external intelligence services.':'External intelligence lookups are currently disabled.'} <a href="#privacy">About your data</a></p>
        </div>
      </section>
      {error&&<div className="error wrap" role="alert"><span>{error}</span>{!ready&&<button onClick={()=>window.location.reload()}>Reconnect</button>}<button className="icon-button" aria-label="Dismiss error" onClick={()=>setError('')}><X size={18}/></button></div>}
      <div className="scope-bar wrap"><span>ONE EMAIL.<br/><strong>Three layers of insight.</strong></span><div><Mail/><span><strong>What it says</strong><small>Language, links & requests</small></span></div><div><Fingerprint/><span><strong>Where it came from</strong><small>Sender identity & email route</small></span></div><div><Paperclip/><span><strong>What it carries</strong><small>File types & attachment fingerprints</small></span></div></div>
      <section className="how-section wrap"><div className="section-heading"><div><span className="eyebrow">FROM UNCERTAINTY TO UNDERSTANDING</span><h2>A clearer answer, in three steps.</h2></div><p>No technical knowledge needed.</p></div><div className="how-grid">{[['01','Bring the original email','Upload a .eml file to preserve its message, attachments and sending headers.'],['02','See what deserves attention','Get a security risk score and plain-language findings linked to the evidence.'],['03','Keep a complete record','Download a PDF with the checks, observed IPs, available locations and recommended next steps.']].map(([n,title,body])=><article key={n}><span>{n}</span><h3>{title}</h3><p>{body}</p></article>)}</div></section>
      </>}
      {page==='investigations'&&<div className="page-shell wrap"><div className="page-heading"><div><span className="eyebrow">PRIVATE CASE WORKSPACE</span><h1>My investigations</h1><p>Review every saved check, reopen its evidence, or remove it permanently.</p></div><button className="primary" onClick={()=>go('analyze')}><Upload size={17}/> Check another email</button></div>
      <div ref={resultRef} className="result-anchor"><AnimatePresence mode="wait">{result&&<motion.div key={result.case_id} initial={{opacity:0,y:16}} animate={{opacity:1,y:0}} exit={{opacity:0}}><PublicResult investigation={result}/></motion.div>}</AnimatePresence></div>
      {checks.length>0?<section className="recent"><div className="section-heading"><div><span className="eyebrow">CASE HISTORY</span><h2>Saved checks</h2></div><small>Private to your account or guest session</small></div><div className="recent-list">{checks.map(c=><div className="recent-row" key={c.case_id}><FileText size={19}/><button className="recent-open" onClick={()=>void open(c.case_id)}><strong>{c.subject||'Untitled email'}</strong><small>{c.demo?'Sample email · ':''}{new Date(c.created_at).toLocaleString()}</small></button><span className={'pill '+c.risk_level}>{c.risk_level} risk · {c.risk_score}/100</span>{confirmDelete===c.case_id?<div className="delete-actions"><span>Delete saved result?</span><button disabled={!!deleting} onClick={()=>void remove(c.case_id)}>Delete</button><button onClick={()=>setConfirmDelete('')}>Cancel</button></div>:<button className="icon-button" disabled={!!deleting} aria-label={'Delete result for '+c.subject} onClick={()=>setConfirmDelete(c.case_id)}><Trash2 size={16}/></button>}</div>)}</div></section>:<div className="empty-page"><History/><h2>No investigations yet</h2><p>Upload an original email or try a safe demonstration.</p><button className="primary" onClick={()=>go('analyze')}>Start a check</button></div>}</div>}
      {page==='mailboxes'&&<div className="page-shell"><div className="page-heading wrap"><div><span className="eyebrow">READ-ONLY CONNECTIONS</span><h1>Connected mailboxes</h1><p>Review selected Gmail or Outlook messages without giving Rakshak permission to send or delete mail.</p></div></div><AccountPanel view="mailboxes" defaultExpanded onChange={accountChanged} onOpen={id=>void open(id)}/></div>}
      {page==='safety'&&<SafetyCenter/>}
      {page==='privacy'&&<div className="page-shell"><div className="page-heading wrap"><div><span className="eyebrow">ACCOUNT & PRIVACY</span><h1>You control the evidence.</h1><p>Choose retention, redact downloaded reports and manage your Rakshak session.</p></div></div><AccountPanel view="account" defaultExpanded onChange={accountChanged} onOpen={id=>void open(id)}/><section className="privacy-section wrap"><div className="privacy-icon"><LockKeyhole size={28}/></div><div><span className="eyebrow">CLEAR BOUNDARIES</span><h2>What Rakshak stores and shares</h2><p>Core detection runs on this server. Saved results include extracted message content and metadata; the original upload and attachment bytes are not retained. If you request a Gemini summary, only selected security findings are sent to Google.</p><details><summary>Analysis limits and external services <ChevronDown size={15}/></summary><p>If external intelligence is enabled, extracted IPs, domains, URLs and hashes may be queried with configured providers. A low score is not a guarantee of safety. Infrastructure location cannot establish a person’s physical location.</p></details></div></section></div>}
    </main><footer className="site-footer wrap"><button className="wordmark" onClick={()=>go('analyze')}><ShieldCheck size={23}/>RAKSHAK</button><span>Pause before you click.</span><button className="text-button" onClick={()=>go('privacy')}>Privacy & analysis limits <ArrowUpRight size={13}/></button></footer>
  </div>;
}
