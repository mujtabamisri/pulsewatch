import express from 'express';
import cors from 'cors';
import initSqlJs, { type Database } from 'sql.js';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import { resolve4, resolve6 } from 'node:dns/promises';
import PDFDocument from 'pdfkit';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../');
const dataDir = process.env.PULSEWATCH_DATA_DIR || path.join(root, 'data');
const dbFile = path.join(dataDir, 'pulsewatch.sqlite');
await mkdir(dataDir, { recursive: true });
const SQL = await initSqlJs();
const db: Database = existsSync(dbFile) ? new SQL.Database(new Uint8Array(await readFile(dbFile))) : new SQL.Database();
db.run(`CREATE TABLE IF NOT EXISTS monitors (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, interval_seconds INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checks (id TEXT PRIMARY KEY, monitor_id TEXT NOT NULL, checked_at TEXT NOT NULL, success INTEGER NOT NULL, status_code INTEGER, response_ms INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, monitor_id TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT, reason TEXT NOT NULL);`);
db.run(`CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY, monitor_id TEXT NOT NULL, audited_at TEXT NOT NULL, score INTEGER NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS diagnostics (id TEXT PRIMARY KEY, monitor_id TEXT NOT NULL, checked_at TEXT NOT NULL, kind TEXT NOT NULL, details TEXT NOT NULL);`);
let saving = Promise.resolve();
function persist() { const bytes = db.export(); saving = saving.then(() => writeFile(dbFile, Buffer.from(bytes))); return saving; }
function rows(sql: string, params: (string | number)[] = []) { const statement = db.prepare(sql); statement.bind(params); const result: Record<string, unknown>[] = []; while (statement.step()) result.push(statement.getAsObject()); statement.free(); return result; }
function isPrivateIP(ip: string) {
  if (net.isIP(ip) === 4) { const p = ip.split('.').map(Number); return p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || (p[0] === 192 && p[1] === 0) || (p[0] === 198 && (p[1] === 18 || p[1] === 19)); }
  return ip === '::1' || ip === '::' || ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd') || ip.toLowerCase().startsWith('fe80') || ip.toLowerCase().startsWith('::ffff:');
}
async function validateUrl(input: string) { const url = new URL(input); if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname || (url.port && !['80','443'].includes(url.port))) throw Error('Use a public HTTP(S) URL on port 80 or 443.'); const addresses = await lookup(url.hostname, { all: true }); if (!addresses.length || addresses.some(a => isPrivateIP(a.address))) throw Error('Local/private network targets are not allowed.'); return url.toString(); }
const app = express(); app.use(cors()); app.use(express.json({ limit: '20kb' }));
const active = new Set<string>();
async function check(monitor: Record<string, unknown>) {
 const id = String(monitor.id); if (active.has(id)) return; active.add(id);
 let success = 0, status: number | null = null, error: string | null = null;
 const start = Date.now();
 try { const url = await validateUrl(String(monitor.url)); const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10000), headers: { 'user-agent': 'PulseWatch/1.0' } }); status = response.status; success = status >= 200 && status < 400 ? 1 : 0; if (!success) error = `HTTP ${status}`; await response.body?.cancel(); }
 catch(e) { error = e instanceof Error ? e.message : 'Network error'; }
 const now = new Date().toISOString(); const elapsed = Date.now() - start;
 try { db.run('INSERT INTO checks VALUES (?,?,?,?,?,?,?)',[randomUUID(),id,now,success,status,elapsed,error]);
 const incident = rows('SELECT * FROM incidents WHERE monitor_id=? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1',[id])[0];
 if (!success && !incident) db.run('INSERT INTO incidents VALUES (?,?,?,?,?)',[randomUUID(),id,now,null,error || 'Unavailable']);
 if (success && incident) db.run('UPDATE incidents SET ended_at=? WHERE id=?',[now,String(incident.id)]);
 await persist(); } finally { active.delete(id); }
}
function getMonitors() { return rows(`SELECT m.*, (SELECT success FROM checks c WHERE c.monitor_id=m.id ORDER BY checked_at DESC LIMIT 1) AS last_success, (SELECT response_ms FROM checks c WHERE c.monitor_id=m.id ORDER BY checked_at DESC LIMIT 1) AS response_ms, (SELECT status_code FROM checks c WHERE c.monitor_id=m.id ORDER BY checked_at DESC LIMIT 1) AS status_code, (SELECT checked_at FROM checks c WHERE c.monitor_id=m.id ORDER BY checked_at DESC LIMIT 1) AS last_checked, (SELECT ROUND(100.0 * AVG(success),2) FROM checks c WHERE c.monitor_id=m.id) AS uptime FROM monitors m ORDER BY created_at DESC`); }
// Diagnostic routes are intentionally local-only. No arbitrary network ports or private hosts.
async function inspectTLS(urlString: string) {
 const u = new URL(await validateUrl(urlString));
 if (u.protocol !== 'https:') return { valid:false, error:'Not HTTPS' };
 return await new Promise<Record<string,unknown>>(resolve => {
  const socket = tls.connect({host:u.hostname,port:443,servername:u.hostname,rejectUnauthorized:true,timeout:8000},()=>{
   const cert=socket.getPeerCertificate(); const expiry=cert.valid_to ? new Date(cert.valid_to) : null;
   resolve({valid:socket.authorized,issuer:cert.issuer?.O||cert.issuer?.CN||'Unknown',expiresAt:expiry?.toISOString()||null,daysRemaining:expiry?Math.floor((expiry.getTime()-Date.now())/86400000):null,subject:cert.subject?.CN||null});socket.end();
  });
  socket.once('error',e=>resolve({valid:false,error:e.message}));socket.once('timeout',()=>{socket.destroy();resolve({valid:false,error:'TLS timeout'});});
 });
}
function quantile(xs:number[],q:number){if(!xs.length)return null;const sorted=[...xs].sort((a,b)=>a-b);return sorted[Math.ceil(q*sorted.length)-1];}
function statsFor(id:string){const checks=rows('SELECT success,response_ms,status_code FROM checks WHERE monitor_id=?',[id]);const times=checks.map(c=>Number(c.response_ms));return {totalChecks:checks.length,uptime:checks.length?100*checks.filter(c=>c.success===1).length/checks.length:null,errorRate:checks.length?100*checks.filter(c=>c.success!==1).length/checks.length:null,avgMs:times.length?Math.round(times.reduce((a,b)=>a+b,0)/times.length):null,minMs:times.length?Math.min(...times):null,maxMs:times.length?Math.max(...times):null,p50Ms:quantile(times,.5),p95Ms:quantile(times,.95),p99Ms:quantile(times,.99)};}
const auditRules=(html:string, url:string)=>{
 const tests:{id:string;title:string;pass:boolean;fix:string;severity:string}[]=[];
 const add=(id:string,title:string,pass:boolean,fix:string,severity='medium')=>tests.push({id,title,pass,fix,severity});
 const match=(re:RegExp)=>html.match(re)?.[1]?.trim()||'';
 const title=match(/<title[^>]*>([\s\S]*?)<\/title>/i).replace(/\s+/g,' ');
 const meta=(name:string)=>{const tags=html.match(/<meta\b[^>]*>/gi)||[];return tags.some(t=>new RegExp('(?:name|property)=[\"\']'+name+'[\"\']','i').test(t)&&/content=[\"\'][^\"\']+/i.test(t));};
 add('title','Page title',title.length>=15&&title.length<=65,'Add a unique, descriptive <title> of approximately 15–65 characters.','high');
 add('description','Meta description',meta('description'),'Add a unique meta description summarizing this page.','high');
 add('h1','Exactly one H1', (html.match(/<h1\b/gi)||[]).length===1,'Use one descriptive main H1 heading.');
 add('canonical','Canonical URL',/<link\b(?=[^>]*rel=[\"\']canonical[\"\'])[^>]*>/i.test(html),'Add a canonical link pointing to the preferred URL.');
 add('viewport','Mobile viewport',meta('viewport'),'Add a responsive viewport meta tag.');
 add('lang','HTML language',/<html\b[^>]*\blang=[\"\'][^\"\']+/i.test(html),'Set the lang attribute on the html element.');
 const images=html.match(/<img\b[^>]*>/gi)||[];
 add('alt','Image alt attributes',images.every(t=>/\balt\s*=/.test(t)),'Add meaningful alt text for informative images; use alt="" for decorative images.');
 add('https','HTTPS',url.startsWith('https:'),'Serve the site over HTTPS.','high');
 add('robots','Robots meta',!/<meta\b[^>]*name=[\"\']robots[\"\'][^>]*content=[\"\'][^\"\']*noindex/i.test(html),'Remove unintended noindex directives.','high');
 add('og','Open Graph title',meta('og:title'),'Add og:title metadata for link previews.','low');
 add('structured','Structured data',/<script\b[^>]*type=[\"\']application\/ld\+json/i.test(html),'Add relevant, valid JSON-LD structured data where appropriate.','low');
 return tests;
};
async function safeFetch(url:string){let current=await validateUrl(url);const redirects:string[]=[];for(let i=0;i<6;i++){const response=await fetch(current,{redirect:'manual',signal:AbortSignal.timeout(12000),headers:{'user-agent':'PulseWatch/2.0'}});if(response.status>=300&&response.status<400&&response.headers.get('location')){const next=new URL(response.headers.get('location')!,current).toString();await response.body?.cancel();current=await validateUrl(next);redirects.push(current);continue;}return {response,finalUrl:current,redirects};}throw Error('Too many redirects');}
app.get('/api/monitors/:id/stats',(req,res)=>res.json(statsFor(String(req.params.id))));
app.get('/api/monitors/:id/diagnostics',async(req,res)=>{try{const m=rows('SELECT * FROM monitors WHERE id=?',[String(req.params.id)])[0];if(!m)return res.status(404).json({error:'Not found'});const u=new URL(String(m.url));const [ssl,dns]=await Promise.all([inspectTLS(String(m.url)),Promise.allSettled([resolve4(u.hostname),resolve6(u.hostname)])]);const result={ssl,dns:{ipv4:dns[0].status==='fulfilled'?dns[0].value:[],ipv6:dns[1].status==='fulfilled'?dns[1].value:[]}};db.run('INSERT INTO diagnostics VALUES (?,?,?,?,?)',[randomUUID(),String(m.id),new Date().toISOString(),'network',JSON.stringify(result)]);await persist();res.json(result);}catch(e){res.status(400).json({error:e instanceof Error?e.message:'Diagnostics failed'});}});
app.post('/api/monitors/:id/audit',async(req,res)=>{try{const m=rows('SELECT * FROM monitors WHERE id=?',[String(req.params.id)])[0];if(!m)return res.status(404).json({error:'Not found'});const {response,finalUrl,redirects}=await safeFetch(String(m.url));const type=response.headers.get('content-type')||'';if(!type.includes('text/html')){await response.body?.cancel();return res.status(400).json({error:'SEO audits require an HTML page.'});}const len=Number(response.headers.get('content-length')||0);if(len>2_000_000){await response.body?.cancel();return res.status(400).json({error:'Page is too large to audit.'});}const html=(await response.text()).slice(0,2_000_000);const tests=auditRules(html,finalUrl);const score=Math.round(tests.filter(t=>t.pass).length/tests.length*100);const result={score,tests,finalUrl,redirects,statusCode:response.status,auditedAt:new Date().toISOString(),note:'PulseWatch heuristic score, NOT Google Lighthouse SEO score. Some checks require browser rendering or a site crawl.'};db.run('INSERT INTO audits VALUES (?,?,?,?,?)',[randomUUID(),String(m.id),result.auditedAt,score,JSON.stringify(result)]);await persist();res.json(result);}catch(e){res.status(400).json({error:e instanceof Error?e.message:'Audit failed'});}});
app.get('/api/monitors/:id/audits',(req,res)=>res.json(rows('SELECT id,audited_at,score,details FROM audits WHERE monitor_id=? ORDER BY audited_at DESC LIMIT 30',[String(req.params.id)]).map(r=>({...r,details:JSON.parse(String(r.details))}))));
app.get('/api/monitors/:id/report.pdf',(req,res)=>{const id=String(req.params.id);const m=rows('SELECT * FROM monitors WHERE id=?',[id])[0];if(!m)return res.status(404).json({error:'Not found'});const doc=new PDFDocument({margin:45});res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition','attachment; filename="pulsewatch-report.pdf"');doc.pipe(res);doc.fontSize(22).text('PulseWatch Monitoring Report');doc.moveDown().fontSize(12).text(String(m.name)).text(String(m.url)).text('Generated: '+new Date().toLocaleString());doc.moveDown();const st=statsFor(id);Object.entries(st).forEach(([k,v])=>doc.text(k+': '+(v??'N/A')));doc.moveDown().fontSize(15).text('Recent incidents');doc.fontSize(10);rows('SELECT * FROM incidents WHERE monitor_id=? ORDER BY started_at DESC LIMIT 25',[id]).forEach(i=>{doc.text(`${i.started_at} - ${i.ended_at||'ONGOING'}: ${i.reason}`);});doc.end();});
app.get('/api/health',(_req,res)=>res.json({status:'ok'}));
app.get('/api/monitors',(_req,res)=>res.json(getMonitors()));
app.post('/api/monitors',async(req,res)=>{ try { const name = String(req.body.name || '').trim().slice(0,80); const url = await validateUrl(String(req.body.url || '')); const interval = Number(req.body.intervalSeconds || 60); if (!name || !Number.isInteger(interval) || interval < 30 || interval > 3600) return res.status(400).json({error:'Provide a name and an interval between 30 and 3600 seconds.'}); const id=randomUUID(); db.run('INSERT INTO monitors VALUES (?,?,?,?,?)',[id,name,url,interval,new Date().toISOString()]); await persist(); void check({id,url}); res.status(201).json({id}); } catch(e){res.status(400).json({error:e instanceof Error?e.message:'Invalid URL'});} });
app.delete('/api/monitors/:id',async(req,res)=>{ const id=String(req.params.id); db.run('DELETE FROM monitors WHERE id=?',[id]); db.run('DELETE FROM checks WHERE monitor_id=?',[id]); db.run('DELETE FROM incidents WHERE monitor_id=?',[id]); db.run('DELETE FROM audits WHERE monitor_id=?',[id]);db.run('DELETE FROM diagnostics WHERE monitor_id=?',[id]); await persist(); res.json({ok:true}); });
app.post('/api/monitors/:id/check',async(req,res)=>{const m=rows('SELECT * FROM monitors WHERE id=?',[String(req.params.id)])[0]; if(!m)return res.status(404).json({error:'Not found'}); await check(m); res.json({ok:true});});
app.get('/api/monitors/:id/history',(req,res)=>{const id=String(req.params.id); res.json({checks:rows('SELECT * FROM checks WHERE monitor_id=? ORDER BY checked_at DESC LIMIT 200',[id]),incidents:rows('SELECT * FROM incidents WHERE monitor_id=? ORDER BY started_at DESC LIMIT 100',[id])});});
app.get('/api/monitors/:id/export',(req,res)=>{const id=String(req.params.id); const data=rows('SELECT checked_at,success,status_code,response_ms,error FROM checks WHERE monitor_id=? ORDER BY checked_at DESC',[id]); const csv=['checked_at,success,status_code,response_ms,error',...data.map(r=>[r.checked_at,r.success,r.status_code??'',r.response_ms??'',`"${String(r.error??'').replaceAll('"','""')}"`].join(','))].join('\n'); res.setHeader('Content-Type','text/csv');res.setHeader('Content-Disposition','attachment; filename="pulsewatch-history.csv"');res.send(csv);});
const last = new Map<string,number>(); setInterval(()=>{for(const m of rows('SELECT * FROM monitors')){const id=String(m.id);if(Date.now()-(last.get(id)||0)>=Number(m.interval_seconds)*1000){last.set(id,Date.now());void check(m);}}},1000);
const port=Number(process.env.PORT||3000);app.listen(port,()=>console.log(`PulseWatch API: http://localhost:${port}`));
