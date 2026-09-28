'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const RADIUS_KM = +process.env.VOLUNTEER_RADIUS_KM || 5;
const ALERT_TTL_MS = 6 * 3600 * 1000;
const LOG_FILE = path.join(__dirname, 'alerts.log');

// SMS goes out through Twilio when configured, otherwise it is only logged.
let twilioClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM) {
  try { twilioClient = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN); }
  catch (e) { console.warn('Twilio package not installed; SMS will be simulated.'); }
}

const alerts = new Map();      // id (secret, held by sender) -> alert
const byToken = new Map();     // public tracking token -> alert
const volunteers = new Map();  // deviceId -> { name, pos, seen }
const hits = new Map();        // ip -> timestamps, for rate limiting

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- helpers ----------
const validPos = p => p && Number.isFinite(p.lat) && Number.isFinite(p.lng) && Math.abs(p.lat) <= 90 && Math.abs(p.lng) <= 180;
const cleanPos = p => ({ lat: p.lat, lng: p.lng, acc: Number.isFinite(p.acc) ? Math.round(p.acc) : null, at: Date.now() });
const isActive = a => !a.resolved && Date.now() - a.created < ALERT_TTL_MS;
const device = req => String(req.get('x-device-id') || '').slice(0, 64);
const baseUrl = req => process.env.PUBLIC_URL || req.protocol + '://' + req.get('host');
const audit = (type, a) => fs.appendFile(LOG_FILE, JSON.stringify({ t: new Date().toISOString(), type, ref: a.token, name: a.name, pos: a.pos }) + '\n', () => {});

function km(a, b) {
  const r = x => x * Math.PI / 180, dLat = r(b.lat - a.lat), dLng = r(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(r(a.lat)) * Math.cos(r(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 12742 * Math.asin(Math.sqrt(h));
}

function limit(max, windowMs) {
  return (req, res, next) => {
    const now = Date.now(), list = (hits.get(req.ip) || []).filter(t => now - t < windowMs);
    if (list.length >= max) return res.status(429).json({ error: 'Too many alerts, slow down' });
    list.push(now); hits.set(req.ip, list); next();
  };
}

async function sendSms(to, body) {
  if (!twilioClient) { console.log('[SIMULATED SMS] to ' + to + ': ' + body); return 'simulated'; }
  try { await twilioClient.messages.create({ to, from: process.env.TWILIO_FROM, body }); return 'sent'; }
  catch (e) { console.error('SMS failed for ' + to + ': ' + e.message); return 'failed'; }
}

// ---------- API ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, sms: twilioClient ? 'twilio' : 'simulated', authority: process.env.AUTHORITY_WEBHOOK ? 'webhook' : 'simulated' });
});

app.post('/api/alerts', limit(10, 10 * 60 * 1000), async (req, res) => {
  const b = req.body || {}, ch = b.channels || {};
  const a = {
    id: crypto.randomBytes(16).toString('hex'), token: crypto.randomBytes(12).toString('hex'),
    device: device(req), name: String(b.name || '').trim().slice(0, 60) || 'Someone',
    pos: validPos(b.pos) ? cleanPos(b.pos) : null, created: Date.now(), resolved: false, toVolunteers: !!ch.volunteers
  };
  alerts.set(a.id, a); byToken.set(a.token, a);
  const trackUrl = baseUrl(req) + '/track/' + a.token;
  const text = 'SILENT SOS from ' + a.name + '. They cannot talk and need help now. Live location: ' + trackUrl +
    (a.pos ? ' Map: https://maps.google.com/?q=' + a.pos.lat + ',' + a.pos.lng : '');
  const results = [];

  if (ch.contacts) {
    const list = (Array.isArray(b.contacts) ? b.contacts : []).filter(c => c && /^\+?\d{5,15}$/.test(String(c.phone))).slice(0, 10);
    const out = await Promise.all(list.map(c => sendSms(String(c.phone), text)));
    const n = s => out.filter(x => x === s).length;
    results.push({
      channel: 'contacts', detail: n('sent') + ' sent, ' + n('simulated') + ' simulated, ' + n('failed') + ' failed',
      status: !list.length ? 'none' : n('failed') === list.length ? 'failed' : n('simulated') ? 'simulated' : 'sent'
    });
  }

  if (ch.volunteers) {
    let n = 0;
    if (a.pos) for (const v of volunteers.values()) if (Date.now() - v.seen < 30000 && km(a.pos, v.pos) <= RADIUS_KM) n++;
    results.push({ channel: 'volunteers', status: n ? 'sent' : 'none', detail: n + ' volunteer(s) within ' + RADIUS_KM + ' km' });
  }

  if (ch.authorities) {
    const num = String(b.authNumber || '112').replace(/[^\d+]/g, '').slice(0, 15) || '112';
    let status = 'simulated', detail = 'No authority webhook set. Call ' + num + ' if you can.';
    if (process.env.AUTHORITY_WEBHOOK) {
      try {
        const r = await fetch(process.env.AUTHORITY_WEBHOOK, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: a.name, pos: a.pos, trackUrl, at: new Date().toISOString() })
        });
        status = r.ok ? 'sent' : 'failed'; detail = 'Webhook responded ' + r.status;
      } catch (e) { status = 'failed'; detail = 'Webhook unreachable'; }
    }
    results.push({ channel: 'authorities', status, detail });
  }

  audit('created', a);
  res.json({ id: a.id, trackUrl, results, sms: twilioClient ? 'twilio' : 'simulated' });
});

function own(req, res) {
  const a = alerts.get(req.params.id);
  if (!a || a.device !== device(req)) { res.status(404).json({ error: 'Alert not found' }); return null; }
  return a;
}

app.patch('/api/alerts/:id/location', (req, res) => {
  const a = own(req, res); if (!a) return;
  if (!isActive(a)) return res.status(410).json({ error: 'Alert ended' });
  if (!validPos(req.body)) return res.status(400).json({ error: 'Bad location' });
  a.pos = cleanPos(req.body); res.json({ ok: true });
});

app.post('/api/alerts/:id/resolve', (req, res) => {
  const a = own(req, res); if (!a) return;
  a.resolved = true; audit('resolved', a); res.json({ ok: true });
});

// Public read-only view for whoever holds the tracking link. Location disappears once the alert ends.
app.get('/api/track/:token', (req, res) => {
  const a = byToken.get(req.params.token);
  if (!a) return res.status(404).json({ error: 'Not found' });
  res.set('Cache-Control', 'no-store');
  res.json({ name: a.name, status: a.resolved ? 'resolved' : isActive(a) ? 'active' : 'expired', pos: isActive(a) ? a.pos : null });
});

// Volunteers
app.post('/api/volunteers', (req, res) => {
  if (!validPos(req.body.pos)) return res.status(400).json({ error: 'Location needed' });
  volunteers.set(device(req), { name: String(req.body.name || 'Volunteer').slice(0, 60), pos: cleanPos(req.body.pos), seen: Date.now() });
  res.json({ ok: true });
});

app.delete('/api/volunteers', (req, res) => { volunteers.delete(device(req)); res.json({ ok: true }); });

app.post('/api/volunteers/nearby', (req, res) => {
  const me = volunteers.get(device(req));
  if (!me) return res.status(403).json({ error: 'Register as a volunteer first' });
  if (validPos(req.body.pos)) me.pos = cleanPos(req.body.pos);
  me.seen = Date.now();
  const list = [];
  for (const a of alerts.values()) {
    if (!a.toVolunteers || !a.pos || !isActive(a) || a.device === device(req)) continue;
    const d = km(me.pos, a.pos);
    if (d <= RADIUS_KM) list.push({ name: a.name, km: +d.toFixed(1), lat: a.pos.lat, lng: a.pos.lng });
  }
  res.json({ alerts: list.sort((x, y) => x.km - y.km) });
});

// ---------- public tracking page ----------
const trackPage = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Live SOS location</title>
<style>body{font-family:system-ui,sans-serif;margin:0 auto;padding:24px;max-width:480px;background:#101626;color:#eef1f8}h1{font-size:1.4rem}.b{padding:16px;border-radius:12px;background:#19213a;margin:12px 0}a{color:#ff8a94}#st.active{color:#ff5a68}</style></head><body>
<h1 id="who">Loading...</h1>
<div class="b"><div>Status: <b id="st">-</b></div><div>Position: <span id="pos">-</span></div><div>Updated: <span id="up">-</span></div><p><a id="map" href="#" target="_blank" rel="noopener" hidden>Open in maps</a></p></div>
<script>
var token=location.pathname.split('/').pop();
function $(i){return document.getElementById(i)}
function tick(){fetch('/api/track/'+encodeURIComponent(token),{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
  if(d.error){$('who').textContent='Link not found';return}
  $('who').textContent=d.name+' sent a silent SOS';
  $('st').textContent=d.status;$('st').className=d.status;
  if(d.pos){$('pos').textContent=d.pos.lat+', '+d.pos.lng+(d.pos.acc?' (about '+d.pos.acc+' m)':'');$('up').textContent=new Date(d.pos.at).toLocaleTimeString();
    var m=$('map');m.href='https://maps.google.com/?q='+d.pos.lat+','+d.pos.lng;m.hidden=false}
  else{$('pos').textContent=d.status==='active'?'Waiting for location...':'Sharing has ended';$('map').hidden=true}
}).catch(function(){})}
tick();setInterval(tick,5000);
</script></body></html>`;

app.get('/track/:token', (req, res) => { res.set('Cache-Control', 'no-store'); res.type('html').send(trackPage); });

app.use((err, req, res, next) => res.status(400).json({ error: 'Bad request' }));

// Housekeeping: drop old alerts and stale volunteers.
setInterval(() => {
  const now = Date.now();
  for (const [id, a] of alerts) if (now - a.created > 24 * 3600 * 1000) { alerts.delete(id); byToken.delete(a.token); }
  for (const [id, v] of volunteers) if (now - v.seen > 60000) volunteers.delete(id);
  hits.clear();
}, 600000).unref();

app.listen(PORT, () => console.log('Silent SOS running on http://localhost:' + PORT + ' (SMS: ' + (twilioClient ? 'twilio' : 'simulated') + ')'));
