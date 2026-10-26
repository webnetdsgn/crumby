// Вся серверная логика Crumb без привязки к специальным импортам Cloudflare, чтобы её можно было проверять тестами.
//
// Переменные и секреты (панель Cloudflare):
//   GEMINI_API_KEY    ключ Gemini API (секрет)
//   APP_PASSCODE      код доступа владельца (секрет)
//   APP_PASSCODES     дополнительные коды через запятую, по одному на каждого человека (секрет)
//   GEMINI_MODEL      модель (по умолчанию gemini-3.1-flash-lite)
//   GEMINI_THINKING   "default": не ограничивать «размышления» модели
//   AI_DAILY_LIMIT    сколько ИИ-запросов в сутки на человека (по умолчанию 80)

export const MODEL_DEFAULT = 'gemini-3.1-flash-lite';
const MAX_BODY = 6_000_000;
const UPSTREAM_TIMEOUT_MS = 28_000;
const MAX_STATE_CHARS = 300_000;
const MAX_SUBS_PER_USER = 5;
const SEND_LIMIT_PER_RUN = 40; // бесплатный план: не больше 50 внешних запросов за один запуск
const GRACE_MIN = 90; // опоздавшее напоминание всё равно уйдёт, но не позже чем через 90 минут

export const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

const enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha256hex = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
export const b64u = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/* ---------------- доступ: у каждого человека свой код ---------------- */

export function codesOf(env) {
  return [env.APP_PASSCODE, ...String(env.APP_PASSCODES || '').split(',')]
    .map((s) => String(s || '').trim())
    .filter(Boolean);
}

function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// Возвращает идентификатор человека (хэш кода) или null. Сам код нигде не хранится.
export async function userOf(req, env) {
  const got = req.headers.get('x-crumb-pass') || '';
  if (!got) return null;
  let ok = false;
  for (const c of codesOf(env)) if (safeEq(got, c)) ok = true;
  return ok ? (await sha256hex('crumb:' + got)).slice(0, 16) : null;
}

/* ---------------- обращение к хранилищу (Durable Object) ---------------- */

async function hub(env, op, body = {}) {
  const stub = env.HUB.get(env.HUB.idFromName('main'));
  const r = await stub.fetch('https://hub/' + op, { method: 'POST', body: JSON.stringify(body) });
  if (!r.ok) throw new Error('hub ' + op + ' ' + r.status);
  return r.json();
}

const PUSH_HOST = /(^|\.)push\.apple\.com$|(^|\.)googleapis\.com$|(^|\.)push\.services\.mozilla\.com$|(^|\.)notify\.windows\.com$/;

/* ---------------- маршрутизация ---------------- */

export async function handleFetch(req, env) {
  const url = new URL(req.url);
  const p = url.pathname;
  const asset = () => (env.ASSETS ? env.ASSETS.fetch(req) : new Response('Not found', { status: 404 }));
  if (!p.startsWith('/api/')) return asset();

  if (p === '/api/health') {
    return json({ ok: true, ai: Boolean(env.GEMINI_API_KEY && codesOf(env).length), push: Boolean(env.HUB), limit: Number(env.AI_DAILY_LIMIT) || 80 });
  }
  if (p === '/api/gemini') {
    if (req.method !== 'POST') return json({ error: 'method' }, 405);
    return gemini(req, env);
  }
  if (p === '/api/push/config') {
    if (!env.HUB) return json({ enabled: false });
    try {
      const v = await hub(env, 'vapid');
      return json({ enabled: true, publicKey: v.publicKey });
    } catch {
      return json({ enabled: false });
    }
  }
  if (p === '/api/push/message') {
    if (!env.HUB) return json({ title: 'Crumb', body: '' });
    const sid = url.searchParams.get('sid') || '';
    if (!/^[0-9a-f]{32}$/.test(sid)) return json({ title: 'Crumb', body: '' });
    try { return json(await hub(env, 'message', { sid })); } catch { return json({ title: 'Crumb', body: '' }); }
  }

  // дальше всё только для людей с кодом
  const uid = await userOf(req, env);
  if (!uid) return json({ error: 'bad_pass' }, 401);
  if (!env.HUB) return json({ error: 'no_storage' }, 503);

  try {
    if (p === '/api/state') {
      if (req.method === 'GET') return json(await hub(env, 'state_get', { uid }));
      if (req.method === 'PUT') {
        let b;
        try { b = await req.json(); } catch { return json({ error: 'bad_json' }, 400); }
        if (typeof b.json !== 'string' || b.json.length > MAX_STATE_CHARS || !Number.isFinite(b.updatedAt)) return json({ error: 'bad_state' }, 400);
        return json(await hub(env, 'state_put', { uid, json: b.json, updatedAt: b.updatedAt }));
      }
      return json({ error: 'method' }, 405);
    }
    if (p === '/api/push/subscribe' && req.method === 'POST') {
      let b;
      try { b = await req.json(); } catch { return json({ error: 'bad_json' }, 400); }
      const ep = b && b.subscription && b.subscription.endpoint;
      let host = '';
      try { const u = new URL(ep); host = u.protocol === 'https:' ? u.hostname : ''; } catch { /* ignore */ }
      if (!host || !PUSH_HOST.test(host)) return json({ error: 'bad_endpoint' }, 400);
      return json(await hub(env, 'sub_put', { uid, endpoint: ep, tz: b.tz, lang: b.lang, prefs: b.prefs, origin: url.origin }));
    }
    if (p === '/api/push/unsubscribe' && req.method === 'POST') {
      let b;
      try { b = await req.json(); } catch { return json({ error: 'bad_json' }, 400); }
      return json(await hub(env, 'sub_del', { uid, endpoint: String((b && b.endpoint) || '') }));
    }
    if (p === '/api/push/test' && req.method === 'POST') {
      return json(await hub(env, 'test', { uid }));
    }
  } catch {
    return json({ error: 'storage' }, 502);
  }
  return json({ error: 'not_found' }, 404);
}

export async function handleScheduled(env) {
  if (!env.HUB) return;
  try { await hub(env, 'cron'); } catch { /* следующий запуск через 15 минут */ }
}

/* ---------------- Gemini ---------------- */

async function callGemini(env, model, body, stream, limitThinking) {
  const payload = { ...body, generationConfig: { ...body.generationConfig } };
  if (limitThinking) payload.generationConfig.thinkingConfig = { thinkingLevel: 'minimal' };
  const method = stream ? 'streamGenerateContent?alt=sse' : 'generateContent';
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    return await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:${method}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
        body: JSON.stringify(payload),
        signal: ctl.signal,
      },
    );
  } finally {
    clearTimeout(timer);
  }
}

async function gemini(req, env) {
  const uid = await userOf(req, env);
  if (!uid) return json({ error: 'bad_pass' }, 401);
  if (!env.GEMINI_API_KEY) return json({ error: 'no_key' }, 500);
  if (Number(req.headers.get('content-length') || 0) > MAX_BODY) return json({ error: 'too_large' }, 413);

  let b;
  try { b = await req.json(); } catch { return json({ error: 'bad_json' }, 400); }

  const contents = (Array.isArray(b.messages) ? b.messages.slice(-12) : [])
    .map((m) => ({ role: m.role === 'model' ? 'model' : 'user', parts: [{ text: String(m.text || '').slice(0, 12000) }] }))
    .filter((c) => c.parts[0].text);
  if (!contents.length || contents[contents.length - 1].role !== 'user') return json({ error: 'bad_messages' }, 400);

  if (b.image && b.image.data) {
    const mime = /^image\/(jpeg|png|webp)$/.test(b.image.mime) ? b.image.mime : 'image/jpeg';
    contents[contents.length - 1].parts.push({ inline_data: { mime_type: mime, data: String(b.image.data) } });
  }

  // суточный лимит на человека: защищает общий бесплатный лимит Gemini; если хранилище не отвечает, не блокируем
  if (env.HUB) {
    try {
      const u = await hub(env, 'use', { uid, limit: Number(env.AI_DAILY_LIMIT) || 80 });
      if (!u.ok) return json({ error: 'limit_day', limit: u.limit }, 429);
    } catch { /* пропускаем */ }
  }

  const maxTokens = Math.min(Math.max(Number(b.maxTokens) || 2048, 256), 4096);
  const body = { contents, generationConfig: { temperature: 0.3, maxOutputTokens: maxTokens } };
  if (b.system) body.systemInstruction = { parts: [{ text: String(b.system).slice(0, 12000) }] };
  if (b.json) body.generationConfig.responseMimeType = 'application/json';

  const model = env.GEMINI_MODEL || MODEL_DEFAULT;
  const stream = b.stream === true;
  let limit = env.GEMINI_THINKING !== 'default';
  const t0 = Date.now();

  const attempt = async (lim) => {
    try {
      return { r: await callGemini(env, model, body, stream, lim) };
    } catch (e) {
      return { err: e && e.name === 'AbortError' ? 'timeout' : 'upstream' };
    }
  };

  let res = await attempt(limit);
  // модель не принимает ограничение «размышлений»: повторяем без него
  if (res.r && res.r.status === 400 && limit) { limit = false; res = await attempt(false); }
  // общий лимит Gemini на минуту: один раз повторяем через секунду, чтобы короткий всплеск не ронял запросы
  if (res.r && res.r.status === 429) { await sleep(1000 + Math.random() * 800); res = await attempt(limit); }

  if (res.err) return json({ error: res.err }, res.err === 'timeout' ? 504 : 502);
  const r = res.r;
  if (r.status === 429) return json({ error: 'rate_limited' }, 429);
  if (!r.ok) {
    let detail = '';
    try { detail = (await r.text()).replace(/\s+/g, ' ').slice(0, 300); } catch { /* ignore */ }
    return json({ error: 'upstream', status: r.status, detail }, 502);
  }

  if (stream) {
    return new Response(r.body, {
      status: 200,
      headers: { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  const d = await r.json();
  const parts = (d && d.candidates && d.candidates[0] && d.candidates[0].content && d.candidates[0].content.parts) || [];
  const text = parts.map((p) => p.text || '').join('').trim();
  if (!text) {
    return json({ error: 'empty', blocked: (d && d.promptFeedback && d.promptFeedback.blockReason) || null, finish: (d && d.candidates && d.candidates[0] && d.candidates[0].finishReason) || null }, 502);
  }
  return json({ text, model, ms: Date.now() - t0, usage: (d && d.usageMetadata) || null });
}

/* ---------------- push: подпись VAPID и отправка ---------------- */

export async function vapidJwt(endpoint, jwk, subject, nowMs = Date.now()) {
  const aud = new URL(endpoint).origin;
  const exp = Math.floor(nowMs / 1000) + 12 * 3600;
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp, sub: subject })));
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + body));
  return head + '.' + body + '.' + b64u(sig);
}

const SCHEDULE = [
  { type: 'water', at: 11 * 60 },
  { type: 'water', at: 14 * 60 + 30 },
  { type: 'water', at: 17 * 60 + 30 },
  { type: 'snack', at: 20 * 60 + 30 },
  { type: 'weight', at: 9 * 60, dow: 0 },
];

const MSG = {
  water: { ru: ['Вода', 'Выпейте стакан воды. Сейчас.'], en: ['Water', 'Drink a glass of water. Now.'] },
  snack: { ru: ['Перекусы', 'Всё записано? Внесите сегодняшние перекусы, пока помните.'], en: ['Snacks', 'Everything logged? Add today’s snacks while you remember.'] },
  weight: { ru: ['Взвешивание', 'Воскресенье: встаньте на весы до еды и запишите вес.'], en: ['Weigh-in', 'Sunday: weigh yourself before eating and log it.'] },
  test: { ru: ['Crumb', 'Уведомления работают.'], en: ['Crumb', 'Notifications work.'] },
  fallback: { ru: ['Crumb', 'Время записать еду.'], en: ['Crumb', 'Time to log your food.'] },
};
export const messageFor = (type, lang) => {
  const m = (MSG[type] || MSG.fallback)[lang === 'en' ? 'en' : 'ru'];
  return { title: m[0], body: m[1], tag: type };
};

export function validTz(tz) {
  try { new Intl.DateTimeFormat('en-GB', { timeZone: String(tz) }); return String(tz); } catch { return 'UTC'; }
}

export function localParts(tz, ms) {
  const f = new Intl.DateTimeFormat('en-GB', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', weekday: 'short', hourCycle: 'h23' });
  const o = {};
  for (const p of f.formatToParts(new Date(ms))) o[p.type] = p.value;
  const dows = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return { day: `${o.year}-${o.month}-${o.day}`, min: Number(o.hour) * 60 + Number(o.minute), dow: dows[o.weekday] };
}

// Какое напоминание сейчас положено этому устройству (или null).
export function dueFor(rec, nowMs) {
  const lp = localParts(rec.tz, nowMs);
  for (const s of SCHEDULE) {
    if (!rec.prefs || !rec.prefs[s.type]) continue;
    if (s.dow !== undefined && lp.dow !== s.dow) continue;
    if (lp.min < s.at || lp.min >= s.at + GRACE_MIN) continue;
    const key = s.type + s.at;
    if (rec.sent && rec.sent[key] === lp.day) continue;
    return { key, day: lp.day, msg: messageFor(s.type, rec.lang) };
  }
  return null;
}

/* ---------------- хранилище ---------------- */

// В продакшене: SQLite внутри Durable Object. Один небольшой столбец «ключ → значение».
export class SqlStore {
  constructor(sql) {
    this.sql = sql;
    sql.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
  }
  async get(k) { const rows = this.sql.exec('SELECT v FROM kv WHERE k = ?', k).toArray(); return rows.length ? rows[0].v : undefined; }
  async put(k, v) { this.sql.exec('INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)', k, v); }
  async del(k) { this.sql.exec('DELETE FROM kv WHERE k = ?', k); }
  async list(prefix) { return this.sql.exec('SELECT k, v FROM kv WHERE k >= ? AND k < ?', prefix, prefix + '￿').toArray().map((r) => [r.k, r.v]); }
}

// Для тестов.
export class MapStore {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.get(k); }
  async put(k, v) { this.m.set(k, v); }
  async del(k) { this.m.delete(k); }
  async list(prefix) { return [...this.m.entries()].filter(([k]) => k.startsWith(prefix)).sort((a, b) => (a[0] < b[0] ? -1 : 1)); }
}

/* ---------------- ядро хранилища: лимиты, данные, подписки, рассылка ---------------- */

export class HubCore {
  constructor(store, env, now = () => Date.now()) {
    this.store = store;
    this.env = env;
    this.now = now;
    this._vapid = null;
  }

  async fetch(request) {
    const op = new URL(request.url).pathname.slice(1);
    const fn = this['op_' + op];
    if (!fn) return json({ error: 'op' }, 404);
    let body = {};
    try { body = await request.json(); } catch { /* пустое тело */ }
    try { return json(await fn.call(this, body)); } catch (e) { return json({ error: 'hub', message: String((e && e.message) || e) }, 500); }
  }

  async op_use({ uid, limit }) {
    const day = new Date(this.now()).toISOString().slice(0, 10);
    const k = `u:${uid}:${day}`;
    const n = Number((await this.store.get(k)) || 0);
    if (n >= limit) return { ok: false, limit, n };
    await this.store.put(k, String(n + 1));
    return { ok: true, n: n + 1, limit };
  }

  async op_state_get({ uid }) {
    const raw = await this.store.get('s:' + uid);
    if (!raw) return { exists: false };
    const o = JSON.parse(raw);
    return { exists: true, json: o.j, updatedAt: o.u };
  }

  async op_state_put({ uid, json: j, updatedAt }) {
    const raw = await this.store.get('s:' + uid);
    if (raw) {
      const o = JSON.parse(raw);
      if ((o.u || 0) > updatedAt) return { ok: false, newer: true, updatedAt: o.u };
    }
    await this.store.put('s:' + uid, JSON.stringify({ j, u: updatedAt }));
    return { ok: true };
  }

  vapid() {
    if (!this._vapid) {
      this._vapid = (async () => {
        let raw = await this.store.get('meta:vapid');
        if (!raw) {
          const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
          const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
          const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
          raw = JSON.stringify({ pub: b64u(pub), jwk });
          await this.store.put('meta:vapid', raw);
        }
        return JSON.parse(raw);
      })();
    }
    return this._vapid;
  }

  async op_vapid() { return { publicKey: (await this.vapid()).pub }; }

  async subs() { return (await this.store.list('p:')).map(([, v]) => JSON.parse(v)); }

  async op_sub_put({ uid, endpoint, tz, lang, prefs, origin }) {
    const sid = (await sha256hex(endpoint)).slice(0, 32);
    const k = 'p:' + sid;
    const old = JSON.parse((await this.store.get(k)) || 'null');
    const mine = (await this.subs()).filter((s) => s.uid === uid && s.sid !== sid).sort((a, b) => a.created - b.created);
    while (mine.length >= MAX_SUBS_PER_USER) await this.store.del('p:' + mine.shift().sid);
    const rec = {
      sid, uid, endpoint, origin,
      tz: validTz(tz),
      lang: lang === 'en' ? 'en' : 'ru',
      prefs: { water: !!(prefs && prefs.water), snack: !!(prefs && prefs.snack), weight: !!(prefs && prefs.weight) },
      sent: old ? old.sent : {},
      pending: old ? old.pending : null,
      fails: 0,
      created: old ? old.created : this.now(),
    };
    await this.store.put(k, JSON.stringify(rec));
    return { sid };
  }

  async op_sub_del({ uid, endpoint }) {
    const sid = (await sha256hex(endpoint)).slice(0, 32);
    const raw = await this.store.get('p:' + sid);
    if (raw && JSON.parse(raw).uid === uid) await this.store.del('p:' + sid);
    return { ok: true };
  }

  async op_message({ sid }) {
    const raw = await this.store.get('p:' + sid);
    if (!raw) return messageFor('fallback', 'ru');
    const rec = JSON.parse(raw);
    const m = rec.pending || messageFor('fallback', rec.lang);
    if (rec.pending) { rec.pending = null; await this.store.put('p:' + sid, JSON.stringify(rec)); }
    return m;
  }

  // Один запрос в push-сервис. Тело пустое: текст устройство забирает само через /api/push/message.
  async send(rec, v) {
    const jwt = await vapidJwt(rec.endpoint, v.jwk, rec.origin || 'https://example.com', this.now());
    const r = await fetch(rec.endpoint, {
      method: 'POST',
      headers: { Authorization: `vapid t=${jwt}, k=${v.pub}`, TTL: '3600', Urgency: 'normal' },
    });
    return r.status;
  }

  async deliver(rec, msg, v) {
    rec.pending = msg;
    await this.store.put('p:' + rec.sid, JSON.stringify(rec));
    let status = 0;
    try { status = await this.send(rec, v); } catch { status = 0; }
    if (status === 404 || status === 410) { await this.store.del('p:' + rec.sid); return status; }
    if (status >= 200 && status < 300) { rec.fails = 0; } else { rec.fails = (rec.fails || 0) + 1; }
    if (rec.fails >= 5) { await this.store.del('p:' + rec.sid); return status; }
    await this.store.put('p:' + rec.sid, JSON.stringify(rec));
    return status;
  }

  async op_test({ uid }) {
    const v = await this.vapid();
    const mine = (await this.subs()).filter((s) => s.uid === uid);
    const results = [];
    for (const rec of mine) results.push({ status: await this.deliver(rec, messageFor('test', rec.lang), v) });
    return { count: mine.length, results };
  }

  async op_cron() {
    const now = this.now();
    const v = await this.vapid();
    const cutoff = localParts('UTC', now - 3 * 86400000).day;
    const recs = await this.subs();
    let sent = 0;
    for (const rec of recs) {
      if (sent >= SEND_LIMIT_PER_RUN) break;
      const due = dueFor(rec, now);
      if (!due) continue;
      rec.sent = rec.sent || {};
      rec.sent[due.key] = due.day;
      for (const k of Object.keys(rec.sent)) if (rec.sent[k] < cutoff) delete rec.sent[k]; // старые отметки не копим
      await this.deliver(rec, due.msg, v);
      sent++;
    }
    // старые счётчики запросов не нужны
    for (const [k] of await this.store.list('u:')) if (k.split(':')[2] < cutoff) await this.store.del(k);
    return { checked: recs.length, sent };
  }
}
