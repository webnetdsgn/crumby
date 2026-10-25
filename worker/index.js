// Тонкая авторизованная прослойка между приложением и Gemini API.
// Ключ Gemini живёт только здесь (секрет GEMINI_API_KEY). Приложение знает лишь код доступа APP_PASSCODE.

const MODEL_DEFAULT = 'gemini-3.1-flash-lite';
const MAX_BODY = 6_000_000;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

function authorized(req, env) {
  const need = env.APP_PASSCODE;
  if (!need) return false; // нет кода на сервере: закрыто для всех
  const got = req.headers.get('x-crumb-pass') || '';
  if (got.length !== need.length) return false;
  let diff = 0;
  for (let i = 0; i < need.length; i++) diff |= got.charCodeAt(i) ^ need.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === '/api/health') {
      return json({ ok: true, ai: Boolean(env.GEMINI_API_KEY && env.APP_PASSCODE) });
    }
    if (url.pathname === '/api/gemini') {
      if (req.method !== 'POST') return json({ error: 'method' }, 405);
      return gemini(req, env);
    }
    if (url.pathname.startsWith('/api/')) return json({ error: 'not_found' }, 404);
    return env.ASSETS ? env.ASSETS.fetch(req) : new Response('Not found', { status: 404 });
  },
};

async function gemini(req, env) {
  if (!authorized(req, env)) return json({ error: 'bad_pass' }, 401);
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

  const body = { contents, generationConfig: { temperature: 0.3, maxOutputTokens: 2048 } };
  if (b.system) body.systemInstruction = { parts: [{ text: String(b.system).slice(0, 12000) }] };
  if (b.json) body.generationConfig.responseMimeType = 'application/json';

  const model = env.GEMINI_MODEL || MODEL_DEFAULT;
  let r;
  try {
    r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      { method: 'POST', headers: { 'content-type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY }, body: JSON.stringify(body) },
    );
  } catch {
    return json({ error: 'upstream' }, 502);
  }
  if (r.status === 429) return json({ error: 'rate_limited' }, 429);
  if (!r.ok) return json({ error: 'upstream', status: r.status }, 502);

  const d = await r.json();
  const parts = (d && d.candidates && d.candidates[0] && d.candidates[0].content && d.candidates[0].content.parts) || [];
  const text = parts.map((p) => p.text || '').join('').trim();
  if (!text) return json({ error: 'empty', blocked: (d && d.promptFeedback && d.promptFeedback.blockReason) || null }, 502);
  return json({ text, model });
}
