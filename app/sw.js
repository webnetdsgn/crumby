/* Crumb service worker: быстрый запуск, офлайн-оболочка и уведомления.
   Страница всегда берётся из сети первой, поэтому обновления приходят сразу. */
const CACHE = 'crumb-v1';
const SHELL = ['/', '/manifest.webmanifest', '/icon-180.png', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(SHELL).catch(() => {}))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('crumb-v') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // шрифты и прочее: как обычно
  if (url.pathname.startsWith('/api/') || url.pathname === '/sw.js') return; // сервер и сам воркер не кэшируем

  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then((r) => { const copy = r.clone(); caches.open(CACHE).then((c) => c.put('/', copy)); return r; })
        .catch(() => caches.match('/')),
    );
    return;
  }
  // кэшируем только статические файлы; всё остальное идёт напрямую
  if (!/\.(png|svg|jpe?g|ico|webmanifest|woff2?)$/.test(url.pathname)) return;
  e.respondWith(
    caches.match(req).then((hit) => {
      const net = fetch(req)
        .then((r) => { if (r && r.ok) { const copy = r.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); } return r; })
        .catch(() => hit);
      return hit || net;
    }),
  );
});

/* Уведомление приходит без текста: ждём сигнал, забираем текст у сервера и показываем.
   iPhone требует показать уведомление на каждый сигнал, поэтому запасной текст есть всегда. */
async function storedSid() {
  const c = await caches.open('crumb-meta');
  const r = await c.match('/__sid');
  return r ? r.text() : '';
}

self.addEventListener('push', (e) => {
  e.waitUntil((async () => {
    let msg = null;
    try {
      const sid = await storedSid();
      if (sid) {
        const r = await fetch('/api/push/message?sid=' + encodeURIComponent(sid), { cache: 'no-store' });
        if (r.ok) msg = await r.json();
      }
    } catch (_) { /* покажем запасной текст */ }
    if (!msg || !msg.title) msg = { title: 'Crumb', body: 'Время записать еду · Time to log your food', tag: 'crumb' };
    await self.registration.showNotification(msg.title, {
      body: msg.body || '',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: msg.tag || 'crumb',
      data: { url: '/' },
    });
  })());
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if ('focus' in c) { await c.focus(); return; }
    }
    await self.clients.openWindow('/');
  })());
});
