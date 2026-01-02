const CACHE = 'logterm-v3';
const CORE = ['/t/', '/t/index.html', '/t/style.css', '/t/app.js'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => (k === CACHE ? null : caches.delete(k))));
    await self.clients.claim();
  })());
});

async function networkFirst(req) {
  try {
    const res = await fetch(req, { cache: 'no-store' });
    const c = await caches.open(CACHE);
    await c.put(req, res.clone());
    return res;
  } catch (err) {
    const hit = await caches.match(req);
    if (hit) return hit;
    throw err;
  }
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  if (url.pathname === '/sw.js') {
    e.respondWith(fetch(e.request, { cache: 'no-store' }));
    return;
  }

  // для UI и логов — network-first, чтобы изменения подтягивались
  if (url.pathname.startsWith('/t/') || url.pathname.startsWith('/logs/')) {
    e.respondWith(networkFirst(e.request));
    return;
  }
});
