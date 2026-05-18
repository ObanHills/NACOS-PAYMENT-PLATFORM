// NACOS PLASU — Service Worker (PWA offline support)
const CACHE_NAME = 'nacos-plasu-v1';
const ASSETS = [
    '/',
    '/index.html',
    '/styles.css',
    '/careers.css',
    '/app.js',
    '/plasu-logo.png',
    '/nacos-logo.png',
    '/manifest.json'
];

// Install: cache all static assets
self.addEventListener('install', e => {
    e.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
    );
    self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
        )
    );
    self.clients.claim();
});

// Fetch: serve from cache, fall back to network
self.addEventListener('fetch', e => {
    // Only cache same-origin GET requests
    if (e.request.method !== 'GET' || !e.request.url.startsWith(self.location.origin)) return;
    e.respondWith(
        caches.match(e.request).then(cached => cached || fetch(e.request))
    );
});
