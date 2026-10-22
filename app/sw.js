// Nexus service worker — installability only (owner order 2026-10-23,
// MiroFish suggestion wave). Deliberately a pure network pass-through:
// it caches nothing, so chats, sessions and API responses are never
// stored on the device or served stale. If this worker is ever removed,
// the app keeps working exactly as before, just not installable.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
