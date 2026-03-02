// ==========================================
// SERVICE WORKER UNTUK SPS ABATA (sw.js)
// ==========================================

const CACHE_NAME = 'sps-abata-v1';

// Saat Service Worker baru diinstall
self.addEventListener('install', (event) => {
  // Memaksa Service Worker baru untuk langsung mengambil alih 
  // tanpa menunggu user menutup semua tab
  self.skipWaiting(); 
});

// Saat Service Worker baru aktif
self.addEventListener('activate', (event) => {
  event.waitUntil(
    // Bersihkan cache lama jika ada (berguna jika Anda mengubah CACHE_NAME)
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      // Ambil alih kontrol halaman web seketika
      return clients.claim();
    })
  );
});

// Strategi Fetch (Network First, agar selalu ambil data terbaru dari Vercel)
self.addEventListener('fetch', (event) => {
  // Hanya tangani request GET
  if (event.request.method !== 'GET') return;

  event.respondWith(
    fetch(event.request).catch(() => {
      // Jika offline, Anda bisa menambahkan logika offline fallback di sini nanti
      return new Response("Aplikasi sedang offline. Pastikan koneksi internet Anda aktif.");
    })
  );
});
