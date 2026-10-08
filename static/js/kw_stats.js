// ==========================================
// STATYSTYKI I KEEP-ALIVE (backend Kwiatownika na Render)
// - liczy: odslony stron i roslin, otwierane rozdzialy rosliny, klikniecia "Rozpoznaj" (plant.id) i wyniki,
//   otwierane przepisy, klikniete zrodla, wyszukiwania. Bez ciasteczek i bez identyfikatorow - tylko liczby.
// - "Do Not Track" / Global Privacy Control w przegladarce = nic nie wysylamy.
// - zdarzenia ida przez sendBeacon (w tle, strona na nic nie czeka). Bez pingu przy wczytaniu strony: serwer
//   budza zdarzenia i papirus (w tle, po wczytaniu), a na nogach trzyma go heartbeat Siedziby co 5 min.
//   KwStats.ping() zostaje dla zgodnosci (reczne obudzenie serwera).
// Adres serwera: <meta name="kw-backend" content="..."> (KW_BACKEND_URL przy budowaniu strony).
// API: window.KwStats.track(rodzaj, klucz), KwStats.backend (adres), KwStats.ping().
// ==========================================
(function () {
    const meta = document.querySelector('meta[name="kw-backend"]');
    const BACKEND = meta && /^https?:\/\//.test(meta.content) ? meta.content.replace(/\/+$/, '') : '';
    const PRIVATE = navigator.doNotTrack === '1' || window.doNotTrack === '1' || navigator.globalPrivacyControl === true;
    const queue = [];
    const sentOnce = new Set();
    let flushTimer = null;
    let lastPing = 0;

    function flush() {
        flushTimer = null;
        if (!BACKEND || PRIVATE || !queue.length) { queue.length = 0; return; }
        const body = JSON.stringify({ events: queue.splice(0, 40) });
        const url = BACKEND + '/api/events';
        let ok = false;
        try {
            // text/plain = "prosty" request: bez zapytania wstepnego CORS, dziala tez przy zamykaniu strony
            ok = navigator.sendBeacon && navigator.sendBeacon(url, new Blob([body], { type: 'text/plain' }));
        } catch (e) { ok = false; }
        if (!ok) {
            try { fetch(url, { method: 'POST', body, keepalive: true, mode: 'no-cors', headers: { 'Content-Type': 'text/plain' } }); }
            catch (e) { /* serwer spi albo brak sieci - trudno */ }
        }
        if (queue.length) schedule();
    }
    function schedule(delay) {
        if (!flushTimer) flushTimer = setTimeout(flush, delay === undefined ? 3000 : delay);
    }

    function track(kind, key, onceKey) {
        if (!BACKEND || PRIVATE || !kind) return;
        if (onceKey) {                       // np. ten sam rozdzial rosliny liczony raz na wizyte strony
            if (sentOnce.has(onceKey)) return;
            sentOnce.add(onceKey);
        }
        queue.push({ k: String(kind), v: key === undefined || key === null ? '' : String(key).slice(0, 160) });
        schedule();
    }

    function ping() {
        if (!BACKEND) return;
        lastPing = Date.now();
        try { fetch(BACKEND + '/api/ping', { method: 'GET', mode: 'cors', cache: 'no-store' }).catch(() => {}); } catch (e) { /* nic */ }
    }

    function slug(text) {
        return String(text || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/ł/g, 'l')
            .replace(/\(\d+\)/g, '').replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);
    }

    // --- rodzaj strony + roslina ---
    const path = location.pathname;
    const plantMatch = path.match(/^\/plant\/([^/]+)\/?/);
    const plantId = plantMatch ? decodeURIComponent(plantMatch[1]).toLowerCase() : '';
    const pageKind = path === '/' || path === '/index.html' ? 'glowna'
        : plantId ? 'roslina' : (slug(path.split('/').filter(Boolean)[0]) || 'inna');

    window.KwStats = { track, ping, backend: BACKEND, plantId, pageKind };

    track('page', pageKind);
    if (plantId) track('plant_view', plantId);

    // --- otwierane rozdzialy strony rosliny (details.grimmoire-tab / subtab) ---
    if (plantId) {
        document.addEventListener('toggle', e => {
            const el = e.target;
            if (!el || el.tagName !== 'DETAILS' || !el.open || !el.matches('.grimmoire-tab, .grimmoire-subtab')) return;
            const sum = el.querySelector(':scope > summary');
            const name = slug(sum ? sum.textContent : '');
            if (name) track('plant_section', plantId + ':' + name, 'sec:' + name);
        }, true);
    }

    // --- klikniete zrodla i linki wychodzace ---
    document.addEventListener('click', e => {
        const a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
        if (!a) return;
        const src = a.getAttribute('data-kw-src');
        if (src) { track('source_click', src); return; }
        let host = '';
        try { host = new URL(a.href, location.href).host; } catch (err) { return; }
        if (host && host !== location.host && !/wikipedia\.org|wikimedia\.org|translate\.google/.test(host)
            && a.closest('main, .grimmoire-wrapper, .recipe-sources')) {
            track('source_click', host.replace(/^www\./, ''));
        }
    }, true);

    // --- wyszukiwania (Enter w wyszukiwarce Kwiatownika albo Przepisnika) ---
    document.addEventListener('keydown', e => {
        if (e.key !== 'Enter' || !e.target || !e.target.matches) return;
        if (!e.target.matches('#universalSearch, #recipeSearch, .kw-input')) return;
        const q = String(e.target.value || '').trim();
        if (q.length >= 2) track('search', q);
    }, true);

    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') flush(); });
    window.addEventListener('pagehide', flush);
})();
