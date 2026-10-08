// ==========================================
// PAPIRUS (strona glowna) – Kronika Siedziby
// Cala tresc jest juz w HTML: kronika (data/changelog.json) i stan Siedziby ze statystykami
// (data/siedziba_stan.json – zapisuje i commituje go agent wdrozen Siedziby), wiec strona pokazuje papirus od
// razu i nie czeka na budzenie darmowego serwera. Ten skrypt:
//  - zamienia daty na "X temu" (time[data-ago]),
//  - pokazuje pulsujacy punkt "Siedziba pracuje", gdy meldunek jest swiezy (do 2 godzin),
//  - PO wczytaniu strony, w tle i bez komunikatow, pyta backend (/api/live, /api/stats/public): gdy serwer
//    odpowie (tez po obudzeniu, do minuty), stan, wpisy i liczby podmieniaja sie na swiezsze; gdy nie - zostaje
//    stan z pliku,
//  - liczy klikniecia w rosliny z papirusu (statystyki).
// ==========================================
function kwPapyrusInit() {
    const box = document.getElementById('kwPapyrus');
    if (!box) return;
    const FRESH_MIN = 120;                       // meldunek mlodszy niz 2 h = Siedziba pracuje "teraz"

    function minutesAgo(iso) {
        const t = Date.parse(iso);
        return t ? Math.max(0, Math.round((Date.now() - t) / 60000)) : null;
    }
    function ago(iso) {
        const m = minutesAgo(iso);
        if (m === null) return '';
        if (m < 1) return 'przed chwilą';
        if (m < 60) return `${m} min temu`;
        const h = Math.round(m / 60);
        if (h < 24) return `${h} godz. temu`;
        const d = Math.round(h / 24);
        return d === 1 ? 'wczoraj' : `${d} dni temu`;
    }

    function refresh() {
        box.querySelectorAll('time[data-ago]').forEach(el => {
            const txt = ago(el.getAttribute('datetime'));
            if (!txt) return;
            if (!el.title) el.title = el.textContent.trim();   // pelna data w dymku
            el.textContent = txt;
        });
        const live = document.getElementById('kwPapyrusLive');
        if (live && live.classList.contains('is-reported')) {
            const m = minutesAgo(live.dataset.ts);
            const fresh = m !== null && m <= FRESH_MIN;
            live.classList.toggle('is-alive', fresh);
            const head = live.querySelector('.kw-live-head');
            if (head) head.textContent = fresh ? 'Siedziba pracuje' : 'Siedziba pracowała';
        }
    }
    refresh();
    setInterval(() => { if (document.visibilityState === 'visible') refresh(); }, 60000);

    // ---------- swiezsze dane z backendu (w tle, po wczytaniu strony) ----------
    const meta = document.querySelector('meta[name="kw-backend"]');
    const API = meta && /^https?:\/\//.test(meta.content) ? meta.content.replace(/\/+$/, '') : '';
    const liveEl = document.getElementById('kwPapyrusLive');
    const liveText = liveEl ? liveEl.querySelector('.kw-live-text') : null;

    function esc(v) {
        return String(v === undefined || v === null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
    function num(n) { return Number(n || 0).toLocaleString('pl-PL'); }
    function pl(n, one, few, many) {             // 1 wizyta, 2 wizyty, 5 wizyt (12-14 zawsze "wizyt")
        n = Math.abs(Number(n) || 0);
        if (n === 1) return one;
        return (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14)) ? few : many;
    }
    function safeLink(url) { return typeof url === 'string' && ((url.startsWith('/') && !url.startsWith('//')) || url.startsWith('https://')) ? url : ''; }
    function plantNames() {                      // nazwy roslin z kart Bestiariusza (sa w HTML)
        const names = {};
        document.querySelectorAll('a.witcher-card[href^="/plant/"]').forEach(a => {
            const id = decodeURIComponent(a.getAttribute('href').split('/')[2] || '');
            const t = a.querySelector('.witcher-card-title');
            if (id && t) names[id] = t.textContent.trim();
        });
        return names;
    }
    function getJSON(path, timeoutMs) {
        const ctrl = window.AbortController ? new AbortController() : null;
        const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
        return fetch(API + path, { mode: 'cors', cache: 'no-store', signal: ctrl ? ctrl.signal : undefined })
            .then(r => (r.ok ? r.json() : Promise.reject(r.status)))
            .finally(() => { if (timer) clearTimeout(timer); });
    }

    function renderLive(data) {
        const s = (data && data.siedziba) || {};
        const jobs = Array.isArray(s.zadania) ? s.zadania.slice(0, 3) : [];
        if (liveEl && liveText && (s.zyje || s.ostatnio)) {
            liveEl.classList.remove('is-reported');      // dalej liczy sie stan z serwera, nie z pliku
            liveEl.classList.toggle('is-alive', !!s.zyje);
            if (s.zyje && jobs.length) {
                liveText.innerHTML = '<strong>Siedziba pracuje</strong>: ' + jobs.map(j =>
                    esc(j.opis || j.rodzaj || 'zadanie') + (j.od ? ` <small>(${ago(j.od) === 'przed chwilą' ? 'od chwili' : 'od ' + esc(ago(j.od).replace(' temu', ''))})</small>` : '')).join(' · ');
            } else if (s.zyje) {
                liveText.innerHTML = '<strong>Siedziba czuwa</strong> – zaraz wybierze kolejne zadanie.';
            } else {
                liveText.innerHTML = `<strong>Siedziba odpoczywa</strong> – ostatnio pracowała ${esc(ago(s.ostatnio))}.`;
            }
        }
        const rows = Array.isArray(data && data.wpisy) ? data.wpisy.slice(0, 6) : [];
        if (!rows.length) return;
        let log = document.getElementById('kwPapyrusLiveLog');
        if (!log) {
            const main = document.getElementById('kwPapyrusLog');
            if (!main) return;
            log = document.createElement('ol');
            log.className = 'kw-chronicle kw-chronicle-live';
            log.id = 'kwPapyrusLiveLog';
            main.parentNode.insertBefore(log, main);
        }
        log.innerHTML = rows.map(w => {
            const link = safeLink(w.url);
            const text = esc(w.text);
            return `<li class="kw-chronicle-entry is-live" data-kind="${esc(w.kind)}">
                <time datetime="${esc(w.ts)}" title="${esc(w.ts)}">${esc(ago(w.ts))}</time>
                <p>${link ? `<a href="${esc(link)}">${text}</a>` : text}</p></li>`;
        }).join('');
        log.hidden = false;
    }

    function renderStats(s) {
        if (!s) return;
        const names = plantNames();
        const parts = [];
        const gw = s.goscie && s.goscie.tydzien, gd = s.goscie && s.goscie.dzis, o = s.rosliny_odslony && s.rosliny_odslony.tydzien, r = s.plantid && s.plantid.razem;
        if (gw) parts.push(`<span><b>${num(gw)}</b> ${pl(gw, 'wizyta', 'wizyty', 'wizyt')} w tygodniu</span>`);
        else if (gd) parts.push(`<span><b>${num(gd)}</b> ${pl(gd, 'wizyta', 'wizyty', 'wizyt')} dziś</span>`);
        if (o) parts.push(`<span><b>${num(o)}</b> ${pl(o, 'odsłona', 'odsłony', 'odsłon')} roślin w tygodniu</span>`);
        if (r) parts.push(`<span><b>${num(r)}</b> ${pl(r, 'rozpoznanie', 'rozpoznania', 'rozpoznań')} rośliny ze zdjęcia${s.plantid.dzis ? ` (dziś ${num(s.plantid.dzis)})` : ''}</span>`);
        const top = (s.najczesciej_czytane || []).slice(0, 4).filter(t => t && t.id).map(t =>
            `<a href="/plant/${encodeURIComponent(t.id)}/">${esc(names[t.id] || t.nazwa || t.id)}</a>`);
        let html = parts.join('');
        if (top.length) html += `<span class="kw-papyrus-top">Najczęściej czytane: ${top.join(', ')}</span>`;
        if (!html) return;
        let el = document.getElementById('kwPapyrusStats');
        if (!el) {
            if (!liveEl) return;
            el = document.createElement('div');
            el.className = 'kw-papyrus-stats';
            el.id = 'kwPapyrusStats';
            liveEl.after(el);
        }
        el.innerHTML = html;
        el.hidden = false;
    }

    function load(timeoutMs) {
        if (!API) return;
        // budzenie darmowego serwera trwa do minuty - nic nie pokazujemy, po prostu czekamy w tle
        getJSON('/api/live', timeoutMs).then(renderLive).catch(() => {});
        getJSON('/api/stats/public', timeoutMs).then(renderStats).catch(() => {});
    }
    function startLive() {
        const go = () => load(70000);
        if (window.requestIdleCallback) requestIdleCallback(go, { timeout: 3000 }); else setTimeout(go, 1500);
        // odswiezanie, gdy strona jest widoczna (co 3 min)
        setInterval(() => { if (document.visibilityState === 'visible') load(20000); }, 180000);
    }
    if (document.readyState === 'complete') startLive();
    else window.addEventListener('load', startLive, { once: true });

    box.addEventListener('click', e => {
        const a = e.target.closest && e.target.closest('a[href^="/plant/"]');
        if (a && window.KwStats) KwStats.track('papyrus', decodeURIComponent(a.getAttribute('href').split('/')[2] || ''));
    });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', kwPapyrusInit);
else kwPapyrusInit();
