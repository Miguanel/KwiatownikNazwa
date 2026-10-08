// ==========================================
// PAPIRUS (strona glowna) – Kronika Siedziby na zywo
// Kronika z plikow (data/changelog.json) jest juz w HTML. Ten skrypt dokleja z backendu:
//  - czy Siedziba teraz pracuje i nad czym (heartbeat Siedziby co kilka minut),
//  - wpisy "na zywo" (zebrane informacje, ktore czekaja na publikacje),
//  - liczby: odwiedziny, odslony roslin, rozpoznania plant.id, najczesciej czytane rosliny.
// Darmowy serwer moze spac – pierwsze zapytanie budzi go nawet do minuty; do tego czasu zostaje tekst z HTML.
// ==========================================
function kwPapyrusInit() {
    const box = document.getElementById('kwPapyrus');
    const meta = document.querySelector('meta[name="kw-backend"]');
    const API = meta && /^https?:\/\//.test(meta.content) ? meta.content.replace(/\/+$/, '') : '';
    if (!box || !API) return;
    const track = (k, v) => { if (window.KwStats) KwStats.track(k, v); };
    const liveEl = document.getElementById('kwPapyrusLive');
    const liveText = liveEl ? liveEl.querySelector('.kw-live-text') : null;
    const statsEl = document.getElementById('kwPapyrusStats');
    const liveLog = document.getElementById('kwPapyrusLiveLog');

    const names = {};
    try { (typeof plantsData !== 'undefined' ? plantsData : []).forEach(p => { if (p && p.id) names[p.id] = p.nazwa_pl || p.id; }); }
    catch (e) { /* brak danych roslin */ }

    function esc(v) {
        return String(v === undefined || v === null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
    function ago(iso) {
        const t = Date.parse(iso);
        if (!t) return '';
        const m = Math.max(0, Math.round((Date.now() - t) / 60000));
        if (m < 1) return 'przed chwilą';
        if (m < 60) return `${m} min temu`;
        const h = Math.round(m / 60);
        if (h < 24) return `${h} godz. temu`;
        const d = Math.round(h / 24);
        return d === 1 ? 'wczoraj' : `${d} dni temu`;
    }
    function num(n) { return Number(n || 0).toLocaleString('pl-PL'); }
    function pl(n, one, few, many) {             // 1 wizyta, 2 wizyty, 5 wizyt (12-14 zawsze "wizyt")
        n = Math.abs(Number(n) || 0);
        if (n === 1) return one;
        return (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14)) ? few : many;
    }
    function safeLink(url) { return typeof url === 'string' && (url.startsWith('/') || url.startsWith('https://')) ? url : ''; }

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
        if (liveEl) liveEl.classList.toggle('is-alive', !!s.zyje);
        if (liveText) {
            if (s.zyje && jobs.length) {
                liveText.innerHTML = '<strong>Siedziba pracuje</strong>: ' + jobs.map(j =>
                    esc(j.opis || j.rodzaj || 'zadanie') + (j.od ? ` <small>(${ago(j.od) === 'przed chwilą' ? 'od chwili' : 'od ' + esc(ago(j.od).replace(' temu', ''))})</small>` : '')).join(' · ');
            } else if (s.zyje) {
                liveText.innerHTML = '<strong>Siedziba czuwa</strong> – zaraz wybierze kolejne zadanie.';
            } else if (s.ostatnio) {
                liveText.innerHTML = `<strong>Siedziba odpoczywa</strong> – ostatnio pracowała ${esc(ago(s.ostatnio))}.`;
            }
        }
        const rows = Array.isArray(data && data.wpisy) ? data.wpisy.slice(0, 6) : [];
        if (liveLog && rows.length) {
            liveLog.innerHTML = rows.map(w => {
                const link = safeLink(w.url);
                const text = esc(w.text);
                return `<li class="kw-chronicle-entry is-live" data-kind="${esc(w.kind)}">
                    <time datetime="${esc(w.ts)}">${esc(ago(w.ts))}</time>
                    <p>${link ? `<a href="${esc(link)}">${text}</a>` : text}</p></li>`;
            }).join('');
            liveLog.hidden = false;
        }
    }

    function renderStats(s) {
        if (!statsEl || !s) return;
        const parts = [];
        const g = s.goscie && s.goscie.dzis, o = s.rosliny_odslony && s.rosliny_odslony.tydzien, r = s.plantid && s.plantid.razem;
        if (g) parts.push(`<span><b>${num(g)}</b> ${pl(g, 'wizyta', 'wizyty', 'wizyt')} dziś</span>`);
        if (o) parts.push(`<span><b>${num(o)}</b> ${pl(o, 'odsłona', 'odsłony', 'odsłon')} roślin w tygodniu</span>`);
        if (r) parts.push(`<span><b>${num(r)}</b> ${pl(r, 'rozpoznanie', 'rozpoznania', 'rozpoznań')} rośliny ze zdjęcia${s.plantid.dzis ? ` (dziś ${num(s.plantid.dzis)})` : ''}</span>`);
        const top = (s.najczesciej_czytane || []).slice(0, 4).map(t =>
            `<a href="/plant/${encodeURIComponent(t.id)}/">${esc(names[t.id] || t.id)}</a>`);
        let html = parts.join('');
        if (top.length) html += `<span class="kw-papyrus-top">Najczęściej czytane: ${top.join(', ')}</span>`;
        if (html) { statsEl.innerHTML = html; statsEl.hidden = false; }
    }

    function load(timeoutMs) {
        getJSON('/api/live', timeoutMs).then(renderLive).catch(() => {
            if (liveText && !liveEl.classList.contains('is-alive') && !liveEl.dataset.tried) {
                liveEl.dataset.tried = '1';
                liveText.innerHTML = 'Łączę się z Siedzibą… <small>(darmowy serwer budzi się do minuty)</small>';
                setTimeout(() => load(70000), 3000);
            }
        });
        getJSON('/api/stats/public', timeoutMs).then(renderStats).catch(() => {});
    }
    load(8000);
    // odswiezanie, gdy papirus jest widoczny (co 2 min)
    setInterval(() => { if (document.visibilityState === 'visible') load(15000); }, 120000);

    box.addEventListener('click', e => {
        const a = e.target.closest && e.target.closest('a[href^="/plant/"]');
        if (a) track('papyrus', decodeURIComponent(a.getAttribute('href').split('/')[2] || ''));
    });
}
// skrypt stoi w tresci strony, a kw_stats.js i reszta ladowane sa nizej - startujemy po wczytaniu dokumentu
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', kwPapyrusInit);
else kwPapyrusInit();
