// ==========================================
// ALMANACH – klikalne pola paska u góry: Koło Roku, Patron Roku, Żywioł, Wibracja.
// Kliknięcie pokazuje dymek ze streszczeniem po polsku przygotowanym na podstawie zagranicznych
// źródeł (japońskich, indyjskich, anglojęzycznych) – static/json/almanach.json – z linkami do oryginałów
// i do tłumaczenia oryginału. Wygląd dymka jak w dymkach Wikipedii (wiki.css).
// ==========================================
(function () {
    'use strict';

    let data = null;
    let loading = null;
    let tip = null, current = null;
    const LANGS = { ja: 'japoński', en: 'angielski', hi: 'hindi', de: 'niemiecki', fr: 'francuski' };

    function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
    function safeUrl(u) { return /^https:\/\//.test(String(u || '')) ? String(u) : ''; }

    function load() {
        if (data) return Promise.resolve(data);
        if (!loading) {
            const src = (document.querySelector('script[src*="almanach.js"]') || {}).src || '/static/js/almanach.js';
            loading = fetch(src.replace(/js\/almanach\.js.*$/, 'json/almanach.json'))
                .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
                .then(d => (data = d))
                .catch(() => { loading = null; return null; });
        }
        return loading;
    }

    // tekst z paska -> wpis w almanachu
    function findEntry(kind, value) {
        if (!data) return null;
        const v = String(value || '').trim();
        if (kind === 'kolo_roku') {
            const key = Object.keys(data.kolo_roku).find(k => v.toLowerCase().includes(k.toLowerCase()));
            return key ? data.kolo_roku[key] : null;
        }
        if (kind === 'patron_roku') return data.patron_roku[v] || null;
        if (kind === 'zywiol') return data.zywiol[v] || null;
        if (kind === 'wibracja') return data.wibracja[(v.match(/\d/) || [''])[0]] || null;
        return null;
    }

    function etoYears(index) {
        const y = new Date().getFullYear();
        const years = [];
        for (let k = y - 24; k <= y + 12; k++) if (((k - 4) % 12 + 12) % 12 === index) years.push(k);
        return years.join(', ');
    }

    function ensureTip() {
        if (tip) return tip;
        tip = document.createElement('div');
        tip.className = 'kw-wiki-tip kw-alm-tip';
        tip.setAttribute('role', 'dialog');
        tip.hidden = true;
        document.body.appendChild(tip);
        tip.addEventListener('click', e => { if (e.target.closest('.kw-wiki-close')) { e.preventDefault(); hide(); } });
        return tip;
    }

    function render(kind, value, entry) {
        let html = '<button type="button" class="kw-wiki-close" aria-label="Zamknij">&times;</button>';
        if (!entry) {
            html += `<div class="kw-wiki-head">${esc(value)}</div><p class="kw-wiki-text">${data ? 'Brak opisu dla tej wartości.' : 'Nie udało się wczytać opisu. Spróbuj ponownie.'}</p>`;
            tip.innerHTML = html;
            return;
        }
        html += `<div class="kw-wiki-head">${esc(entry.tytul)}</div>`;
        if (entry.podtytul) html += `<div class="kw-wiki-sub">${esc(entry.podtytul)}</div>`;
        html += `<div class="kw-wiki-body"><p class="kw-wiki-text">${esc(entry.tekst)}</p>`;
        if (kind === 'patron_roku' && typeof entry.index === 'number') html += `<p class="kw-wiki-sub" style="margin-top:6px;">Lata tego znaku: ${esc(etoYears(entry.index))}</p>`;
        html += '</div>';
        const src = (entry.zrodla || []).filter(z => safeUrl(z.url));
        if (src.length) {
            html += '<div class="kw-alm-src"><span class="kw-alm-src-label">Źródła (streszczenie przetłumaczone na polski):</span><ul>';
            src.forEach(z => {
                const lang = z.jezyk && z.jezyk !== 'pl'
                    ? ` <a class="kw-alm-tr" href="https://translate.google.com/translate?sl=${encodeURIComponent(z.jezyk)}&tl=pl&u=${encodeURIComponent(z.url)}" target="_blank" rel="noopener nofollow" title="Otwórz oryginał przetłumaczony na polski">przetłumacz ↗</a>` : '';
                html += `<li><a href="${esc(z.url)}" target="_blank" rel="noopener nofollow">${esc(z.nazwa)}</a> <small>(${esc(LANGS[z.jezyk] || z.jezyk || '')})</small>${lang}</li>`;
            });
            html += '</ul></div>';
        }
        tip.innerHTML = html;
    }

    function position() {
        if (!tip || tip.hidden || !current) return;
        if (window.innerWidth < 576) { tip.classList.add('kw-wiki-sheet'); tip.style.left = ''; tip.style.top = ''; return; }
        tip.classList.remove('kw-wiki-sheet');
        const r = current.getBoundingClientRect();
        const tw = tip.offsetWidth, margin = 8;
        let left = Math.max(margin, Math.min(r.left + r.width / 2 - tw / 2, window.innerWidth - tw - margin));
        tip.style.left = `${Math.round(left)}px`;
        tip.style.top = `${Math.round(r.bottom + 8)}px`;
    }

    function show(el) {
        ensureTip();
        current = el;
        const kind = el.dataset.alm;
        const value = el.textContent.trim();
        tip.innerHTML = '<button type="button" class="kw-wiki-close" aria-label="Zamknij">&times;</button><div class="kw-wiki-loading"><span class="kw-wiki-spinner"></span> Otwieram almanach…</div>';
        tip.hidden = false;
        position();
        load().then(() => {
            if (current !== el) return;
            render(kind, value, findEntry(kind, value));
            position();
        });
    }
    function hide() { if (tip) tip.hidden = true; current = null; }

    // pasek almanachu się przewija i da się go przeciągać – kliknięcie liczy się tylko bez przesunięcia
    let downX = null;
    document.addEventListener('pointerdown', e => { downX = e.clientX; }, true);
    document.addEventListener('click', e => {
        const el = e.target.closest && e.target.closest('[data-alm]');
        if (el) {
            if (downX !== null && Math.abs(e.clientX - downX) > 6) return;
            e.preventDefault();
            if (current === el && tip && !tip.hidden) hide(); else show(el);
            return;
        }
        if (tip && !tip.hidden && !tip.contains(e.target)) hide();
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') hide();
        const el = e.target.closest && e.target.closest('[data-alm]');
        if (el && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); show(el); }
    });
    window.addEventListener('scroll', () => requestAnimationFrame(position), true);
    window.addEventListener('resize', () => requestAnimationFrame(position));

    function init() {
        document.querySelectorAll('[data-alm]').forEach(el => {
            el.tabIndex = 0;
            el.setAttribute('role', 'button');
            el.title = 'Kliknij: co to znaczy?';
        });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
    // pasek jest klonowany przez skrypt przewijania – nadaj atrybuty także kopiom
    window.addEventListener('load', init);
})();
