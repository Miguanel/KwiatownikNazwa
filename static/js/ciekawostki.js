// ==========================================
// PASEK CIEKAWOSTEK – wciąż nowe, losowe ciekawostki
// Zamiast przewijania w kółko tej samej listy (zapisanej przy budowaniu strony) pasek pobiera
// wszystkie ciekawostki z /api/ciekawostki.json (pliki roślin, wiedza z Siedziby, święta Koła Roku)
// i dokłada je jedna po drugiej w losowej kolejności: gdy ciekawostka wyjedzie za lewą krawędź,
// jest usuwana, a z prawej pojawia się kolejna. Każda pojawi się raz, zanim zacznie się nowa runda.
// Najechanie myszą zatrzymuje pasek; można go przeciągać palcem lub myszą.
// ==========================================
(function () {
    'use strict';

    const SPEED = 0.6;                  // px na klatkę (jak dotychczas)
    const wrapper = document.getElementById('banner-marquee');
    if (!wrapper) return;
    const content = wrapper.querySelector('.scrollable-content');
    if (!content) return;

    function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

    let pool = [];          // wszystkie ciekawostki
    let bag = [];           // kolejka bieżącej rundy (przetasowana)
    const recent = new Set();

    function shuffle(a) {
        for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
        return a;
    }

    function nextFact() {
        if (!pool.length) return null;
        if (!bag.length) {
            bag = shuffle(pool.slice());
            // nie zaczynaj nowej rundy od tego, co właśnie było na ekranie
            bag.sort((a, b) => (recent.has(a.t) ? 1 : 0) - (recent.has(b.t) ? 1 : 0));
        }
        return bag.shift();
    }

    function makeItem(f) {
        const el = document.createElement('span');
        el.className = 'marquee-item';
        const label = f.r ? `<strong>${esc(f.r)}:</strong> ` : '';
        const body = esc(f.t);
        el.innerHTML = `<i class="ra ra-scroll-unfurled"></i> ${f.id
            ? `<a href="/plant/${encodeURIComponent(f.id)}/" class="marquee-link">${label}${body}</a>`
            : `${label}${body}`}`;
        el.dataset.text = f.t;
        return el;
    }

    // --- przewijanie ---
    let pos = 0, paused = false, dragging = false, dragX = 0, dragPos = 0;

    function fill() {
        // zawsze tyle pozycji, by wypełnić pasek z zapasem
        let guard = 0;
        while (content.scrollWidth - pos < wrapper.clientWidth * 2 && guard++ < 30) {
            const f = nextFact();
            if (f) { content.appendChild(makeItem(f)); continue; }
            // brak danych z pliku – przewijamy w kółko to, co jest
            const first = content.firstElementChild;
            if (!first || content.children.length < 2) break;
            content.appendChild(first.cloneNode(true));
        }
    }

    function recycle() {
        // ciekawostka całkowicie za lewą krawędzią -> usuń i przesuń licznik o jej szerokość
        let first = content.firstElementChild;
        while (first && pos > first.offsetWidth + parseFloat(getComputedStyle(first).marginRight || 0)) {
            const w = first.offsetWidth + parseFloat(getComputedStyle(first).marginRight || 0);
            if (first.dataset.text) { recent.add(first.dataset.text); if (recent.size > 20) recent.delete(recent.values().next().value); }
            first.remove();
            pos -= w;
            first = content.firstElementChild;
        }
    }

    function step() {
        if (!paused && !dragging) pos += SPEED;
        recycle();
        fill();
        wrapper.scrollLeft = pos;
        requestAnimationFrame(step);
    }

    wrapper.addEventListener('mouseenter', () => { paused = true; });
    wrapper.addEventListener('mouseleave', () => { paused = false; dragging = false; });
    wrapper.addEventListener('pointerdown', e => { dragging = true; dragX = e.clientX; dragPos = pos; wrapper.style.cursor = 'grabbing'; });
    window.addEventListener('pointerup', () => { dragging = false; wrapper.style.cursor = ''; });
    wrapper.addEventListener('pointermove', e => {
        if (!dragging) return;
        pos = Math.max(0, dragPos - (e.clientX - dragX) * 1.5);
    });
    // kliknięcie w link po przeciągnięciu nie przechodzi
    wrapper.addEventListener('click', e => { if (Math.abs(pos - dragPos) > 6 && e.target.closest('a')) e.preventDefault(); }, true);

    function start() {
        // ciekawostki zapisane w stronie zostają na początek, potem dochodzą losowe z pliku
        content.querySelectorAll('.marquee-item').forEach(el => { el.dataset.text = el.textContent.trim(); });
        const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        const src = (document.querySelector('script[src*="ciekawostki.js"]') || {}).src || '';
        const url = src ? src.replace(/static\/js\/ciekawostki\.js.*$/, 'api/ciekawostki.json') : '/api/ciekawostki.json';
        fetch(url)
            .then(r => r.ok ? r.json() : [])
            .then(list => {
                pool = (Array.isArray(list) ? list : []).filter(f => f && f.t);
                if (reduce) {
                    // bez ruchu: pokaż jedną losową ciekawostkę na raz, zmieniaj co 12 s
                    const show = () => { const f = nextFact(); if (f) { content.innerHTML = ''; content.appendChild(makeItem(f)); } };
                    show(); setInterval(show, 12000);
                    return;
                }
                requestAnimationFrame(step);
            })
            .catch(() => { if (!reduce) requestAnimationFrame(step); });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
})();
