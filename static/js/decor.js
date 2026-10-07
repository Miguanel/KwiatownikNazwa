// ==========================================
// OZDOBY KART ROŚLIN – gałązki z liśćmi i ślady ziemi na kartach
// Każda karta rośliny dostaje w rogu gałązkę (5 liści, wąs, krople rosy, zarodniki) i w przeciwnym
// rogu grudki ziemi / mech. Kształt jest stały dla danej rośliny (zależy od jej nazwy), więc karta
// wygląda tak samo po każdym wejściu, a różne karty różnią się między sobą.
// Sposób pojawiania się ozdób zależy od pory dnia (html[data-kw-pora]):
//   rano    – liście rozwijają się, potem na końcach liści osiadają krople rosy,
//   dzień   – gałązka wyrasta z rogu, ziemia osypuje się z góry,
//   wieczór – liście opadają kołysząc się i kładą na karcie, złotawe barwy,
//   noc     – (tryb nocny, niezależnie od godziny) ozdoby wyłaniają się z mroku, żyłki liści
//             i mech zaczynają świecić, wokół gałązki migoczą zarodniki.
// Animacja startuje, gdy karta wjeżdża na ekran, i powtarza się po przełączeniu dnia/nocy.
// Przy „ograniczeniu ruchu” w systemie ozdoby są od razu na miejscu.
// ==========================================
(function () {
    'use strict';

    const root = document.documentElement;
    // karta -> rozmiar gałązki (px); obrazkowe karty mają gałązkę w lewym lub prawym rogu,
    // tekstowe zawsze w prawym (tytuły są wyrównane do lewej)
    const TARGETS = [
        { sel: '.witcher-card', size: 92, img: true },
        { sel: '.mini-card', size: 58, img: true },
        { sel: '.result-card', size: 52, img: false },
        { sel: '.thera-card', size: 52, img: false },
        { sel: '.grimmoire-hero', size: 120, img: true, hero: true }
    ];
    const SEL = TARGETS.map(t => t.sel).join(',');

    // ---------- pora dnia ----------
    function pora() {
        if (root.getAttribute('data-theme') === 'night') return 'noc';
        const h = new Date().getHours();
        if (h >= 5 && h < 10) return 'rano';
        if (h >= 17 || h < 5) return 'wieczor';
        return 'dzien';
    }
    function setPora() {
        const p = pora();
        if (root.getAttribute('data-kw-pora') === p) return false;
        root.setAttribute('data-kw-pora', p);
        return true;
    }

    // ---------- kształty ----------
    function hash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
    function rng(seed) { let s = seed || 1; return () => ((s = Math.imul(s ^ (s >>> 15), 2246822507) ^ Math.imul(s ^ (s >>> 13), 3266489909)) >>> 0) / 4294967296; }

    const LEAF = 'M0 0C6-7.5 18-8.5 27 0C18 8.5 6 7.5 0 0Z';
    const NS = 'http://www.w3.org/2000/svg';

    function sprig(r) {
        // łodyga z rogu (0,0) na ukos; liście naprzemiennie po obu stronach
        const bend = 8 + r() * 10;
        const ex = 66 + r() * 8, ey = 40 + r() * 10;
        const stem = `M1 1C${18 + bend} ${6 + r() * 4} ${38} ${20 + bend * 0.6} ${ex} ${ey}`;
        const pts = [[13, 5], [24, 10], [37, 18], [50, 27], [ex, ey]];
        let leaves = '', dew = '';
        pts.forEach((p, i) => {
            const side = i === pts.length - 1 ? 0 : (i % 2 ? -1 : 1);
            const ang = (i === pts.length - 1 ? 32 : side * (38 + r() * 26) + 30) + (r() - 0.5) * 12;
            const sc = (0.62 + i * 0.1) * (0.9 + r() * 0.2);
            const cls = (i + (r() > 0.5 ? 1 : 0)) % 2 ? 'kd-a' : 'kd-b';
            leaves += `<g transform="translate(${p[0].toFixed(1)} ${p[1].toFixed(1)}) rotate(${ang.toFixed(0)}) scale(${sc.toFixed(2)})">` +
                `<g class="kd-leaf" style="--i:${i}"><path class="${cls}" d="${LEAF}"/><path class="kd-vein" d="M1 0L24 0M8 0l5-4M8 0l5 4M15 0l5-3.4M15 0l5 3.4"/></g></g>`;
            if (i % 2 === 0 || i === pts.length - 1) {
                const rad = ang * Math.PI / 180, L = 25 * sc;
                dew += `<circle class="kd-dew" style="--i:${i}" cx="${(p[0] + Math.cos(rad) * L).toFixed(1)}" cy="${(p[1] + Math.sin(rad) * L + 1.5).toFixed(1)}" r="${(1.4 + r() * 0.9).toFixed(1)}"/>`;
            }
        });
        const tendril = `<path class="kd-tendril" d="M43 23c3 10 13 11 12 3c-.6-3.8-5.4-3.4-5 0"/>`;
        let spores = '';
        for (let i = 0; i < 6; i++) spores += `<circle class="kd-spore" style="--i:${i};--d:${(2.2 + r() * 2.6).toFixed(1)}s" cx="${(14 + r() * 74).toFixed(0)}" cy="${(14 + r() * 60).toFixed(0)}" r="${(0.9 + r() * 1.1).toFixed(1)}"/>`;
        return `<svg class="kd-sprig" viewBox="0 0 100 80" aria-hidden="true" focusable="false">` +
            `<path class="kd-stem" pathLength="1" d="${stem}"/>${tendril}${leaves}${dew}${spores}</svg>`;
    }

    function dirt(r) {
        // grudki i plamy ziemi przy dolnej krawędzi (róg w punkcie 100,60), drobiny rozsypane wyżej
        let blobs = '', specks = '';
        for (let i = 0; i < 4; i++) {
            const cx = 62 + r() * 34, cy = 46 + r() * 12, rx = 9 + r() * 14, ry = 4 + r() * 6;
            blobs += `<ellipse class="kd-blob" style="--i:${i}" cx="${cx.toFixed(0)}" cy="${cy.toFixed(0)}" rx="${rx.toFixed(0)}" ry="${ry.toFixed(0)}" transform="rotate(${((r() - 0.5) * 30).toFixed(0)} ${cx.toFixed(0)} ${cy.toFixed(0)})"/>`;
        }
        for (let i = 0; i < 11; i++) {
            const x = 40 + r() * 58, y = 22 + r() * 36;
            specks += `<circle class="kd-speck" style="--i:${i}" cx="${x.toFixed(0)}" cy="${y.toFixed(0)}" r="${(0.8 + r() * 1.8).toFixed(1)}"/>`;
        }
        // mały zeschły listek w ziemi
        const lx = 58 + r() * 20, ly = 50 + r() * 6;
        const fallen = `<g transform="translate(${lx.toFixed(0)} ${ly.toFixed(0)}) rotate(${(-150 + r() * 60).toFixed(0)}) scale(.45)"><g class="kd-leaf kd-fallen" style="--i:5"><path class="kd-c" d="${LEAF}"/><path class="kd-vein" d="M1 0L24 0"/></g></g>`;
        return `<svg class="kd-dirt" viewBox="0 0 100 60" preserveAspectRatio="xMaxYMax meet" aria-hidden="true" focusable="false">${blobs}${fallen}${specks}</svg>`;
    }

    // ---------- doklejanie do kart ----------
    const io = 'IntersectionObserver' in window ? new IntersectionObserver(entries => {
        entries.forEach(e => {
            const d = e.target.querySelector(':scope > .kd');
            if (!d) return;
            if (e.isIntersecting) { d.classList.add('kd-in', 'kd-vis'); }
            else d.classList.remove('kd-vis');
        });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.15 }) : null;

    function decorate(card, t) {
        if (card.querySelector(':scope > .kd')) return;
        const key = (card.querySelector('h1,h2,h3,h4,h5,.witcher-card-title,.mini-card-title,.card-title') || card).textContent.trim().slice(0, 80) || String(Math.random());
        const r = rng(hash(key));
        const flip = t.hero ? false : (t.img ? r() > 0.5 : true);   // true = gałązka w prawym górnym rogu
        if (getComputedStyle(card).position === 'static') card.style.position = 'relative';
        const d = document.createElement('span');
        d.className = 'kd' + (flip ? ' kd-flip' : '') + (t.hero ? ' kd-hero' : '');
        d.setAttribute('aria-hidden', 'true');
        d.style.setProperty('--kd-size', t.size + 'px');
        d.style.setProperty('--kd-delay', (r() * 0.25).toFixed(2) + 's');
        d.innerHTML = sprig(r) + dirt(r) + (t.hero ? `<span class="kd-2">${sprig(r)}</span>` : '');
        card.appendChild(d);
        if (io) io.observe(card); else d.classList.add('kd-in', 'kd-vis');
    }

    function scan(scope) {
        TARGETS.forEach(t => (scope || document).querySelectorAll(t.sel).forEach(c => decorate(c, t)));
    }

    // karty indeksu i wyszukiwarki są dorysowywane skryptami – pilnuj nowych
    let pending = false;
    const mo = new MutationObserver(muts => {
        if (pending) return;
        if (!muts.some(m => [...m.addedNodes].some(n => n.nodeType === 1 && (n.matches(SEL) || n.querySelector(SEL))))) return;
        pending = true;
        requestAnimationFrame(() => { pending = false; scan(); });
    });

    // po zmianie dnia/nocy: odtwórz animację na widocznych kartach
    function replay() {
        document.querySelectorAll('.kd.kd-in').forEach(d => {
            d.classList.remove('kd-in');
            if (d.classList.contains('kd-vis')) { void d.offsetWidth; d.classList.add('kd-in'); }
        });
    }
    new MutationObserver(() => { if (setPora()) replay(); }).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
    setInterval(() => { if (setPora()) replay(); }, 10 * 60 * 1000);

    function init() {
        setPora();
        scan();
        mo.observe(document.body, { childList: true, subtree: true });
    }
    setPora();
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
