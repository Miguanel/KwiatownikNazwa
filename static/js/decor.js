// ==========================================
// OZDOBY PRZY NAZWACH KATEGORII – kopczyk ziemi z wyrastającą gałązką
// Tylko przy stałych nagłówkach kategorii (.section-title, .bestiary-header – np. „Bestiariusz Roślin”,
// „Księga Przepisów”), nie na kartach roślin ani w przewijanych karuzelach.
// Ozdoba stoi tuż za nazwą kategorii, na linii plecionki pod nagłówkiem: kopczyk ziemi (grudki,
// kamyki, korzonki, mech), z którego wyrasta gałązka z liśćmi; obok rozsypane drobiny ziemi.
// Kształt jest stały dla danego nagłówka (zależy od jego tekstu).
// Sposób pojawiania się zależy od pory dnia (html[data-kw-pora]):
//   rano    – gałązka powoli rozwija liście, potem na liściach osiada rosa,
//   dzień   – ziemia się osypuje, gałązka wyrasta z kopczyka,
//   wieczór – złotawe liście opadają, kołysząc się, na gałązkę,
//   noc     – (tryb nocny) wszystko wyłania się z mroku, żyłki liści i mech świecą, migoczą zarodniki.
// Animacja startuje, gdy nagłówek wjeżdża na ekran, i powtarza się po przełączeniu dnia/nocy.
// Przy „ograniczeniu ruchu” w systemie ozdoby są od razu na miejscu.
// ==========================================
(function () {
    'use strict';

    const root = document.documentElement;
    const SEL = '.section-title, .bestiary-header';

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
    const f1 = n => n.toFixed(1);

    const LEAF = 'M0 0C6-7.5 18-8.5 27 0C18 8.5 6 7.5 0 0Z';
    let uid = 0;

    // kopczyk: nieregularny wierzch z kilku łuków
    function moundPath(r) {
        const x0 = 3, x1 = 60, base = 58;
        const peak = 40 + r() * 4;
        const pts = [];
        const n = 9;
        for (let i = 0; i <= n; i++) {
            const t = i / n;
            const x = x0 + (x1 - x0) * t;
            const y = base - (base - peak) * Math.pow(Math.sin(Math.PI * t), 0.8) + (i && i < n ? (r() - 0.5) * 3 : 0);
            pts.push([x, y]);
        }
        let d = `M${f1(pts[0][0])} ${base}`;
        for (let i = 1; i < pts.length; i++) {
            const [px, py] = pts[i - 1], [x, y] = pts[i];
            d += ` Q${f1((px + x) / 2 + (r() - 0.5) * 2)} ${f1(Math.min(py, y) - r() * 2.5)} ${f1(x)} ${f1(y)}`;
        }
        return d + ' Z';
    }

    function build(r) {
        const id = 'kdg' + (++uid);
        let s = `<svg class="kd-art" viewBox="0 -8 120 70" aria-hidden="true" focusable="false"><defs>` +
            `<linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="kd-soil-top"/><stop offset="1" class="kd-soil-bot"/></linearGradient></defs>`;

        // --- gałązka (pod spodem – wyrasta z ziemi) ---
        const sx = 30 + r() * 4;
        const stem = `M${f1(sx)} 47C${f1(sx - 1)} 31 ${f1(sx + 9)} 19 ${f1(sx + 30)} 12C${f1(sx + 44)} 8 ${f1(sx + 56)} 11 ${f1(sx + 66)} 19`;
        s += `<path class="kd-stem" pathLength="1" d="${stem}"/>`;
        s += `<path class="kd-tendril" d="M${f1(sx + 40)} 10c4-7 13-6 12 1c-.5 4-6 4-5.5 0"/>`;
        const leaves = [[2, 35, -150, 0.66], [6, 27, -35, 0.72], [15, 19, -100, 0.78], [27, 13, 28, 0.84], [41, 10, -58, 0.84], [66, 19, 34, 1]];
        let dew = '';
        leaves.forEach((L, i) => {
            const x = sx + L[0], y = L[1], ang = L[2] + (r() - 0.5) * 14, sc = L[3] * (0.92 + r() * 0.16);
            const cls = i % 2 ? 'kd-a' : 'kd-b';
            s += `<g transform="translate(${f1(x)} ${f1(y)}) rotate(${ang.toFixed(0)}) scale(${sc.toFixed(2)})">` +
                `<g class="kd-leaf" style="--i:${i}"><path class="${cls}" d="${LEAF}"/><path class="kd-vein" d="M1 0L24 0M8 0l5-4M8 0l5 4M15 0l5-3.4M15 0l5 3.4"/></g></g>`;
            if (i % 2 === 1 || i === leaves.length - 1) {
                const rad = ang * Math.PI / 180, l = 24 * sc;
                dew += `<circle class="kd-dew" style="--i:${i}" cx="${f1(x + Math.cos(rad) * l)}" cy="${f1(y + Math.sin(rad) * l + 1.6)}" r="${f1(1.5 + r() * 0.8)}"/>`;
            }
        });
        s += dew;

        // --- kopczyk ziemi ---
        s += `<path class="kd-mound" d="${moundPath(r)}" fill="url(#${id})"/>`;
        // korzonki wystające z ziemi
        s += `<path class="kd-root" d="M10 56c-3 1-5 3-8 3M52 55c3 0 5 2 9 2M44 57c1 1 1 3 3 4"/>`;
        // grudki – zaokrąglone wielokąty w kilku odcieniach
        for (let i = 0; i < 7; i++) {
            const cx = 9 + r() * 46, cy = 47 + r() * 9, rr = 1.6 + r() * 2.4;
            let d = '';
            const k = 5 + Math.floor(r() * 3);
            for (let j = 0; j < k; j++) {
                const a = j / k * Math.PI * 2, q = rr * (0.7 + r() * 0.5);
                d += (j ? 'L' : 'M') + f1(cx + Math.cos(a) * q) + ' ' + f1(cy + Math.sin(a) * q * 0.8);
            }
            s += `<path class="kd-clod kd-clod${i % 3}" style="--i:${i}" d="${d}Z"/>`;
        }
        // kamyki z odblaskiem
        for (let i = 0; i < 3; i++) {
            const cx = 12 + r() * 40, cy = 51 + r() * 6, rx = 1.8 + r() * 1.8;
            s += `<g class="kd-pebble" style="--i:${i}"><ellipse cx="${f1(cx)}" cy="${f1(cy)}" rx="${f1(rx)}" ry="${f1(rx * 0.65)}"/>` +
                `<ellipse class="kd-shine" cx="${f1(cx - rx * 0.3)}" cy="${f1(cy - rx * 0.25)}" rx="${f1(rx * 0.35)}" ry="${f1(rx * 0.2)}"/></g>`;
        }
        // kępki mchu na wierzchu
        for (let i = 0; i < 4; i++) {
            const cx = 12 + i * 11 + r() * 6, cy = 44 + Math.abs(cx - 31) * 0.38 + r() * 2;
            s += `<path class="kd-moss" style="--i:${i}" d="M${f1(cx - 3.5)} ${f1(cy + 1.5)}q1-3.5 3.5-3q2.5-1.5 3.5 2q.5 1.5-1 1.5z"/>`;
        }
        // drobiny ziemi rozsypane obok kopczyka
        for (let i = 0; i < 12; i++) {
            const x = 58 + r() * 34, y = 52 + r() * 7;
            s += `<circle class="kd-speck" style="--i:${i}" cx="${f1(x)}" cy="${f1(y)}" r="${f1(0.5 + r() * 1.1)}"/>`;
        }
        // zeschły listek obok
        s += `<g transform="translate(${f1(74 + r() * 10)} 58) rotate(${(-170 + r() * 30).toFixed(0)}) scale(.42)"><g class="kd-leaf kd-fallen" style="--i:6"><path class="kd-c" d="${LEAF}"/><path class="kd-vein" d="M1 0L24 0"/></g></g>`;
        // zarodniki (widoczne nocą)
        for (let i = 0; i < 6; i++) s += `<circle class="kd-spore" style="--i:${i};--d:${f1(2.2 + r() * 2.6)}s" cx="${f1(14 + r() * 92)}" cy="${f1(4 + r() * 40)}" r="${f1(0.8 + r() * 1)}"/>`;
        return s + '</svg>';
    }

    // ---------- ustawienie tuż za nazwą kategorii ----------
    function place(h) {
        const d = h.querySelector(':scope > .kd-head');
        if (!d) return;
        // koniec tekstu nagłówka (bez samej ozdoby)
        const range = document.createRange();
        range.setStart(h, 0);
        range.setEndBefore(d);
        const rects = [...range.getClientRects()].filter(r => r.width > 0);
        const hb = h.getBoundingClientRect();
        const end = rects.length ? Math.max(...rects.map(r => r.right)) - hb.left : 0;
        const w = d.offsetWidth;
        d.style.left = Math.max(0, Math.min(end + 6, h.clientWidth - w)) + 'px';
    }

    const io = 'IntersectionObserver' in window ? new IntersectionObserver(entries => {
        entries.forEach(e => {
            const d = e.target.querySelector(':scope > .kd-head');
            if (!d) return;
            if (e.isIntersecting) d.classList.add('kd-in', 'kd-vis'); else d.classList.remove('kd-vis');
        });
    }, { rootMargin: '0px 0px -6% 0px', threshold: 0.3 }) : null;

    function decorate(h) {
        if (h.querySelector(':scope > .kd-head')) return;
        const r = rng(hash(h.textContent.trim().slice(0, 60)));
        const d = document.createElement('span');
        d.className = 'kd kd-head' + (h.classList.contains('bestiary-header') ? ' kd-big' : '');
        d.setAttribute('aria-hidden', 'true');
        d.style.setProperty('--kd-delay', (r() * 0.2).toFixed(2) + 's');
        d.innerHTML = build(r);
        h.appendChild(d);
        place(h);
        // licznik przy nazwie (np. „(42)”) dopisuje się później – przesuń ozdobę za nim
        new MutationObserver(() => place(h)).observe(h, { childList: true, subtree: true, characterData: true });
        if ('ResizeObserver' in window) new ResizeObserver(() => place(h)).observe(h);
        if (io) io.observe(h); else d.classList.add('kd-in', 'kd-vis');
    }

    // po zmianie dnia/nocy: odtwórz animację na widocznych nagłówkach
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
        document.querySelectorAll(SEL).forEach(decorate);
        // czcionki z Google wczytują się później i zmieniają szerokość tekstu
        if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => document.querySelectorAll(SEL).forEach(place));
    }
    setPora();
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
