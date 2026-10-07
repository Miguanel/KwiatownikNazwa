// ==========================================
// OZDOBY PRZY NAZWACH KATEGORII – kopczyk ziemi z wyrastającą gałązką
// Tylko przy stałych nagłówkach kategorii (.section-title, .bestiary-header – np. „Bestiariusz Roślin”,
// „Księga Przepisów”), nie na kartach roślin ani w przewijanych karuzelach.
// Ozdoba stoi tuż za nazwą kategorii, na linii plecionki pod nagłówkiem: kopczyk ziemi (grudki,
// kamyki, korzonki, mech), z którego wyrasta gałązka z liśćmi; obok rozsypane drobiny ziemi.
// Kształt jest losowany przy każdym wczytaniu strony: wygięcie i wysokość łodygi, kierunek wzrostu,
// liczba (4–7 + szczytowy) i układ liści, kopczyk, grudki i kamyki.
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

        // --- gałązka (pod spodem – wyrasta z ziemi), za każdym razem inna ---
        // Łodyga = jedna krzywa Béziera z losowymi punktami kontrolnymi: inne wygięcie, wysokość
        // i kierunek wzrostu (w lewo lub w prawo). Liście są doczepiane w punktach wyliczonych
        // ze wzoru na krzywą, więc zawsze wyrastają z łodygi.
        const sx = 20 + r() * 20;                                   // miejsce wyjścia z ziemi
        // szczyt odchylony w lewo lub w prawo, ale w obrębie ozdoby (nie wchodzi na tekst nagłówka)
        const endX = Math.max(22, Math.min(100, sx + (r() - 0.5) * 50));
        const endY = 8 + r() * 15;                                  // wysokość roślinki
        const cp1x = sx + (r() - 0.5) * 35, cp1y = 47 - r() * 15;     // wygięcie dolne
        const cp2x = endX + (r() - 0.5) * 35, cp2y = endY + r() * 15; // wygięcie górne
        const stem = `M${f1(sx)} 47C${f1(cp1x)} ${f1(cp1y)} ${f1(cp2x)} ${f1(cp2y)} ${f1(endX)} ${f1(endY)}`;
        s += `<path class="kd-stem" pathLength="1" d="${stem}"/>`;
        // wąs przy szczycie
        s += `<path class="kd-tendril" d="M${f1(endX)} ${f1(endY)}c4-7 13-6 12 1c-.5 4-6 4-5.5 0"/>`;

        // punkt na krzywej Béziera dla t z [0, 1]
        const bez = (t, p0, p1, p2, p3) => {
            const mt = 1 - t;
            return mt * mt * mt * p0 + 3 * mt * mt * t * p1 + 3 * mt * t * t * p2 + t * t * t * p3;
        };

        // 4–7 liści bocznych na przemian po obu stronach, coraz większych ku górze
        const numLeaves = 4 + Math.floor(r() * 4);
        const leaves = [];
        let side = r() > 0.5 ? 1 : -1;                              // strona pierwszego liścia
        for (let j = 0; j < numLeaves; j++) {
            const t = 0.15 + 0.75 * (j / (numLeaves - 1));          // pozycja na łodydze: od dołu do góry
            leaves.push({
                x: bez(t, sx, cp1x, cp2x, endX),
                y: bez(t, 47, cp1y, cp2y, endY),
                ang: side > 0 ? -25 + r() * 50 : -155 + r() * 50,  // w prawo / w lewo, ±25°
                sc: 0.5 + t * 0.4 + r() * 0.2
            });
            side = -side;
        }
        // liść szczytowy – przedłuża kierunek łodygi na jej końcu (styczna: od 2. punktu kontrolnego do końca)
        const tip = Math.atan2(endY - cp2y, endX - cp2x) * 180 / Math.PI;
        leaves.push({ x: endX, y: endY, ang: tip + (r() - 0.5) * 30, sc: 0.85 + r() * 0.3 });

        let dew = '';
        leaves.forEach((L, i) => {
            const cls = i % 2 ? 'kd-a' : 'kd-b';
            s += `<g transform="translate(${f1(L.x)} ${f1(L.y)}) rotate(${L.ang.toFixed(0)}) scale(${L.sc.toFixed(2)})">` +
                `<g class="kd-leaf" style="--i:${i}"><path class="${cls}" d="${LEAF}"/><path class="kd-vein" d="M1 0L24 0M8 0l5-4M8 0l5 4M15 0l5-3.4M15 0l5 3.4"/></g></g>`;
            // kropla rosy na co drugim liściu i na szczytowym
            if (i % 2 === 1 || i === leaves.length - 1) {
                const rad = L.ang * Math.PI / 180, l = 24 * L.sc;
                dew += `<circle class="kd-dew" style="--i:${i}" cx="${f1(L.x + Math.cos(rad) * l)}" cy="${f1(L.y + Math.sin(rad) * l + 1.6)}" r="${f1(1.5 + r() * 0.8)}"/>`;
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
        d.style.left = Math.max(0, Math.min(end + 12, h.clientWidth - w)) + 'px';   // 12 px odstępu – liście wychylone w lewo nie zachodzą na tekst
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
        // nowe ziarno przy każdym wczytaniu strony – roślinka (i kopczyk) za każdym razem inna
        const r = rng(Math.floor(Math.random() * 4294967296));
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
