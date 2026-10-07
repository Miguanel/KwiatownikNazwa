// ==========================================
// DZIEŃ / NOC – przełącznik w górnym pasku + świetliki w górnym pasku w trybie nocnym
// Wybór zapamiętywany w localStorage („kw_theme”); skrypt w <head> base.html ustawia
// html[data-theme="night"] jeszcze przed narysowaniem strony (bez mignięcia jasnego tła).
// Świetliki: <canvas id="kwFireflies"> tylko na nagłówku strony (menu, almanach, ciekawostki),
// nie łapie kliknięć. Nad tekstem świetliki gasną, rozświetlają się tylko na pustym tle.
// Przy „ograniczeniu ruchu” w systemie świetliki stoją i tylko delikatnie się żarzą.
// ==========================================
(function () {
    'use strict';

    const root = document.documentElement;
    const KEY = 'kw_theme';
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const isNight = () => root.getAttribute('data-theme') === 'night';

    function save(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* brak pamięci przeglądarki */ } }

    function setTheme(night, animate) {
        if (animate) {
            root.classList.add('kw-theme-anim');
            setTimeout(() => root.classList.remove('kw-theme-anim'), 650);
        }
        if (night) root.setAttribute('data-theme', 'night'); else root.removeAttribute('data-theme');
        save(night ? 'night' : 'day');
        const meta = document.querySelector('meta[name="theme-color"]');
        if (meta) meta.setAttribute('content', night ? '#0e100d' : '#3e4a3d');
        const btn = document.getElementById('kwThemeToggle');
        if (btn) {
            btn.setAttribute('aria-pressed', night ? 'true' : 'false');
            btn.title = night ? 'Tryb dzienny' : 'Tryb nocny';
            btn.setAttribute('aria-label', btn.title);
        }
        if (night) fireflies.start(); else fireflies.stop();
    }

    // ------------------------------------------
    // ŚWIETLIKI – tylko w górnym pasku (menu, almanach, ciekawostki)
    // Canvas leży na nagłówku (.main-header) i nie łapie kliknięć. Świetlik, który przelatuje nad
    // tekstem (napisy menu, wartości almanachu, ciekawostki, ikony, logo), gaśnie do ledwo widocznego
    // punktu i rozświetla się dopiero, gdy wyleci na puste tło – tekst jest zawsze czytelny.
    // ------------------------------------------
    const fireflies = (function () {
        let host = null, canvas = null, ctx = null, w = 0, h = 0, dpr = 1;
        let flies = [], running = false, raf = null, last = 0;
        let textEls = [], rects = [], lastScan = 0, lastRects = 0;
        const PAD = 7;                                   // margines wokół tekstu (px)

        function make() {
            host = document.querySelector('.main-header');
            if (!host) return false;
            canvas = document.createElement('canvas');
            canvas.id = 'kwFireflies';
            canvas.setAttribute('aria-hidden', 'true');
            host.appendChild(canvas);
            ctx = canvas.getContext('2d');
            if ('ResizeObserver' in window) new ResizeObserver(resize).observe(host);
            window.addEventListener('resize', resize);
            resize();
            return true;
        }

        function resize() {
            if (!canvas) return;
            dpr = Math.min(window.devicePixelRatio || 1, 2);
            w = host.clientWidth; h = host.clientHeight;
            canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            const want = Math.round(Math.min(26, Math.max(7, (w * h) / 7000)));
            flies.forEach(f => { if (f.y > h - 3) f.y = Math.random() * h; });
            while (flies.length < want) flies.push(spawn());
            if (flies.length > want) flies.length = want;
            lastScan = 0;
        }

        function spawn() {
            return {
                x: Math.random() * w,
                y: 4 + Math.random() * Math.max(1, h - 8),
                vx: (Math.random() - 0.5) * 0.3,
                ang: Math.random() * Math.PI * 2,
                turn: (Math.random() - 0.5) * 0.02,
                r: 0.9 + Math.random() * 1.3,
                phase: Math.random() * Math.PI * 2,
                speed: 0.6 + Math.random() * 1.4,           // tempo migotania
                hue: Math.random() < 0.8 ? 'warm' : 'green',
                vis: 1                                       // 1 = może świecić, 0 = nad tekstem
            };
        }

        // --- gdzie w pasku jest tekst ---
        function scanText() {
            // elementy z własnym tekstem + ikony i obrazki; lista odświeżana co 0,8 s
            // (pasek ciekawostek ciągle dokłada i usuwa pozycje)
            textEls = [];
            host.querySelectorAll('*').forEach(el => {
                if (el === canvas) return;
                if (/^(I|IMG|SVG|INPUT|BUTTON|SELECT)$/i.test(el.tagName)) { textEls.push(el); return; }
                for (const n of el.childNodes) {
                    if (n.nodeType === 3 && n.nodeValue.trim()) { textEls.push(el); return; }
                }
            });
        }
        function measure() {
            // prostokąty tekstu we współrzędnych canvasu; pozycje mierzone co ~0,1 s,
            // bo pasek ciekawostek i almanachu się przesuwa
            const hb = host.getBoundingClientRect();
            rects = [];
            textEls.forEach(el => {
                for (const r of el.getClientRects()) {
                    if (r.width < 1 || r.height < 1) continue;
                    if (r.right < hb.left || r.left > hb.right || r.bottom < hb.top || r.top > hb.bottom) continue;
                    rects.push([r.left - hb.left - PAD, r.top - hb.top - PAD, r.right - hb.left + PAD, r.bottom - hb.top + PAD]);
                }
            });
        }
        function overText(x, y) {
            for (let i = 0; i < rects.length; i++) {
                const r = rects[i];
                if (x >= r[0] && x <= r[2] && y >= r[1] && y <= r[3]) return true;
            }
            return false;
        }
        function refresh(t) {
            if (t - lastScan > 800) { scanText(); lastScan = t; lastRects = 0; }
            if (t - lastRects > 100) { measure(); lastRects = t; }
        }

        function draw(t) {
            ctx.clearRect(0, 0, w, h);
            ctx.globalCompositeOperation = 'lighter';
            flies.forEach(f => {
                // jasność: powolne „oddychanie” + co jakiś czas krótki błysk; nad tekstem – zgaszony
                const pulse = 0.5 + 0.5 * Math.sin(t / 1000 * f.speed + f.phase);
                const glow = Math.pow(pulse, 3) * f.vis;
                const core = 0.1 + 0.8 * Math.pow(pulse, 3) * (0.15 + 0.85 * f.vis);
                if (glow > 0.02) {
                    const a = 0.85 * glow;
                    const R = f.r * (4 + 6 * glow);
                    const g = ctx.createRadialGradient(f.x, f.y, 0, f.x, f.y, R);
                    if (f.hue === 'warm') {
                        g.addColorStop(0, `rgba(255, 236, 150, ${a})`);
                        g.addColorStop(0.35, `rgba(230, 200, 90, ${a * 0.45})`);
                        g.addColorStop(1, 'rgba(200, 160, 60, 0)');
                    } else {
                        g.addColorStop(0, `rgba(215, 255, 170, ${a})`);
                        g.addColorStop(0.35, `rgba(150, 210, 110, ${a * 0.45})`);
                        g.addColorStop(1, 'rgba(110, 170, 80, 0)');
                    }
                    ctx.fillStyle = g;
                    ctx.beginPath(); ctx.arc(f.x, f.y, R, 0, Math.PI * 2); ctx.fill();
                }
                ctx.fillStyle = `rgba(255, 245, 210, ${Math.min(1, core)})`;
                ctx.beginPath(); ctx.arc(f.x, f.y, f.r * (0.35 + 0.25 * f.vis), 0, Math.PI * 2); ctx.fill();
            });
            ctx.globalCompositeOperation = 'source-over';
        }

        function move(dt) {
            flies.forEach(f => {
                f.ang += f.turn * dt + (Math.random() - 0.5) * 0.08;
                f.x += (f.vx + Math.cos(f.ang) * 0.35) * dt;
                f.y += Math.sin(f.ang) * 0.22 * dt;
                if (f.x < -10) f.x = w + 10; else if (f.x > w + 10) f.x = -10;
                // odbicie od górnej i dolnej krawędzi paska
                if (f.y < 3) { f.y = 3; f.ang = -f.ang; } else if (f.y > h - 3) { f.y = h - 3; f.ang = -f.ang; }
                // płynne gaśnięcie nad tekstem (~0,2 s) i rozpalanie poza nim (~0,6 s)
                const target = overText(f.x, f.y) ? 0 : 1;
                f.vis += (target - f.vis) * Math.min(1, (target ? 0.06 : 0.25) * dt);
            });
        }

        function step(t) {
            if (!running) return;
            raf = requestAnimationFrame(step);
            if (t - last < 33) return;                      // ~30 klatek/s
            const dt = Math.min(3, (t - last) / 16.7 || 1);
            last = t;
            refresh(t);
            move(dt);
            draw(t);
        }

        return {
            start() {
                if (!canvas && !make()) return;
                if (reduceMotion) {
                    // bez ruchu: świetliki stoją; te nad tekstem są zgaszone
                    const t = performance.now();
                    scanText(); measure();
                    flies.forEach(f => { f.vis = overText(f.x, f.y) ? 0 : 1; });
                    draw(t);
                    return;
                }
                if (running) return;
                running = true; last = 0; lastScan = 0;
                raf = requestAnimationFrame(step);
            },
            stop() {
                running = false;
                if (raf) cancelAnimationFrame(raf);
                raf = null;
                if (ctx) setTimeout(() => { if (!running) ctx.clearRect(0, 0, w, h); }, 1300);   // po wygaszeniu (CSS)
            }
        };
    })();

    // przeglądarka sama wstrzymuje requestAnimationFrame w ukrytej karcie

    function init() {
        const btn = document.getElementById('kwThemeToggle');
        if (btn) btn.addEventListener('click', () => setTheme(!isNight(), true));
        setTheme(isNight(), false);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
