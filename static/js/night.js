// ==========================================
// DZIEŃ / NOC – przełącznik w górnym pasku + świetliki w trybie nocnym
// Wybór zapamiętywany w localStorage („kw_theme”); skrypt w <head> base.html ustawia
// html[data-theme="night"] jeszcze przed narysowaniem strony (bez mignięcia jasnego tła).
// Świetliki: <canvas id="kwFireflies"> na całym ekranie (nie łapie kliknięć), kilkadziesiąt
// ciepłych, migoczących punktów błądzących powoli jak nad nocną łąką. Przy „ograniczeniu ruchu”
// w systemie świetliki stoją i tylko delikatnie się żarzą.
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
    // ŚWIETLIKI
    // ------------------------------------------
    const fireflies = (function () {
        let canvas = null, ctx = null, w = 0, h = 0, dpr = 1;
        let flies = [], running = false, raf = null, last = 0;

        function make() {
            canvas = document.createElement('canvas');
            canvas.id = 'kwFireflies';
            canvas.setAttribute('aria-hidden', 'true');
            document.body.appendChild(canvas);
            ctx = canvas.getContext('2d');
            window.addEventListener('resize', resize);
            resize();
        }

        function resize() {
            if (!canvas) return;
            dpr = Math.min(window.devicePixelRatio || 1, 2);
            w = window.innerWidth; h = window.innerHeight;
            canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            const want = Math.round(Math.min(46, Math.max(14, (w * h) / 32000)));
            while (flies.length < want) flies.push(spawn(true));
            if (flies.length > want) flies.length = want;
        }

        function spawn(anywhere) {
            return {
                x: Math.random() * w,
                y: anywhere ? Math.random() * h : h + 10,
                // więcej świetlików w dolnej części ekranu – jak nad trawą
                vx: (Math.random() - 0.5) * 0.25,
                vy: -0.05 - Math.random() * 0.12,
                ang: Math.random() * Math.PI * 2,
                turn: (Math.random() - 0.5) * 0.02,
                r: 1.2 + Math.random() * 1.8,
                phase: Math.random() * Math.PI * 2,
                speed: 0.6 + Math.random() * 1.4,           // tempo migotania
                hue: Math.random() < 0.8 ? 'warm' : 'green'
            };
        }

        function draw(t) {
            ctx.clearRect(0, 0, w, h);
            ctx.globalCompositeOperation = 'lighter';
            flies.forEach(f => {
                // jasność: powolne „oddychanie” + co jakiś czas krótki błysk
                const pulse = 0.5 + 0.5 * Math.sin(t / 1000 * f.speed + f.phase);
                const glow = Math.pow(pulse, 3);
                const a = 0.08 + 0.85 * glow;
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
                ctx.fillStyle = `rgba(255, 250, 220, ${Math.min(1, a + 0.1)})`;
                ctx.beginPath(); ctx.arc(f.x, f.y, f.r * 0.6, 0, Math.PI * 2); ctx.fill();
            });
            ctx.globalCompositeOperation = 'source-over';
        }

        function step(t) {
            if (!running) return;
            raf = requestAnimationFrame(step);
            if (t - last < 33) return;                      // ~30 klatek/s
            const dt = Math.min(3, (t - last) / 16.7 || 1);
            last = t;
            flies.forEach((f, i) => {
                f.ang += f.turn * dt + (Math.random() - 0.5) * 0.08;
                f.x += (f.vx + Math.cos(f.ang) * 0.35) * dt;
                f.y += (f.vy + Math.sin(f.ang) * 0.25) * dt;
                if (f.x < -20) f.x = w + 20; else if (f.x > w + 20) f.x = -20;
                if (f.y < -20) flies[i] = spawn(false);
            });
            draw(t);
        }

        return {
            start() {
                if (!canvas) make();
                if (reduceMotion) { draw(performance.now()); return; }
                if (running) return;
                running = true; last = 0;
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
