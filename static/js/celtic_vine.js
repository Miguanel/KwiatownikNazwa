// ==========================================
// ŻYWA CELTYCKA GAŁĄŹ (pas pod nagłówkiem)
// Dwie splecione gałązki (złota i zielona) przesuwają się bez końca – segmenty wjeżdżają z prawej
// i znikają z lewej. Co kilka sekund z gałązki wyrasta pęd z liściem: pęd rośnie, liść się rozwija,
// chwilę trwa i blednie. Rysowane na <canvas> w każdym elemencie .kw-vine.
// Przy „ograniczeniu ruchu” w systemie (prefers-reduced-motion) rysuje się jeden nieruchomy kadr.
// ==========================================
(function () {
    'use strict';

    const GOLD = '#9a7b2f', MOSS = '#3e4a3d', LEAF = '#5f7a3a', LEAF_LIGHT = '#8a9a5b';
    const HALO = 'rgba(244, 241, 234, 0.95)';          // tło pod skrzyżowaniem (efekt przeplotu)
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function Vine(el) {
        this.el = el;
        this.canvas = document.createElement('canvas');
        this.canvas.setAttribute('aria-hidden', 'true');
        el.appendChild(this.canvas);
        this.ctx = this.canvas.getContext('2d');
        this.offset = Math.random() * 1000;     // przesunięcie splotu (rośnie z czasem)
        this.speed = 14;                        // px na sekundę
        this.period = 32;                       // długość jednego splotu w px
        this.amp = 4;                         // wychylenie gałązek
        this.sprouts = [];
        this.nextSprout = 0.8;
        this.last = 0;
        this.resize();
        if ('ResizeObserver' in window) new ResizeObserver(() => this.resize()).observe(el);
        else window.addEventListener('resize', () => this.resize());
    }

    Vine.prototype.resize = function () {
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        this.w = Math.max(1, this.el.clientWidth);
        this.h = Math.max(1, this.el.clientHeight);
        this.canvas.width = Math.round(this.w * dpr);
        this.canvas.height = Math.round(this.h * dpr);
        this.canvas.style.width = this.w + 'px';
        this.canvas.style.height = this.h + 'px';
        this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        this.cy = 6;                            // oś splotu (pas u góry elementu; pędy zwisają w dół)
        if (reduceMotion) this.drawStatic();
    };

    // y gałązki (s = +1 złota, -1 zielona) w punkcie x ekranu
    Vine.prototype.y = function (x, s) {
        const k = (2 * Math.PI) / (this.period * 2);
        return this.cy + s * this.amp * Math.sin(k * (x + this.offset));
    };

    Vine.prototype.strand = function (x0, x1, s, color, width) {
        const c = this.ctx;
        c.beginPath();
        for (let x = x0; x <= x1 + 1; x += 2) {
            const y = this.y(x, s);
            if (x === x0) c.moveTo(x, y); else c.lineTo(x, y);
        }
        c.strokeStyle = color; c.lineWidth = width; c.lineCap = 'round'; c.stroke();
    };

    Vine.prototype.drawStrands = function () {
        const w = this.w;
        // pełne gałązki
        this.strand(0, w, -1, MOSS, 1.6);
        this.strand(0, w, 1, GOLD, 1.6);
        // co drugi odcinek złota gałązka przechodzi POD zieloną: zielona dostaje „halo” i jest rysowana na wierzchu
        const P = this.period;
        let n = Math.floor(this.offset / P);
        for (let x = n * P - this.offset; x < w; x += P, n++) {
            if (n % 2 !== 0) continue;
            const a = Math.max(0, x + 3), b = Math.min(w, x + P - 3);
            if (b <= a) continue;
            this.strand(a, b, -1, HALO, 4.2);
            this.strand(a, b, -1, MOSS, 1.6);
        }
    };

    // --- pęd z liściem ---
    Vine.prototype.addSprout = function () {
        const x = this.w * (0.08 + Math.random() * 0.86);
        const side = Math.random() < 0.5 ? 1 : -1;               // na którą gałązkę / w którą stronę się wygina
        this.sprouts.push({
            x,                                                    // pozycja na ekranie (przesuwa się razem ze splotem)
            s: side,
            len: 10 + Math.random() * 7,                           // długość pędu
            bend: (Math.random() < 0.5 ? -1 : 1) * (4 + Math.random() * 6),
            leaf: 5 + Math.random() * 2.5,
            color: Math.random() < 0.6 ? LEAF : LEAF_LIGHT,
            age: 0,
            life: 7 + Math.random() * 4
        });
    };

    Vine.prototype.drawSprout = function (p) {
        const c = this.ctx;
        const grow = Math.min(1, p.age / 1.6);                    // 1.6 s – rośnie pęd
        const unfurl = Math.max(0, Math.min(1, (p.age - 1.2) / 1.2)); // potem rozwija się liść
        const fade = Math.max(0, Math.min(1, (p.life - p.age) / 1.5)); // na końcu blednie
        const ease = t => 1 - Math.pow(1 - t, 3);
        const g = ease(grow);
        const x0 = p.x, y0 = this.y(p.x, p.s);
        // pęd: krzywa w dół, wygięta na bok
        const x1 = x0 + p.bend * g, y1 = y0 + p.len * g;
        const cx = x0 + p.bend * 0.1, cy = y0 + p.len * 0.7 * g;
        c.save();
        c.globalAlpha = fade;
        c.beginPath();
        c.moveTo(x0, y0);
        c.quadraticCurveTo(cx, cy, x1, y1);
        c.strokeStyle = MOSS; c.lineWidth = 1.2; c.lineCap = 'round'; c.stroke();
        if (unfurl > 0) {
            const u = ease(unfurl);
            const ang = Math.atan2(y1 - cy, x1 - cx);
            c.translate(x1, y1);
            c.rotate(ang - Math.PI / 2 + (p.bend > 0 ? -0.5 : 0.5));
            const L = p.leaf * 1.9 * u, W = p.leaf * 0.85 * u;
            c.beginPath();                                        // liść: dwa łuki
            c.moveTo(0, 0);
            c.quadraticCurveTo(W, L * 0.5, 0, L);
            c.quadraticCurveTo(-W, L * 0.5, 0, 0);
            c.fillStyle = p.color; c.fill();
            c.beginPath(); c.moveTo(0, 0); c.lineTo(0, L * 0.85); // nerw liścia
            c.strokeStyle = 'rgba(253, 250, 240, 0.7)'; c.lineWidth = 0.6; c.stroke();
        }
        c.restore();
    };

    Vine.prototype.frame = function (t) {
        const dt = this.last ? Math.min(0.1, (t - this.last) / 1000) : 0;
        this.last = t;
        const shift = this.speed * dt;
        this.offset += shift;
        // pędy jadą razem ze splotem (w lewo) i znikają za krawędzią
        this.sprouts.forEach(p => { p.x -= shift; p.age += dt; });
        this.sprouts = this.sprouts.filter(p => p.age < p.life && p.x > -20);
        this.nextSprout -= dt;
        if (this.nextSprout <= 0) {
            if (this.sprouts.length < Math.max(2, Math.round(this.w / 220))) this.addSprout();
            this.nextSprout = 1.2 + Math.random() * 2.8;
        }
        this.draw();
    };

    Vine.prototype.draw = function () {
        this.ctx.clearRect(0, 0, this.w, this.h);
        this.sprouts.forEach(p => this.drawSprout(p));
        this.drawStrands();
    };

    Vine.prototype.drawStatic = function () {
        this.sprouts = [];
        for (let i = 0; i < Math.round(this.w / 260); i++) {
            this.addSprout();
            const p = this.sprouts[this.sprouts.length - 1];
            p.age = 3; p.life = 1e9;
        }
        this.draw();
    };

    function init() {
        const vines = Array.from(document.querySelectorAll('.kw-vine')).map(el => new Vine(el));
        if (!vines.length || reduceMotion) return;
        let lastDraw = 0;
        function loop(t) {
            if (t - lastDraw >= 33) {                             // ~30 klatek/s wystarczy
                vines.forEach(v => v.frame(t));
                lastDraw = t;
            }
            requestAnimationFrame(loop);
        }
        requestAnimationFrame(loop);                              // przeglądarka sama wstrzymuje w ukrytej karcie
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
