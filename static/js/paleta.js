/* =====================================================================
   PALETA BARW ZIELARZA – interfejs (templates/paleta.html)
   Dane: static/json/paleta.json (ręczne) + static/json/paleta_siedziba.json (uzupełnienia
   z Siedziby Kwiatownika, opcjonalne). Model koloru: static/js/paleta_model.js.
   Wszystko liczy się w przeglądarce – strona jest statyczna (freeze.py).
   ===================================================================== */
(function () {
    'use strict';
    const M = window.KwPaletaModel;
    const root = document.getElementById('paleta');
    if (!root || !M) return;

    const LS_KEY = 'kw_paleta_v1';
    const $ = (sel, el) => (el || document).querySelector(sel);
    const $$ = (sel, el) => Array.from((el || document).querySelectorAll(sel));
    const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const slug = s => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/ł/g, 'l');
    const godz = h => String(h).replace('.', ',') + ' h';
    const safeUrl = u => (typeof u === 'string' && /^https?:\/\//i.test(u)) ? u : null;
    const PH_NAZWY = { kwasne: 'kwaśne (ocet)', obojetne: 'obojętne', zasadowe: 'zasadowe (soda)' };
    const RODZAJ = { pasta: 'pasta', olej: 'olej (macerat)', plukanka: 'płukanka' };
    const PEWNOSC = { potwierdzone: ['potwierdzone źródłami', 'ok'], tradycyjne: ['tradycja ludowa', 'trad'], niepewne: ['niepewne', 'nie'] };

    let D = null, Z = {}, profil = null, planMix = { kroki: [{ godziny: 3.5, skladniki: [] }], plukanki: [] };
    let wybranyCel = null, aktualne = null;
    let krokCel = 0;                          // do którego etapu pasty trafiają nowe zioła z listy i atlasu   // aktualne = {plan, zrodlo:'cel'|'mix', dE?, cel?}

    // ------------------------------------------------------------------ dane
    async function wczytaj() {
        const r = await fetch(root.dataset.json, { cache: 'no-cache' });
        D = await r.json();
        try {
            const s = await fetch(root.dataset.jsonSiedziba, { cache: 'no-cache' });
            if (s.ok) scalSiedzibe(await s.json());
        } catch (e) { /* brak pliku z Siedziby – normalne */ }
        Z = Object.fromEntries(D.ziola.map(z => [z.id, z]));
    }

    // Siedziba tylko DOPISUJE: nowe zioła (z kompletem pól modelu) i uwagi/ostrzeżenia/źródła do istniejących.
    function scalSiedzibe(S) {
        if (!S || typeof S !== 'object') return;
        const byId = Object.fromEntries(D.ziola.map(z => [z.id, z]));
        const uniq = (a, b) => Array.from(new Set([...(a || []), ...(b || [])].filter(x => typeof x === 'string' && x.trim())));
        Object.entries(S.uzupelnienia || {}).forEach(([id, u]) => {
            const z = byId[id];
            if (!z || !u) return;
            z.uwagi = uniq(z.uwagi, u.uwagi);
            z.ostrzezenia = uniq(z.ostrzezenia, u.ostrzezenia);
            z.zrodla_siedziba = (z.zrodla_siedziba || []).concat((u.zrodla || []).filter(x => x && safeUrl(x.url)));
            if (u.proporcje_ze_zrodel) z.proporcje_ze_zrodel = u.proporcje_ze_zrodel;
            z._siedziba = u.zaktualizowano || true;
        });
        (S.nowe_ziola || []).forEach(n => {
            if (!n || !n.id || byId[n.id] || !/^#[0-9a-f]{6}$/i.test(n.kolor || '') || !(n.sila > 0 && n.sila <= 1.5)
                || !RODZAJ[n.rodzaj] || !D.grupy.some(g => g.klucz === n.grupa)) return;
            n.zrodla = []; n.zrodla_siedziba = (n.zrodla_siedziba || n.zrodla_ext || []).filter(x => x && safeUrl(x.url));
            n.uwagi = n.uwagi || []; n.ostrzezenia = n.ostrzezenia || [];
            n.pewnosc = PEWNOSC[n.pewnosc] ? n.pewnosc : 'niepewne';
            n.trwalosc = ['trwała', 'półtrwała', 'zmywalna'].includes(n.trwalosc) ? n.trwalosc : 'zmywalna';
            n._siedziba = true;
            D.ziola.push(n); byId[n.id] = n;
        });
    }

    // ------------------------------------------------------------------ profil
    const DOMYSLNY = { poziom: 6, siwizna: 0, grubosc: 'srednie', porowatosc: 'srednia', dlugosc: 'ramiona', chemia: {}, produkty: {} };
    function wczytajProfil() {
        try { const p = JSON.parse(localStorage.getItem(LS_KEY) || 'null'); if (p && p.poziom) return Object.assign({}, DOMYSLNY, p); } catch (e) { }
        return JSON.parse(JSON.stringify(DOMYSLNY));
    }
    function zapiszProfil() { try { localStorage.setItem(LS_KEY, JSON.stringify(profil)); } catch (e) { } }

    function zbudujProfil() {
        const form = $('#palProfilForm');
        const lv = $('#palLevels');
        lv.innerHTML = D.poziomy.map(p => `<button type="button" role="radio" aria-checked="false" data-lv="${p.poziom}" title="${p.poziom} – ${esc(p.nazwa)}" style="--c:${p.hex}"><span>${p.poziom}</span></button>`).join('');
        $('#palDlugosc').innerHTML = D.dlugosci.map(d => `<option value="${d.klucz}">${esc(d.nazwa)}</option>`).join('');

        // stan → formularz
        form.poziom.value = profil.poziom; form.siwizna.value = profil.siwizna; form.dlugosc.value = profil.dlugosc;
        $$('input[name="grubosc"]', form).forEach(r => r.checked = r.value === profil.grubosc);
        $$('input[name="porowatosc"]', form).forEach(r => r.checked = r.value === profil.porowatosc);
        $$('input[type="checkbox"][name*="."]', form).forEach(cb => { const [g, k] = cb.name.split('.'); cb.checked = !!(profil[g] && profil[g][k]); });

        lv.addEventListener('click', e => { const b = e.target.closest('[data-lv]'); if (b) { form.poziom.value = b.dataset.lv; zmienProfil(); } });
        lv.addEventListener('keydown', e => {
            if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
            e.preventDefault();
            form.poziom.value = Math.min(10, Math.max(1, Number(form.poziom.value) + (e.key === 'ArrowRight' ? 1 : -1)));
            zmienProfil(); const b = $(`[data-lv="${form.poziom.value}"]`, lv); if (b) b.focus();
        });
        form.addEventListener('input', zmienProfil);
        form.addEventListener('change', zmienProfil);
        odswiezProfilUI();
    }

    function zmienProfil() {
        const f = $('#palProfilForm');
        profil.poziom = Number(f.poziom.value);
        profil.siwizna = Number(f.siwizna.value);
        profil.dlugosc = f.dlugosc.value;
        profil.grubosc = ($('input[name="grubosc"]:checked', f) || {}).value || 'srednie';
        profil.porowatosc = ($('input[name="porowatosc"]:checked', f) || {}).value || 'srednia';
        profil.chemia = {}; profil.produkty = {};
        $$('input[type="checkbox"][name*="."]', f).forEach(cb => { const [g, k] = cb.name.split('.'); if (cb.checked) profil[g][k] = true; });
        zapiszProfil();
        odswiezProfilUI();
        planujPrzeliczenie();
    }

    function odswiezProfilUI() {
        const p = D.poziomy.find(x => x.poziom === profil.poziom);
        $('#palPoziomOut').textContent = `${p.poziom} – ${p.nazwa}`;
        $('#palSiwiznaOut').textContent = profil.siwizna + '%';
        $$('#palLevels [data-lv]').forEach(b => {
            const on = Number(b.dataset.lv) === profil.poziom;
            b.classList.toggle('on', on); b.setAttribute('aria-checked', on); b.tabIndex = on ? 0 : -1;
        });
        const przed = M.przewiduj(profil, { kroki: [], plukanki: [] }, Z, D).przed;
        const [g1, g2] = M.gramy(profil, D);
        $('#palProfilSum').innerHTML = `${pasma(przed.pig, przed.siwy, profil.siwizna / 100, 'Twój włos teraz', 'sm')}
            <div><strong>Twój włos teraz</strong><br><span class="pal-muted">Proszku na jedno nałożenie: ok. ${g1}–${g2} g.</span>
            <br><span class="pal-muted small">Profil zapisuje się tylko w tej przeglądarce.</span></div>`;
        const ryzyko = profil.produkty.henna_zlozona || profil.produkty.farby_progresywne || profil.produkty.czarna_henna || profil.produkty.uczulenie_ppd;
        $('#palProfilSum').classList.toggle('pal-risk', !!ryzyko);
    }

    // ------------------------------------------------------------------ rysunek pasm
    let pasmoNr = 0;
    function pasma(pigHex, siwyHex, g, label, size) {
        const N = 26, W = 160, H = 104, id = 'pg' + (++pasmoNr);
        let paths = '';
        for (let i = 0; i < N; i++) {
            // rozkład siwych równomierny, ale „poszarpany” (deterministyczny)
            const siwe = ((i * 0.618 + 0.13) % 1) < g;
            const x = 4 + i * (W - 8) / (N - 1);
            const a = 2.5 + (i % 3);
            const d = `M${x.toFixed(1)} -2 C ${(x + a).toFixed(1)} ${H * 0.3} ${(x - a).toFixed(1)} ${H * 0.6} ${(x + a * 0.6).toFixed(1)} ${H + 2}`;
            paths += `<path d="${d}" stroke="${siwe ? siwyHex : pigHex}" stroke-width="${(W / N + 1.6).toFixed(1)}" fill="none" stroke-linecap="round"/>`;
        }
        return `<svg class="pal-strands ${size || ''}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(label)}">
            <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset=".32" stop-color="#fff" stop-opacity=".28"/>
              <stop offset=".42" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".18"/></linearGradient>
              <clipPath id="${id}c"><rect width="${W}" height="${H}" rx="10"/></clipPath></defs>
            <g clip-path="url(#${id}c)">${paths}<rect width="${W}" height="${H}" fill="url(#${id})"/></g></svg>`;
    }

    // ------------------------------------------------------------------ koło barw
    function arc(cx, cy, r1, r2, a0, a1) {
        const p = (r, a) => [cx + r * Math.cos(a), cy + r * Math.sin(a)].map(v => v.toFixed(2)).join(' ');
        const big = a1 - a0 > Math.PI ? 1 : 0;
        return `M ${p(r2, a0)} A ${r2} ${r2} 0 ${big} 1 ${p(r2, a1)} L ${p(r1, a1)} A ${r1} ${r1} 0 ${big} 0 ${p(r1, a0)} Z`;
    }
    function zbudujKolo() {
        const svg = $('#palWheel');
        const cx = 160, cy = 160, R2 = 152, R1 = 96, gap = 0.035;
        const kolejnosc = ['rudosci', 'brazy', 'fiolety', 'blondy'];  // jak na grafice: 1 lewo-góra, 2 prawo-góra, 4 lewo-dół, 3 prawo-dół
        const start = { rudosci: Math.PI, brazy: -Math.PI / 2, blondy: 0, fiolety: Math.PI / 2 };
        let html = '';
        kolejnosc.forEach(gk => {
            const cele = D.cele.filter(c => c.grupa === gk);
            const a0 = start[gk] + gap, span = Math.PI / 2 - 2 * gap, step = span / cele.length;
            cele.forEach((c, i) => {
                const s = a0 + i * step + 0.006, e = a0 + (i + 1) * step - 0.006;
                const mid = (s + e) / 2;
                html += `<g class="pal-seg" tabindex="0" role="button" data-cel="${c.id}" aria-label="${esc(c.nazwa)}" style="--dx:${(Math.cos(mid) * 6).toFixed(1)}px;--dy:${(Math.sin(mid) * 6).toFixed(1)}px">
                    <title>${esc(c.nazwa)}</title><path d="${arc(cx, cy, R1, R2, s, e)}" fill="${c.hex}"/></g>`;
            });
            const g = D.grupy.find(x => x.klucz === gk);
            const am = start[gk] + Math.PI / 4;
            html += `<text class="pal-qnum" x="${(cx + (R1 - 16) * Math.cos(am)).toFixed(1)}" y="${(cy + (R1 - 16) * Math.sin(am) + 5).toFixed(1)}" text-anchor="middle" aria-hidden="true">${g.nr}</text>`;
        });
        html += `<g id="palCenter" aria-hidden="true"><circle cx="${cx}" cy="${cy}" r="${R1 - 30}" class="pal-center-ring"/>
            <path id="palCenterL" d="M ${cx} ${cy - 62} A 62 62 0 0 0 ${cx} ${cy + 62} Z"/><path id="palCenterR" d="M ${cx} ${cy - 62} A 62 62 0 0 1 ${cx} ${cy + 62} Z"/>
            <text x="${cx - 31}" y="${cy + 4}" text-anchor="middle" class="pal-center-t" id="palCenterTL">teraz</text>
            <text x="${cx + 31}" y="${cy + 4}" text-anchor="middle" class="pal-center-t" id="palCenterTR">cel</text></g>`;
        svg.innerHTML = html;
        $('#palLegend').innerHTML = D.grupy.slice().sort((a, b) => a.nr - b.nr)
            .map(g => `<li><span class="pal-dot" style="background:${g.kolor}"></span><b>${g.nr}.</b> ${esc(g.nazwa)}</li>`).join('');

        svg.addEventListener('click', e => { const s = e.target.closest('.pal-seg'); if (s) wybierzCel(s.dataset.cel); });
        svg.addEventListener('keydown', e => {
            const s = e.target.closest('.pal-seg'); if (!s) return;
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); wybierzCel(s.dataset.cel); }
        });
        odswiezSrodek();
    }
    function odswiezSrodek() {
        const przed = M.przewiduj(profil, { kroki: [], plukanki: [] }, Z, D).przed;
        const L = $('#palCenterL'), R = $('#palCenterR');
        if (!L) return;
        L.setAttribute('fill', przed.srednio);
        const c = wybranyCel && D.cele.find(x => x.id === wybranyCel);
        R.setAttribute('fill', c ? c.hex : przed.srednio);
        $('#palCenterTR').textContent = c ? 'cel' : '?';
        const jasny = hex => M.labFromHex(hex)[0] > 55;
        $('#palCenterTL').setAttribute('fill', jasny(przed.srednio) ? '#2b2b2b' : '#fff');
        $('#palCenterTR').setAttribute('fill', jasny(c ? c.hex : przed.srednio) ? '#2b2b2b' : '#fff');
        $$('.pal-seg').forEach(s => s.classList.toggle('on', s.dataset.cel === wybranyCel));
    }

    // ------------------------------------------------------------------ dobór
    const waski = () => window.matchMedia('(max-width: 900px)').matches;
    const ruch = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
    // przewinięcie tak, żeby element nie chował się pod przyklejonym nagłówkiem strony (menu + almanach + ciekawostki)
    function przewinDo(el) {
        const h = document.querySelector('.main-header');
        const off = (h ? h.getBoundingClientRect().bottom : 110) + 10;
        window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - off, behavior: ruch() });
    }
    function wybierzCel(id) {
        wybranyCel = id;
        odswiezSrodek();
        przeliczDobor(true);
    }
    function opisPlanu(plan) {
        const kroki = plan.kroki.filter(k => k.skladniki.length);
        const parts = kroki.map((k, i) => {
            const suma = k.skladniki.reduce((s, x) => s + x.czesci, 0);
            const t = k.skladniki.map(s => `${esc(Z[s.id].nazwa)} ${Math.round(s.czesci / suma * 100)}%${s.ph && Z[s.id].ph ? ' <small>(' + esc(PH_NAZWY[s.ph]) + ')</small>' : ''}`).join(' · ');
            return (kroki.length > 1 ? `<b>Etap ${i + 1}:</b> ` : '') + t;
        });
        if (plan.plukanki.length) parts.push('<b>Płukanki:</b> ' + plan.plukanki.map(p => `${esc(Z[p.id].nazwa)} ×${p.razy}${p.ph && Z[p.id].ph ? ' <small>(' + esc(PH_NAZWY[p.ph]) + ')</small>' : ''}`).join(' · '));
        return parts.join('<br>');
    }
    function metoda(plan) {
        const n = plan.kroki.filter(k => k.skladniki.length).length;
        if (!n) return 'płukanki';
        return n > 1 ? '2 etapy' : '1 etap';
    }

    function przeliczDobor(przewin) {
        const box = $('#palPropozycje');
        const tgt = $('#palTarget');
        const c = wybranyCel && D.cele.find(x => x.id === wybranyCel);
        if (!c) return;
        tgt.innerHTML = `<div class="pal-target-row"><span class="pal-swatch" style="background:${c.hex}"></span>
            <div><strong>${esc(c.nazwa)}</strong><br><span class="pal-muted">${esc(D.grupy.find(g => g.klucz === c.grupa).nazwa)}</span></div></div>`;
        box.innerHTML = '<p class="pal-muted"><span class="spinner-border spinner-border-sm" aria-hidden="true"></span> Liczę mieszanki…</p>';
        setTimeout(() => {
            const r = M.dobierz(profil, c.hex, Z, D, {
                tylkoRodzime: $('#palOptRodzime').checked, bezTrwalych: $('#palOptBezTrwalych').checked, tylkoPlukanki: $('#palOptPlukanki').checked
            });
            let html = '';
            if (r.jasniejszyNizWlos)
                html += `<div class="pal-alert"><i class="bi bi-exclamation-circle" aria-hidden="true"></i> Ten odcień jest jaśniejszy niż Twój włos. Zioła nie rozjaśniają, więc pokazuję najbliższe, co da się osiągnąć – raczej jako refleks.</div>`;
            if (!r.wyniki.length) html += '<p class="pal-muted">Brak ziół spełniających wybrane ograniczenia.</p>';
            r.wyniki.forEach((w, i) => {
                const q = M.jakosc(w.dE), trw = M.receptura(profil, w.plan, Z, D).trwalosc;
                html += `<article class="pal-prop" data-i="${i}">
                    <div class="pal-prop-sw">${pasma(w.wynik.po.pig, w.wynik.po.siwy, w.wynik.siwizna, 'Przewidywany kolor', 'sm')}</div>
                    <div class="pal-prop-body">
                        <div class="pal-prop-head"><span class="pal-q ${q.klasa}">${q.tekst}</span>
                          <span class="pal-tag">${metoda(w.plan)}</span><span class="pal-tag t-${slug(trw)}">${trw}</span>
                          ${w.lagodna ? '<span class="pal-tag t-zmywalna">łagodna alternatywa</span>' : ''}</div>
                        <div class="pal-prop-mix">${opisPlanu(w.plan)}</div>
                        <div class="pal-prop-btns"><button type="button" class="btn pal-btn" data-pokaz="${i}">Pokaż recepturę</button>
                        <button type="button" class="btn pal-btn-ghost" data-edytuj="${i}">Zmień w mieszalniku</button></div>
                    </div></article>`;
            });
            box.innerHTML = html;
            box._wyniki = r.wyniki;
            if (r.wyniki.length) pokaz({ plan: r.wyniki[0].plan, zrodlo: 'cel', dE: r.wyniki[0].dE, cel: c }, false);
            // na telefonie propozycje są pod kołem, poza ekranem - pokaż je po kliknięciu odcienia
            if (przewin && waski()) przewinDo(tgt);
        }, 20);
    }

    // ------------------------------------------------------------------ mieszalnik
    function zbudujPicker() {
        const box = $('#palPicker');
        box.innerHTML = D.grupy.slice().sort((a, b) => a.nr - b.nr).map(g => {
            const zz = D.ziola.filter(z => z.grupa === g.klucz);
            return `<div class="pal-pick-group"><h3><span class="pal-dot" style="background:${g.kolor}"></span>${esc(g.nazwa)}</h3>
                <div class="pal-pick-list">${zz.map(z => `<button type="button" class="pal-pick" data-add="${z.id}" title="${esc(z.lat)} – ${esc(RODZAJ[z.rodzaj])}">
                    <span class="pal-dot" style="background:${z.kolor}"></span>${esc(z.nazwa)}<small>${z.rodzaj === 'plukanka' ? 'płuk.' : z.rodzaj === 'olej' ? 'olej' : ''}</small></button>`).join('')}</div></div>`;
        }).join('');
        box.addEventListener('click', e => {
            const b = e.target.closest('[data-add]'); if (!b) return;
            dodajDoMiksera(Z[b.dataset.add]);
            rysujMikser(); przeliczMix();
        });
    }

    function dodajDoMiksera(z) {
        if (z.rodzaj === 'plukanka') {
            if (!planMix.plukanki.some(p => p.id === z.id)) planMix.plukanki.push({ id: z.id, razy: 4, ph: z.ph ? 'obojetne' : undefined });
            return;
        }
        krokCel = Math.min(krokCel, planMix.kroki.length - 1);
        const krok = planMix.kroki[krokCel];
        if (!krok.skladniki.some(s => s.id === z.id)) krok.skladniki.push({ id: z.id, czesci: 5, ph: z.ph ? 'obojetne' : undefined });
    }

    function wierszZiola(z, wartosc, min, max, etyk, attrs, ph) {
        return `<div class="pal-mrow" ${attrs}>
            <span class="pal-dot" style="background:${z.kolor}"></span>
            <span class="pal-mname">${esc(z.nazwa)}</span>
            <input type="range" min="${min}" max="${max}" step="1" value="${wartosc}" class="pal-range pal-mval" aria-label="${esc(etyk + ' – ' + z.nazwa)}">
            <output class="pal-mout">${wartosc}</output>
            ${z.ph ? `<select class="form-select form-select-sm pal-mph" aria-label="pH – ${esc(z.nazwa)}">${M.PH.map(p => `<option value="${p}"${p === (ph || 'obojetne') ? ' selected' : ''}>${PH_NAZWY[p]}</option>`).join('')}</select>` : ''}
            <button type="button" class="pal-mdel" aria-label="Usuń ${esc(z.nazwa)}">×</button></div>`;
    }

    function rysujMikser() {
        const box = $('#palMixer');
        let html = '';
        krokCel = Math.max(0, Math.min(krokCel, planMix.kroki.length - 1));
        const wiele = planMix.kroki.length > 1;
        planMix.kroki.forEach((k, ki) => {
            const suma = k.skladniki.reduce((s, x) => s + x.czesci, 0);
            const tu = ki === krokCel;
            html += `<div class="pal-step${wiele && tu ? ' cel' : ''}" data-krok="${ki}"><div class="pal-step-h"><strong>${wiele ? 'Etap ' + (ki + 1) + ' – pasta' : 'Pasta'}</strong>
                ${wiele ? `<button type="button" class="pal-stepsel${tu ? ' on' : ''}" data-krok-cel="${ki}" aria-pressed="${tu}">${tu ? '<i class="bi bi-check2" aria-hidden="true"></i> tu dodajesz zioła' : 'dodawaj tutaj'}</button>` : ''}
                <label class="pal-time">czas: <input type="range" min="1" max="6" step="0.5" value="${k.godziny}" class="pal-range pal-godz" aria-label="Czas nakładania, etap ${ki + 1}"> <output>${godz(k.godziny)}</output></label>
                ${ki > 0 ? '<button type="button" class="pal-mdel pal-delstep" aria-label="Usuń etap">×</button>' : ''}</div>`;
            html += k.skladniki.length ? k.skladniki.map((s, si) => wierszZiola(Z[s.id], s.czesci, 1, 10, 'Części', `data-k="${ki}" data-s="${si}"`, s.ph)
                .replace('</output>', `</output><span class="pal-pct">${suma ? Math.round(s.czesci / suma * 100) : 0}%</span>`)).join('')
                : `<p class="pal-muted small">${tu ? 'Kliknij zioło typu pasta lub olej na liście.' : 'Pusty etap – kliknij „dodawaj tutaj”, a potem zioło z listy.'}</p>`;
            html += '</div>';
        });
        if (planMix.kroki.length < 2)
            html += `<button type="button" class="btn pal-btn-ghost pal-addstep"><i class="bi bi-plus-lg" aria-hidden="true"></i> Dodaj etap 2 (np. indygo po hennie)</button>`;
        html += `<div class="pal-step"><div class="pal-step-h"><strong>Płukanki</strong> <small class="pal-muted">liczba płukań</small></div>`;
        html += planMix.plukanki.length ? planMix.plukanki.map((p, pi) => wierszZiola(Z[p.id], p.razy, 1, 12, 'Liczba płukań', `data-p="${pi}"`, p.ph)).join('')
            : '<p class="pal-muted small">Dodaj zioło typu płukanka.</p>';
        html += `</div><button type="button" class="btn pal-btn-ghost pal-clear"><i class="bi bi-eraser" aria-hidden="true"></i> Wyczyść</button>`;
        box.innerHTML = html;
        const hint = $('#palPickTarget');
        if (hint) hint.innerHTML = wiele
            ? `Pasty i oleje trafią do: <b>Etapu ${krokCel + 1}</b> · płukanki – do płukanek`
            : 'Pasty i oleje trafią do pasty, płukanki – do płukanek';
        const wPlanie = new Set([...planMix.kroki.flatMap(k => k.skladniki.map(s => s.id)), ...planMix.plukanki.map(p => p.id)]);
        $$('#palPicker [data-add]').forEach(b => { const on = wPlanie.has(b.dataset.add); b.classList.toggle('on', on); b.setAttribute('aria-pressed', on); });
    }

    function zbudujMikser() {
        const box = $('#palMixer');
        box.addEventListener('input', e => {
            const row = e.target.closest('.pal-mrow');
            if (e.target.classList.contains('pal-godz')) {
                const ki = Number(e.target.closest('.pal-step').dataset.krok);
                planMix.kroki[ki].godziny = Number(e.target.value);
                e.target.nextElementSibling.textContent = godz(e.target.value);
            } else if (row && e.target.classList.contains('pal-mval')) {
                const v = Number(e.target.value);
                row.querySelector('.pal-mout').textContent = v;
                if (row.dataset.p != null) planMix.plukanki[row.dataset.p].razy = v;
                else {
                    const k = planMix.kroki[row.dataset.k];
                    k.skladniki[row.dataset.s].czesci = v;
                    const suma = k.skladniki.reduce((s, x) => s + x.czesci, 0);
                    $$('.pal-mrow', row.parentElement).forEach((r, i) => { const pc = r.querySelector('.pal-pct'); if (pc) pc.textContent = Math.round(k.skladniki[i].czesci / suma * 100) + '%'; });
                }
            }
            przeliczMix();
        });
        box.addEventListener('change', e => {
            const row = e.target.closest('.pal-mrow');
            if (row && e.target.classList.contains('pal-mph')) {
                if (row.dataset.p != null) planMix.plukanki[row.dataset.p].ph = e.target.value;
                else planMix.kroki[row.dataset.k].skladniki[row.dataset.s].ph = e.target.value;
                przeliczMix();
            }
        });
        box.addEventListener('click', e => {
            const row = e.target.closest('.pal-mrow');
            if (e.target.closest('.pal-mdel') && row) {
                if (row.dataset.p != null) planMix.plukanki.splice(row.dataset.p, 1);
                else planMix.kroki[row.dataset.k].skladniki.splice(row.dataset.s, 1);
            } else if (e.target.closest('[data-krok-cel]')) {
                krokCel = Number(e.target.closest('[data-krok-cel]').dataset.krokCel);
            } else if (e.target.closest('.pal-delstep')) {
                planMix.kroki.splice(Number(e.target.closest('.pal-step').dataset.krok), 1);
                krokCel = Math.min(krokCel, planMix.kroki.length - 1);
            } else if (e.target.closest('.pal-addstep')) {
                planMix.kroki.push({ godziny: 3.5, skladniki: [] });
                krokCel = planMix.kroki.length - 1;            // nowy etap od razu przyjmuje zioła
            } else if (e.target.closest('.pal-clear')) {
                planMix = { kroki: [{ godziny: 3.5, skladniki: [] }], plukanki: [] };
                krokCel = 0;
            } else return;
            rysujMikser(); przeliczMix();
        });
        rysujMikser();
    }

    function planZMiksera() {
        return { kroki: planMix.kroki.filter(k => k.skladniki.length).map(k => ({ godziny: k.godziny, skladniki: k.skladniki.map(s => Object.assign({}, s)) })),
                 plukanki: planMix.plukanki.map(p => Object.assign({}, p)) };
    }
    function przeliczMix() {
        const plan = planZMiksera();
        const prev = $('#palMixPreview');
        const bar = $('#palMixBar');
        if (!plan.kroki.length && !plan.plukanki.length) { prev.innerHTML = ''; bar.innerHTML = ''; pasekMiksera(); return; }
        const w = M.przewiduj(profil, plan, Z, D);
        prev.innerHTML = `<div class="pal-ba">
            <figure>${pasma(w.przed.pig, w.przed.siwy, w.siwizna, 'Przed')}<figcaption>przed</figcaption></figure>
            <i class="bi bi-arrow-right" aria-hidden="true"></i>
            <figure>${pasma(w.po.pig, w.po.siwy, w.siwizna, 'Po')}<figcaption>po</figcaption></figure></div>`;
        const n = plan.kroki.reduce((a, k) => a + k.skladniki.length, 0) + plan.plukanki.length;
        bar.innerHTML = `${pasma(w.przed.pig, w.przed.siwy, w.siwizna, 'Przed', 'xs')}<i class="bi bi-arrow-right" aria-hidden="true"></i>${pasma(w.po.pig, w.po.siwy, w.siwizna, 'Po', 'xs')}
            <span class="pal-mixbar-t">${n} ${n === 1 ? 'zioło' : (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14)) ? 'zioła' : 'ziół'} · ${metoda(plan)}</span>
            <button type="button" class="pal-mixbar-b" data-do-mieszanki>mieszanka <i class="bi bi-arrow-up" aria-hidden="true"></i></button>`;
        pasekMiksera();
        pokaz({ plan, zrodlo: 'mix' }, false);
    }

    // Pasek u dołu ekranu (telefon): podgląd „przed → po”, gdy przewijasz listę ziół i duży podgląd jest poza ekranem.
    const widoczne = { panel: false, podglad: false };
    function pasekMiksera() {
        const bar = $('#palMixBar');
        const pokazac = waski() && !$('#palPanelMix').hidden && widoczne.panel && !widoczne.podglad && bar.innerHTML.trim() !== '';
        bar.hidden = !pokazac;
    }
    function obserwujMikser() {
        if (!('IntersectionObserver' in window)) return;
        const io = new IntersectionObserver(entries => {
            entries.forEach(en => { widoczne[en.target.id === 'palPanelMix' ? 'panel' : 'podglad'] = en.isIntersecting; });
            pasekMiksera();
        }, { rootMargin: '-110px 0px 0px 0px' });   // pod przyklejonym nagłówkiem strony
        io.observe($('#palPanelMix'));
        io.observe($('#palMixPreview'));
        window.addEventListener('resize', pasekMiksera);
        $('#palMixBar').addEventListener('click', e => {
            if (e.target.closest('[data-do-mieszanki]')) $('#palMixPreview').scrollIntoView({ behavior: ruch(), block: 'center' });
        });
    }
    function doMiksera(plan) {
        planMix = {
            kroki: plan.kroki.length ? plan.kroki.map(k => ({ godziny: k.godziny || 3.5, skladniki: k.skladniki.map(s => Object.assign({}, s)) })) : [{ godziny: 3.5, skladniki: [] }],
            plukanki: plan.plukanki.map(p => Object.assign({}, p))
        };
        krokCel = 0;
        rysujMikser();
        przelaczZakladke('mix');
        przeliczMix();
    }

    // ------------------------------------------------------------------ receptura
    function linkZiola(z) {
        const nazwa = `<span data-wiki-term="${esc(z.wiki || z.nazwa)}">${esc(z.nazwa)}</span> <i class="pal-lat">${esc(z.lat)}</i>`;
        return z.karta ? `${nazwa} <a class="pal-karta" href="${esc(root.dataset.plantUrl.replace('__ID__', encodeURIComponent(z.karta)))}">karta rośliny →</a>` : nazwa;
    }
    function pokaz(stan, przewin) {
        aktualne = stan;
        const { plan } = stan;
        const box = $('#palReceptura');
        if (!plan || (!plan.kroki.length && !plan.plukanki.length)) { box.innerHTML = '<p class="pal-muted">Brak ziół w mieszance.</p>'; return; }
        const w = M.przewiduj(profil, plan, Z, D);
        const R = M.receptura(profil, plan, Z, D);
        const dl = D.dlugosci.find(d => d.klucz === profil.dlugosc);
        let html = `<div class="pal-rec-top">
            <figure>${pasma(w.przed.pig, w.przed.siwy, w.siwizna, 'Przed')}<figcaption>przed</figcaption></figure>
            <i class="bi bi-arrow-right pal-rec-arrow" aria-hidden="true"></i>
            <figure>${pasma(w.po.pig, w.po.siwy, w.siwizna, 'Przewidywany kolor')}<figcaption>przewidywany kolor</figcaption></figure>
            ${stan.cel ? `<figure class="pal-rec-cel"><span class="pal-swatch lg" style="background:${stan.cel.hex}"></span><figcaption>cel: ${esc(stan.cel.nazwa)}<br><span class="pal-q ${M.jakosc(stan.dE).klasa}">${M.jakosc(stan.dE).tekst}</span></figcaption></figure>` : ''}
            </div>`;
        html += `<p class="pal-rec-meta"><span class="pal-tag">${metoda(plan)}</span> <span class="pal-tag t-${slug(R.trwalosc)}">${R.trwalosc}</span>
            ${R.kroki.length ? `<span>${iloscProszku(R)} <span class="pal-muted">(${esc(dl.nazwa)}, włosy ${profil.grubosc === 'srednie' ? 'średnie' : profil.grubosc})</span></span>` : ''}</p>`;

        R.kroki.forEach((k, i) => {
            html += `<div class="pal-rec-step"><h3>${R.kroki.length > 1 ? `Etap ${i + 1}` : 'Pasta'} <small>– nakładanie ok. ${godz(k.godziny)}</small></h3>
                <div class="pal-table-wrap"><table class="pal-table"><thead><tr><th>Zioło</th><th>Udział</th><th>Ilość</th></tr></thead><tbody>
                ${k.skladniki.map(s => `<tr><td><span class="pal-dot" style="background:${s.z.kolor}"></span>${linkZiola(s.z)}${s.ph && s.z.ph ? `<br><small>pH: ${esc(PH_NAZWY[s.ph])}</small>` : ''}</td><td>${s.procent}%</td><td>${s.z.rodzaj === 'olej' ? `${s.gramy[0]}–${s.gramy[1]} g korzenia<br><small>w oleju (macerat)</small>` : `${s.gramy[0]}–${s.gramy[1]} g`}</td></tr>`).join('')}
                </tbody></table></div><ol class="pal-howto">
                ${k.skladniki.map(s => `<li><b>${esc(s.z.nazwa)}:</b> ${esc(s.z.przygotowanie)}</li>`).join('')}
                <li>Nałóż pastę na czyste, suche lub lekko wilgotne włosy, od nasady, pasmo po paśmie. Owiń folią i trzymaj ok. ${godz(k.godziny)}, potem spłucz samą wodą lub odżywką (bez szamponu przez 1–2 dni).</li>
                ${i === 1 ? '<li>Etap 2 nakładaj w ciągu 72 h po etapie 1 – indygo potrzebuje świeżego podkładu z henny.</li>' : ''}
                </ol></div>`;
        });
        if (R.plukanki.length) {
            html += `<div class="pal-rec-step"><h3>Płukanki <small>– po myciu, regularnie</small></h3><ul class="pal-howto">
                ${R.plukanki.map(p => `<li><span class="pal-dot" style="background:${p.z.kolor}"></span>${linkZiola(p.z)}: ${esc(p.z.dawka || p.z.przygotowanie)}. ${esc(p.z.nakladanie || '')}${p.ph && p.z.ph ? `; pH: ${esc(PH_NAZWY[p.ph])}` : ''}. <b>Powtórz ok. ${p.razy}×</b> (po każdym myciu).</li>`).join('')}
                </ul></div>`;
        }
        const ikony = { stop: 'bi-sign-stop', uwaga: 'bi-exclamation-triangle', info: 'bi-info-circle' };
        html += `<div class="pal-warns"><h3>Bezpieczeństwo</h3><ul>${R.ostrzezenia.map(o => `<li class="w-${o.poziom}"><i class="bi ${ikony[o.poziom]}" aria-hidden="true"></i> ${esc(o.tekst)}</li>`).join('')}</ul></div>`;
        html += `<div class="pal-rec-btns"><button type="button" class="btn pal-btn" id="palKopiuj"><i class="bi bi-clipboard" aria-hidden="true"></i> Kopiuj recepturę</button>
            <button type="button" class="btn pal-btn-ghost" id="palLink"><i class="bi bi-link-45deg" aria-hidden="true"></i> Kopiuj link</button>
            <button type="button" class="btn pal-btn-ghost" id="palDrukuj"><i class="bi bi-printer" aria-hidden="true"></i> Drukuj</button>
            ${stan.zrodlo === 'cel' ? '<button type="button" class="btn pal-btn-ghost" id="palDoMix"><i class="bi bi-sliders" aria-hidden="true"></i> Zmień w mieszalniku</button>' : ''}
            <span class="pal-muted small" id="palKopiujInfo" aria-live="polite"></span></div>`;
        box.innerHTML = html;
        if (przewin) przewinDo(document.getElementById('palWynik'));
    }

    function iloscProszku(R, tekst) {
        const [a, b] = R.gramy, n = R.kroki.length;
        const g = (x, y) => tekst ? `${x}–${y} g` : `<strong>${x}–${y} g</strong>`;
        return n > 1 ? `Proszku na każdy etap: ${g(a, b)} (razem ${g(a * n, b * n)})` : `Proszku na jedno nałożenie: ${g(a, b)}`;
    }

    function tekstReceptury() {
        if (!aktualne) return '';
        const R = M.receptura(profil, aktualne.plan, Z, D);
        const L = ['Kwiatownik – Paleta Barw Zielarza', ''];
        if (aktualne.cel) L.push('Cel: ' + aktualne.cel.nazwa);
        L.push('Trwałość: ' + R.trwalosc);
        if (R.kroki.length) L.push(iloscProszku(R, true));
        L.push('');
        R.kroki.forEach((k, i) => {
            L.push((R.kroki.length > 1 ? 'Etap ' + (i + 1) : 'Pasta') + ` (nakładanie ok. ${godz(k.godziny)}):`);
            k.skladniki.forEach(s => L.push(`- ${s.z.nazwa} (${s.z.lat}): ${s.procent}%, ${s.gramy[0]}–${s.gramy[1]} g${s.ph && s.z.ph ? ', pH ' + PH_NAZWY[s.ph] : ''}`));
            k.skladniki.forEach(s => L.push(`  ${s.z.nazwa}: ${s.z.przygotowanie}`));
            L.push('');
        });
        if (R.plukanki.length) {
            L.push('Płukanki:');
            R.plukanki.forEach(p => L.push(`- ${p.z.nazwa}: ${p.z.dawka || p.z.przygotowanie}; ok. ${p.razy}×`));
            L.push('');
        }
        L.push('Bezpieczeństwo:');
        R.ostrzezenia.forEach(o => L.push('- ' + o.tekst));
        L.push('', location.href.split('#')[0] + '#' + stanDoHash());
        return L.join('\n');
    }
    function stanDoHash() {
        const s = { pr: profil, pl: aktualne && aktualne.plan, c: aktualne && aktualne.cel && aktualne.cel.id };
        return 'r=' + encodeURIComponent(JSON.stringify(s));
    }
    function stanZHash() {
        const m = location.hash.match(/r=([^&]+)/);
        if (!m) return null;
        try { return JSON.parse(decodeURIComponent(m[1])); } catch (e) { return null; }
    }
    function poprawnyPlan(pl) {
        if (!pl || !Array.isArray(pl.kroki) || !Array.isArray(pl.plukanki)) return null;
        const kroki = pl.kroki.slice(0, 2).map(k => ({ godziny: Math.min(6, Math.max(1, Number(k.godziny) || 3.5)),
            skladniki: (k.skladniki || []).filter(s => Z[s.id] && Z[s.id].rodzaj !== 'plukanka').slice(0, 5)
                .map(s => ({ id: s.id, czesci: Math.min(10, Math.max(1, Number(s.czesci) || 5)), ph: M.PH.includes(s.ph) ? s.ph : undefined })) }))
            .filter(k => k.skladniki.length);
        const plukanki = pl.plukanki.filter(p => Z[p.id] && Z[p.id].rodzaj === 'plukanka').slice(0, 5)
            .map(p => ({ id: p.id, razy: Math.min(12, Math.max(1, Number(p.razy) || 4)), ph: M.PH.includes(p.ph) ? p.ph : undefined }));
        return { kroki, plukanki };
    }
    async function kopiuj(text, info) {
        try { await navigator.clipboard.writeText(text); info.textContent = 'Skopiowano.'; }
        catch (e) {
            const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
            try { document.execCommand('copy'); info.textContent = 'Skopiowano.'; } catch (e2) { info.textContent = 'Nie udało się skopiować.'; }
            ta.remove();
        }
        setTimeout(() => { info.textContent = ''; }, 2500);
    }

    // ------------------------------------------------------------------ atlas
    function zbudujAtlas() {
        const f = $('#palAtlasFilter');
        f.innerHTML = `<button type="button" class="pal-fchip on" data-g="">wszystkie</button>` +
            D.grupy.slice().sort((a, b) => a.nr - b.nr).map(g => `<button type="button" class="pal-fchip" data-g="${g.klucz}"><span class="pal-dot" style="background:${g.kolor}"></span>${esc(g.nazwa)}</button>`).join('') +
            `<button type="button" class="pal-fchip" data-g="rodzime">🌿 rosną w Polsce</button>`;
        f.addEventListener('click', e => {
            const b = e.target.closest('[data-g]'); if (!b) return;
            $$('.pal-fchip', f).forEach(x => x.classList.toggle('on', x === b));
            rysujAtlas(b.dataset.g);
        });
        rysujAtlas('');
    }
    function rysujAtlas(filtr) {
        const pSiwy = { poziom: 10, siwizna: 100, grubosc: 'srednie', porowatosc: 'srednia', dlugosc: 'ramiona', chemia: {}, produkty: {} };
        const pBlond = Object.assign({}, pSiwy, { poziom: 6, siwizna: 0 });
        const zrodlo = nr => D.zrodla.find(z => z.nr === nr);
        const zz = D.ziola.filter(z => !filtr || (filtr === 'rodzime' ? z.rodzime : z.grupa === filtr));
        $('#palAtlas').innerHTML = zz.map(z => {
            const plan = z.rodzaj === 'plukanka' ? { kroki: [], plukanki: [{ id: z.id, razy: 6 }] } : { kroki: [{ godziny: 3.5, skladniki: [{ id: z.id, czesci: 1 }] }], plukanki: [] };
            const a = M.przewiduj(pSiwy, plan, Z, D).po.siwy, b = M.przewiduj(pBlond, plan, Z, D).po.pig;
            const pw = PEWNOSC[z.pewnosc] || PEWNOSC.niepewne;
            const zr = (z.zrodla || []).map(zrodlo).filter(Boolean).map(s => safeUrl(s.url)
                ? `<a href="${esc(s.url)}" target="_blank" rel="noopener nofollow">[${s.nr}]</a>` : `<span title="${esc(s.nazwa)}">[${s.nr}]</span>`).join(' ');
            const zs = (z.zrodla_siedziba || []).map(s => `<a href="${esc(safeUrl(s.url))}" target="_blank" rel="noopener nofollow">${esc(s.nazwa || new URL(s.url).hostname)}</a>`).join(', ');
            return `<article class="pal-herb">
                <div class="pal-herb-sw" title="na siwym włosie / na ciemnym blondzie"><span style="background:${a}"></span><span style="background:${b}"></span></div>
                <div class="pal-herb-b"><h3>${linkZiola(z)}</h3>
                <p class="pal-herb-tags"><span class="pal-tag">${esc(RODZAJ[z.rodzaj])}</span><span class="pal-tag t-${slug(z.trwalosc)}">${esc(z.trwalosc)}</span><span class="pal-tag p-${pw[1]}">${pw[0]}</span>${z.rodzime ? '<span class="pal-tag">🌿 w Polsce</span>' : ''}${z._siedziba ? '<span class="pal-tag p-sied">z Siedziby</span>' : ''}</p>
                <p><b>Barwnik:</b> ${esc(z.barwnik)}</p><p>${esc(z.dziala)}</p>
                ${(z.uwagi || []).length ? `<p class="pal-muted small">${z.uwagi.map(esc).join(' ')}</p>` : ''}
                <p class="pal-herb-src">${zr ? 'Źródła: ' + zr : ''}${zs ? `<br>Z Siedziby: ${zs}` : ''}</p>
                <button type="button" class="btn pal-btn-ghost btn-sm" data-dodaj="${z.id}"><i class="bi bi-plus-lg" aria-hidden="true"></i> do mieszalnika</button></div></article>`;
        }).join('');
    }

    function zbudujZrodla() {
        $('#palZrodla').innerHTML = D.zrodla.map(s => `<li value="${s.nr}">${safeUrl(s.url) ? `<a href="${esc(s.url)}" target="_blank" rel="noopener nofollow">${esc(s.nazwa)}</a>` : esc(s.nazwa)}</li>`).join('');
    }

    // ------------------------------------------------------------------ zakładki i zdarzenia
    function przelaczZakladke(k) {
        const cel = k === 'cel';
        $('#palTabCel').classList.toggle('active', cel); $('#palTabCel').setAttribute('aria-selected', cel);
        $('#palTabMix').classList.toggle('active', !cel); $('#palTabMix').setAttribute('aria-selected', !cel);
        $('#palPanelCel').hidden = !cel; $('#palPanelMix').hidden = cel;
        pasekMiksera();
    }

    let timer = null;
    function planujPrzeliczenie() {
        clearTimeout(timer);
        timer = setTimeout(() => {
            odswiezSrodek();
            if (!$('#palPanelCel').hidden && wybranyCel) przeliczDobor();
            else if (!$('#palPanelMix').hidden) przeliczMix();
            else if (aktualne) pokaz(aktualne, false);
        }, 250);
    }

    function zdarzenia() {
        $('#palTabCel').addEventListener('click', () => przelaczZakladke('cel'));
        $('#palTabMix').addEventListener('click', () => { przelaczZakladke('mix'); przeliczMix(); });
        $$('.pal-tabs [role="tab"]').forEach(t => t.addEventListener('keydown', e => {
            if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { const o = t.id === 'palTabCel' ? $('#palTabMix') : $('#palTabCel'); o.focus(); o.click(); }
        }));
        ['#palOptRodzime', '#palOptBezTrwalych', '#palOptPlukanki'].forEach(s => $(s).addEventListener('change', () => { if (wybranyCel) przeliczDobor(); }));
        $('#palPropozycje').addEventListener('click', e => {
            const box = $('#palPropozycje'), c = D.cele.find(x => x.id === wybranyCel);
            const p = e.target.closest('[data-pokaz]'), m = e.target.closest('[data-edytuj]');
            if (p) { const w = box._wyniki[p.dataset.pokaz]; pokaz({ plan: w.plan, zrodlo: 'cel', dE: w.dE, cel: c }, true); }
            if (m) doMiksera(box._wyniki[m.dataset.edytuj].plan);
        });
        $('#palReceptura').addEventListener('click', e => {
            const info = $('#palKopiujInfo');
            if (e.target.closest('#palKopiuj')) kopiuj(tekstReceptury(), info);
            else if (e.target.closest('#palLink')) { history.replaceState(null, '', '#' + stanDoHash()); kopiuj(location.href, info); }
            else if (e.target.closest('#palDrukuj')) window.print();
            else if (e.target.closest('#palDoMix') && aktualne) { doMiksera(aktualne.plan); przewinDo(document.getElementById('palDobor')); }
        });
        $('#palAtlas').addEventListener('click', e => {
            const b = e.target.closest('[data-dodaj]'); if (!b) return;
            dodajDoMiksera(Z[b.dataset.dodaj]);
            rysujMikser(); przelaczZakladke('mix'); przeliczMix();
            przewinDo(document.getElementById('palDobor'));
        });
    }

    // ------------------------------------------------------------------ start
    (async function start() {
        try { await wczytaj(); }
        catch (e) { root.insertAdjacentHTML('afterbegin', '<div class="pal-alert">Nie udało się wczytać danych palety. Odśwież stronę.</div>'); return; }
        const zLinku = stanZHash();
        profil = wczytajProfil();
        if (zLinku && zLinku.pr && typeof zLinku.pr === 'object') {
            const p = zLinku.pr;
            profil = Object.assign({}, DOMYSLNY, {
                poziom: Math.min(10, Math.max(1, Number(p.poziom) || 6)), siwizna: Math.min(100, Math.max(0, Number(p.siwizna) || 0)),
                grubosc: ['cienkie', 'srednie', 'grube'].includes(p.grubosc) ? p.grubosc : 'srednie',
                porowatosc: ['niska', 'srednia', 'wysoka'].includes(p.porowatosc) ? p.porowatosc : 'srednia',
                dlugosc: D.dlugosci.some(d => d.klucz === p.dlugosc) ? p.dlugosc : 'ramiona',
                chemia: Object.fromEntries(Object.entries(p.chemia || {}).filter(([, v]) => v === true)),
                produkty: Object.fromEntries(Object.entries(p.produkty || {}).filter(([, v]) => v === true))
            });
        }
        zbudujProfil();
        zbudujKolo();
        zbudujPicker();
        zbudujMikser();
        obserwujMikser();
        zbudujAtlas();
        zbudujZrodla();
        zdarzenia();
        const plan = zLinku && poprawnyPlan(zLinku.pl);
        if (plan && (plan.kroki.length || plan.plukanki.length)) {
            const c = zLinku.c && D.cele.find(x => x.id === zLinku.c);
            if (c) { wybranyCel = c.id; odswiezSrodek(); }
            doMiksera(plan);
            pokaz({ plan, zrodlo: 'mix' }, false);
        }
    })();
})();
