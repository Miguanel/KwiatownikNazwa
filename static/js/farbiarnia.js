/* =====================================================================
   FARBIARNIA – barwienie wełny, jedwabiu, bawełny i lnu roślinami
   Dane: static/json/farbiarnia.json. Wszystko liczy się w przeglądarce (strona statyczna).

   Model koloru (jak w Palecie Barw): barwnik działa jak filtr nakładany na kolor włókna.
   „kolory” w danych to wynik na białej wełnie przy pełnej ilości rośliny, więc filtr rośliny
   T = kolor / biała wełna (w liniowym RGB), a wynik = włókno × T^a,
   gdzie a = (ilość / pełna ilość)^0,7 × chłonność włókna (× 0,5 dla włókien roślinnych bez zaprawy).
   Dobarwienie drugą rośliną to drugi filtr nałożony na wynik pierwszego.
   ===================================================================== */
(function () {
    'use strict';
    const root = document.getElementById('farbiarnia');
    if (!root) return;
    const $ = (s, el) => (el || document).querySelector(s);
    const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
    const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const safeUrl = u => (typeof u === 'string' && /^https?:\/\//i.test(u)) ? u : null;
    const LS = 'kw_farbiarnia_v1';
    const ZAPRAWY = { brak: 'bez zaprawy', alun: 'ałun', zelazo: 'ałun + żelazo' };
    const TYP = { zaprawowy: 'wymaga zaprawy', bezposredni: 'barwi bez zaprawy (garbniki)', kadziowy: 'barwnik kadziowy' };
    const PEWNOSC = { potwierdzone: ['potwierdzone źródłami', 'ok'], tradycyjne: ['tradycja farbiarska', 'trad'], niepewne: ['niepewne', 'nie'] };

    // ---------- kolory ----------
    const toLin = v => v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    const toSrgb = v => v <= 0.0031308 ? 12.92 * v : 1.055 * Math.pow(v, 1 / 2.4) - 0.055;
    const c01 = v => Math.min(1, Math.max(0, v));
    const lin = hex => { const n = parseInt(String(hex).slice(1), 16); return [n >> 16 & 255, n >> 8 & 255, n & 255].map(v => toLin(v / 255)); };
    const hexL = c => '#' + c.map(v => Math.round(c01(toSrgb(c01(v))) * 255).toString(16).padStart(2, '0')).join('');
    const jasny = hex => { const c = lin(hex); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2] > 0.3; };

    let D = null, R = {}, W = {};
    const stan = { wlokno: 'welna', masa: 100, zaprawa: 'alun', roslina: null, ilosc: null, drugi: '', drugiIlosc: null };

    function zapamietaj() { try { localStorage.setItem(LS, JSON.stringify({ wlokno: stan.wlokno, masa: stan.masa, zaprawa: stan.zaprawa })); } catch (e) { } }
    function przypomnij() { try { Object.assign(stan, JSON.parse(localStorage.getItem(LS) || '{}')); } catch (e) { } }

    function domyslnaIlosc(r) { return r.typ === 'kadziowy' ? 3 : Math.round((r.wof[0] + r.wof[1]) / 2); }

    function filtr(r, zaprawa) {
        const T = lin(r.kolory[zaprawa] || r.kolory.alun);
        const bialy = lin(W.welna.kolor);
        return T.map((v, i) => c01(v / bialy[i]));
    }
    function sila(r, ilosc, wlokno, zaprawa) {
        let a;
        if (r.typ === 'kadziowy') a = (1 - Math.exp(-ilosc / 2.2)) / (1 - Math.exp(-6 / 2.2));
        else a = Math.pow(Math.max(0, ilosc) / r.wof[1], 0.7);
        a *= wlokno.chlonnosc;
        if (wlokno.rodzaj === 'celulozowe' && zaprawa === 'brak' && r.typ === 'zaprawowy') a *= 0.5;
        return a;
    }
    function barw(c, r, ilosc, wlokno, zaprawa) {
        const T = filtr(r, zaprawa), a = sila(r, ilosc, wlokno, zaprawa);
        return c.map((v, i) => v * Math.pow(Math.max(T[i], 1e-4), a));
    }
    function wynik(zaprawa) {
        const wl = W[stan.wlokno], r = R[stan.roslina];
        let c = lin(wl.kolor);
        if (!r) return hexL(c);
        c = barw(c, r, stan.ilosc, wl, zaprawa);
        const r2 = R[stan.drugi];
        if (r2) c = barw(c, r2, stan.drugiIlosc, wl, zaprawa);
        return hexL(c);
    }

    // ---------- rysunek motka ----------
    let nr = 0;
    function motek(hex, label, cls) {
        const id = 'fbm' + (++nr);
        let nitki = '';
        for (let i = 0; i < 9; i++) {
            const y = 14 + i * 4.2;
            nitki += `<path d="M10 ${y} C 40 ${y - 9} 80 ${y + 9} 110 ${y}" stroke="${hex}" stroke-width="5.2" fill="none" stroke-linecap="round"/>`;
        }
        return `<svg class="fb-motek ${cls || ''}" viewBox="0 0 120 64" role="img" aria-label="${esc(label)}">
            <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".25"/>
            <stop offset=".45" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity=".22"/></linearGradient></defs>
            <ellipse cx="60" cy="32" rx="56" ry="26" fill="${hex}"/>${nitki}
            <ellipse cx="60" cy="32" rx="56" ry="26" fill="url(#${id})"/>
            <ellipse cx="60" cy="32" rx="16" ry="6" fill="var(--kw-paper)" opacity=".9"/></svg>`;
    }

    // ---------- interfejs ----------
    function zbudujWlokna() {
        $('#fbWlokna').innerHTML = D.wlokna.map(w => `<label><input type="radio" name="wlokno" value="${w.id}"${w.id === stan.wlokno ? ' checked' : ''}> ${esc(w.nazwa)}</label>`).join('');
        $('#fbMasa').value = stan.masa;
        $$('input[name="zaprawa"]').forEach(r => { r.checked = r.value === stan.zaprawa; });
        $('#fbForm').addEventListener('change', e => {
            if (e.target.name === 'wlokno') stan.wlokno = e.target.value;
            if (e.target.name === 'zaprawa') stan.zaprawa = e.target.value;
            odswiez(false);
        });
        $('#fbMasa').addEventListener('input', e => { stan.masa = Math.min(5000, Math.max(1, Number(e.target.value) || 0)); odswiez(false); });
    }

    function grupaKoloru(r) {
        const c = lin(r.kolory.alun), [cr, cg, cb] = c;
        if (cb > cr && cb > cg) return 'Błękity i fiolety';
        if (cr > cg * 2.2) return 'Czerwienie i fiolety';
        if (0.2126 * cr + 0.7152 * cg + 0.0722 * cb < 0.12) return 'Brązy, szarości i czernie';
        return 'Żółcie, złota i zielenie';
    }
    function zbudujPicker() {
        const grupy = {};
        D.rosliny.forEach(r => (grupy[grupaKoloru(r)] = grupy[grupaKoloru(r)] || []).push(r));
        const kol = ['Żółcie, złota i zielenie', 'Czerwienie i fiolety', 'Błękity i fiolety', 'Brązy, szarości i czernie'];
        $('#fbPicker').innerHTML = kol.filter(k => grupy[k]).map(k => `<div class="pal-pick-group"><h3>${esc(k)}</h3><div class="pal-pick-list">
            ${grupy[k].map(r => `<button type="button" class="pal-pick" data-r="${r.id}"><span class="pal-dot" style="background:${r.kolory.alun}"></span>${esc(r.nazwa)}</button>`).join('')}</div></div>`).join('');
        $('#fbPicker').addEventListener('click', e => {
            const b = e.target.closest('[data-r]'); if (!b) return;
            wybierz(b.dataset.r);
            if (window.matchMedia('(max-width: 900px)').matches) przewin($('#fbWybor'));
        });
        $('#fbDrugi').innerHTML = '<option value="">— bez dobarwiania —</option>' + D.rosliny.map(r => `<option value="${r.id}">${esc(r.nazwa)}</option>`).join('');
        $('#fbDrugi').addEventListener('change', e => {
            stan.drugi = e.target.value;
            stan.drugiIlosc = R[stan.drugi] ? domyslnaIlosc(R[stan.drugi]) : null;
            odswiez();
        });
    }
    function przewin(el) {
        const h = document.querySelector('.main-header');
        const off = (h ? h.getBoundingClientRect().bottom : 110) + 10;
        const ruch = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
        window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - off, behavior: ruch });
    }
    function wybierz(id) {
        if (!R[id]) return;
        stan.roslina = id;
        stan.ilosc = domyslnaIlosc(R[id]);
        odswiez();
    }

    function suwak(r, wartosc, idAttr, etykieta) {
        const kadz = r.typ === 'kadziowy';
        const min = kadz ? 1 : Math.max(5, Math.round(r.wof[0] / 2)), max = kadz ? 8 : Math.round(r.wof[1] * 1.5);
        return `<label class="fb-ilosc">${esc(etykieta)}: <strong data-out="${idAttr}">${kadz ? wartosc + ' zanurz.' : wartosc + '%'}</strong>
            <input type="range" class="pal-range" data-suwak="${idAttr}" min="${min}" max="${max}" step="${kadz ? 1 : 5}" value="${wartosc}"></label>
            <small class="pal-help">${kadz ? 'Więcej zanurzeń = głębszy błękit.' : `Zwykle ${r.wof[0]}–${r.wof[1]}% masy włókna (${esc(r.stan)}).`}</small>`;
    }

    function probki() {
        return Object.keys(ZAPRAWY).map(z => `<button type="button" class="fb-probka${z === stan.zaprawa ? ' on' : ''}" data-zap="${z}" aria-pressed="${z === stan.zaprawa}">
                 ${motek(wynik(z), ZAPRAWY[z], 'sm')}<span>${ZAPRAWY[z]}</span></button>`).join('');
    }
    // pelne=false: tylko kolory i receptura (suwaki nie są przerysowywane – przeciąganie palcem działa płynnie)
    function odswiez(pelne = true) {
        zapamietaj();
        const wl = W[stan.wlokno];
        $('#fbAlunNazwa').textContent = wl.rodzaj === 'celulozowe' ? 'octan glinu' : 'ałun';
        $$('#fbPicker [data-r]').forEach(b => b.classList.toggle('on', b.dataset.r === stan.roslina));
        const r = R[stan.roslina];
        if (!r) return;
        if (!pelne) {
            const p = $('.fb-probki'); if (p) p.innerHTML = probki();
            recepta();
            return;
        }
        // wybór + próbki trzech zapraw
        $('#fbWybor').innerHTML = `<div class="fb-wybrana"><h3>${esc(r.nazwa)} <i class="pal-lat">${esc(r.lat)}</i></h3>
            <p class="pal-herb-tags"><span class="pal-tag">${esc(TYP[r.typ])}</span><span class="pal-tag">trwałość: ${esc(r.trwalosc)}</span>
            ${r.rodzime ? '<span class="pal-tag">🌿 w Polsce</span>' : ''}</p>
            ${suwak(r, stan.ilosc, '1', 'Ilość rośliny')}
            <div class="fb-probki" role="group" aria-label="Zaprawa – kliknij próbkę">${probki()}</div></div>`;
        const r2 = R[stan.drugi];
        $('#fbDrugiIlosc').innerHTML = r2 ? suwak(r2, stan.drugiIlosc, '2', 'Ilość / zanurzenia') : '';
        recepta();
    }

    function recepta() {
        const wl = W[stan.wlokno], r = R[stan.roslina], r2 = R[stan.drugi];
        const m = stan.masa, Z = D.zaprawy, cel = wl.rodzaj === 'celulozowe';
        const zap = cel ? Z.celulozowe : Z.bialkowe;
        const g = (p) => (m * p / 100);
        const fmt = v => v >= 10 ? Math.round(v) : (Math.round(v * 10) / 10).toString().replace('.', ',');
        const zakres = ([a, b]) => `${fmt(g(a))}–${fmt(g(b))} g`;
        const ilR = x => x.typ === 'kadziowy' ? null : `${fmt(g(x === r ? stan.ilosc : stan.drugiIlosc))} g ${x.stan === 'świeże' ? 'świeżej rośliny' : 'suszu'}`;
        const woda = D.kapiel.litry_na_kg.map(v => fmt(v * m / 1000)).join('–');
        const kolor = wynik(stan.zaprawa);
        let html = `<div class="fb-rec-top">${motek(wl.kolor, 'Włókno przed barwieniem', '')}<i class="bi bi-arrow-right" aria-hidden="true"></i>${motek(kolor, 'Przewidywany kolor', 'lg')}
            <div><strong>${esc(r.nazwa)}${r2 ? ' + ' + esc(r2.nazwa) : ''}</strong><br><span class="pal-muted">${esc(wl.nazwa)}, ${fmt(m)} g · ${esc(ZAPRAWY[stan.zaprawa])}</span>
            <br><span class="pal-swatch" style="background:${kolor}" title="${kolor}"></span> <code>${kolor}</code></div></div>`;
        // lista zakupów / ilości
        const wiersze = [];
        if (r.typ !== 'kadziowy') wiersze.push([r.nazwa, ilR(r)]);
        else wiersze.push([r.nazwa, `kadź indygowa, ${stan.ilosc} zanurz.`]);
        if (r2) wiersze.push([r2.nazwa + ' (dobarwienie)', r2.typ === 'kadziowy' ? `kadź indygowa, ${stan.drugiIlosc} zanurz.` : ilR(r2)]);
        if (stan.zaprawa !== 'brak') {
            wiersze.push([cel ? 'Octan glinu' : 'Ałun (siarczan glinowo-potasowy)', zakres(zap.alun.proc)]);
            if (zap.alun.dodatek) wiersze.push([zap.alun.dodatek.nazwa, `${fmt(g(zap.alun.dodatek.proc))} g`]);
        }
        if (stan.zaprawa === 'zelazo') wiersze.push(['Siarczan żelaza(II)', zakres(Z.zelazo.proc)]);
        wiersze.push(['Woda do kąpieli', `${woda} l`]);
        html += `<div class="pal-table-wrap"><table class="pal-table"><thead><tr><th>Co</th><th>Ile</th></tr></thead><tbody>
            ${wiersze.map(([a, b]) => `<tr><td>${esc(a)}</td><td>${esc(b)}</td></tr>`).join('')}</tbody></table></div>`;
        // kroki
        const kroki = [zap.pranie];
        if (stan.zaprawa !== 'brak') kroki.push(`<b>Zaprawa:</b> ${zap.alun.opis}${zap.alun.dodatek ? ` ${esc(zap.alun.dodatek.nazwa[0].toUpperCase() + zap.alun.dodatek.nazwa.slice(1))} – ${esc(zap.alun.dodatek.po_co)}.` : ''}`);
        else if (r.typ === 'zaprawowy') kroki.push('<b>Bez zaprawy</b> kolor będzie słabszy i mniej odporny na pranie i słońce.');
        kroki.push(`<b>${esc(r.nazwa)}:</b> ${esc(r.przygotowanie)}`);
        if (r2) kroki.push(`<b>Dobarwienie – ${esc(r2.nazwa)}:</b> ${esc(r2.przygotowanie)}`);
        if (stan.zaprawa === 'zelazo') kroki.push(`<b>Kąpiel żelazowa:</b> ${esc(Z.zelazo.opis)}`);
        kroki.push('Wypłucz w wodzie o podobnej temperaturze (nagła zmiana filcuje wełnę), wypierz łagodnie i susz w cieniu.');
        html += `<ol class="pal-howto">${kroki.map(k => `<li>${k}</li>`).join('')}</ol>`;
        // ostrzeżenia
        const ostr = [...(r.uwagi || []), ...(r2 ? r2.uwagi || [] : [])];
        if (stan.zaprawa === 'zelazo') ostr.push(Z.zelazo.uwaga);
        if (r.trwalosc === 'słaba' || (r2 && r2.trwalosc === 'słaba')) ostr.push('Barwnik o słabej odporności na światło – susz w cieniu i nie wieszaj na słońcu.');
        html += `<div class="pal-warns"><h3>Uwagi i bezpieczeństwo</h3><ul>
            ${ostr.map(t => `<li class="w-uwaga"><i class="bi bi-exclamation-triangle" aria-hidden="true"></i> ${esc(t)}</li>`).join('')}
            ${D.bezpieczenstwo.map(t => `<li class="w-info"><i class="bi bi-info-circle" aria-hidden="true"></i> ${esc(t)}</li>`).join('')}</ul></div>`;
        html += `<div class="pal-rec-btns"><button type="button" class="btn pal-btn" id="fbDrukuj"><i class="bi bi-printer" aria-hidden="true"></i> Drukuj recepturę</button>
            ${r.karta ? `<a class="btn pal-btn-ghost" href="/plant/${encodeURIComponent(r.karta)}/">Karta rośliny →</a>` : ''}</div>`;
        $('#fbReceptura').innerHTML = html;
    }

    function zbudujAtlas() {
        const zr = nr => D.zrodla.find(z => z.nr === nr);
        $('#fbAtlas').innerHTML = D.rosliny.map(r => {
            const pw = PEWNOSC[r.pewnosc] || PEWNOSC.niepewne;
            const linki = (r.zrodla || []).map(zr).filter(Boolean).map(s => safeUrl(s.url) ? `<a href="${esc(s.url)}" target="_blank" rel="noopener nofollow">[${s.nr}]</a>` : `<span title="${esc(s.nazwa)}">[${s.nr}]</span>`).join(' ');
            return `<article class="pal-herb">
                <div class="fb-atlas-sw" title="bez zaprawy · ałun · ałun + żelazo">${['brak', 'alun', 'zelazo'].map(z => `<span style="background:${r.kolory[z]}"></span>`).join('')}</div>
                <div class="pal-herb-b"><h3>${esc(r.nazwa)} <i class="pal-lat">${esc(r.lat)}</i></h3>
                <p class="pal-herb-tags"><span class="pal-tag">${esc(TYP[r.typ])}</span><span class="pal-tag p-${pw[1]}">${pw[0]}</span>${r.rodzime ? '<span class="pal-tag">🌿 w Polsce</span>' : ''}</p>
                <p><b>Surowiec:</b> ${esc(r.czesc)}${r.typ !== 'kadziowy' ? ` · ${r.wof[0]}–${r.wof[1]}% masy włókna` : ''}</p>
                ${(r.uwagi || []).length ? `<p class="pal-muted small">${r.uwagi.map(esc).join(' ')}</p>` : ''}
                <p class="pal-herb-src">${linki ? 'Źródła: ' + linki : ''}${r.karta ? ` · <a href="/plant/${encodeURIComponent(r.karta)}/">karta rośliny</a>` : ''}</p>
                <button type="button" class="btn pal-btn-ghost btn-sm" data-wybierz="${r.id}">Barw tą rośliną</button></div></article>`;
        }).join('');
        $('#fbAtlas').addEventListener('click', e => {
            const b = e.target.closest('[data-wybierz]'); if (!b) return;
            wybierz(b.dataset.wybierz);
            przewin($('#fbWybor'));
        });
        $('#fbZrodla').innerHTML = D.zrodla.map(s => `<li value="${s.nr}">${safeUrl(s.url) ? `<a href="${esc(s.url)}" target="_blank" rel="noopener nofollow">${esc(s.nazwa)}</a>` : esc(s.nazwa)}</li>`).join('');
    }

    function zdarzenia() {
        root.addEventListener('input', e => {
            const s = e.target.closest('[data-suwak]'); if (!s) return;
            const v = Number(s.value);
            if (s.dataset.suwak === '1') stan.ilosc = v; else stan.drugiIlosc = v;
            const r = R[s.dataset.suwak === '1' ? stan.roslina : stan.drugi];
            const out = root.querySelector(`[data-out="${s.dataset.suwak}"]`);
            if (out && r) out.textContent = r.typ === 'kadziowy' ? v + ' zanurz.' : v + '%';
            odswiez(false);
        });
        root.addEventListener('click', e => {
            const p = e.target.closest('[data-zap]');
            if (p) {
                stan.zaprawa = p.dataset.zap;
                $$('input[name="zaprawa"]').forEach(r => { r.checked = r.value === stan.zaprawa; });
                odswiez(false);
            }
            if (e.target.closest('#fbDrukuj')) window.print();
        });
    }

    (async function start() {
        try { D = await (await fetch(root.dataset.json)).json(); }
        catch (e) { root.insertAdjacentHTML('afterbegin', '<div class="pal-alert">Nie udało się wczytać danych Farbiarni. Odśwież stronę.</div>'); return; }
        D.rosliny.forEach(r => { R[r.id] = r; });
        D.wlokna.forEach(w => { W[w.id] = w; });
        przypomnij();
        if (!W[stan.wlokno]) stan.wlokno = 'welna';
        if (!ZAPRAWY[stan.zaprawa]) stan.zaprawa = 'alun';
        zbudujWlokna();
        zbudujPicker();
        zbudujAtlas();
        zdarzenia();
        const q = new URLSearchParams(location.search).get('r');
        wybierz(R[q] ? q : 'cebula');
    })();
})();
