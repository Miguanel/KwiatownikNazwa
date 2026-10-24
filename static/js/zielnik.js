/* =====================================================================
   MÓJ ZIELNIK (/zielnik/)
   Dane o roślinach: /api/zielnik.json (liczone przy budowie strony, app/utils/zielnik_data.py).
   Dane użytkownika: window.KwZielnik (static/js/zielnik_store.js, localStorage „kw_zielnik_v1”).
   Zakładki: Rośliny (co zrobić z każdą), Spiżarnia (zbiory + terminy + etykiety),
   Co zrobić (przepisy wg pokrycia Twoich roślin), Kalendarz (prace w tym miesiącu i rok).
   ===================================================================== */
(function () {
    'use strict';
    const root = document.getElementById('zielnik');
    const Z = window.KwZielnik;
    if (!root || !Z) return;

    const $ = id => document.getElementById(id);
    const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const norm = s => String(s || '').toLowerCase().replace(/ł/g, 'l').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();
    const MIES = ['styczeń', 'luty', 'marzec', 'kwiecień', 'maj', 'czerwiec', 'lipiec', 'sierpień', 'wrzesień', 'październik', 'listopad', 'grudzień'];
    const MIES_D = ['sty', 'lut', 'mar', 'kwi', 'maj', 'cze', 'lip', 'sie', 'wrz', 'paź', 'lis', 'gru'];
    const MIES_1 = ['S', 'L', 'M', 'K', 'M', 'C', 'L', 'S', 'W', 'P', 'L', 'G'];
    const ZAST = { kulinarne: '🍲 W kuchni', ogrodowe: '🌱 W ogrodzie', rzemieslnicze: '🧶 Rzemiosło', kosmetyczne: '🌸 Kosmetyka' };

    // Postać zapasu → orientacyjna trwałość w miesiącach (dla suszu zależy też od części rośliny)
    const FORMY = {
        susz: { n: 'susz', m: null },
        swieze: { n: 'świeże', d: 5 },
        mrozone: { n: 'mrożone', m: 8 },
        nalewka: { n: 'nalewka / tynktura', m: 36 },
        macerat: { n: 'olej (macerat)', m: 12 },
        ocet: { n: 'ocet ziołowy', m: 12 },
        syrop: { n: 'syrop / sok', m: 12 },
        masc: { n: 'maść / balsam', m: 12 },
        hydrolat: { n: 'hydrolat', m: 6 },
        nasiona: { n: 'nasiona do siewu', m: 24 },
        inne: { n: 'inne', m: 12 }
    };
    const SUSZ_DLUGO = ['korzen', 'klacze', 'kora', 'nasiona', 'galazki', 'szyszki'];

    let DATA = null, R = {}, P = [];
    const ILE = { pelne: 24, jedna: 12, kilka: 8 };
    let katCo = 'all', ileCo = Object.assign({}, ILE);
    const ulubione = (() => { try { return new Set(JSON.parse(localStorage.getItem('recipeFavorites')) || []); } catch (e) { return new Set(); } })();

    // ---------- pomocnicze ----------
    const stan = () => Z.wczytaj();
    const nazwa = id => (R[id] && R[id].n) || (stan().rosliny[id] || {}).nazwa || String(id).replace(/_/g, ' ');
    const linkRosliny = id => '/plant/' + encodeURIComponent(id) + '/';
    const linkPrzepisu = t => '/przepisy/?q=' + encodeURIComponent(t) + '&autoopen=true';
    function zapasy(d) {
        const out = {};
        (d || stan()).zbiory.forEach(z => { if (!z.zuzyte && z.id) out[z.id] = (out[z.id] || 0) + 1; });
        return out;
    }
    function dodajMies(dataIso, m, dni) {
        const d = new Date((dataIso || new Date().toISOString().slice(0, 10)) + 'T12:00:00');
        if (isNaN(d)) return null;
        if (dni) d.setDate(d.getDate() + dni); else d.setMonth(d.getMonth() + m);
        return d.toISOString().slice(0, 10);
    }
    function zuzyjDo(z) {
        const f = FORMY[z.forma] || FORMY.inne;
        if (f.d) return dodajMies(z.data, 0, f.d);
        let m = f.m;
        if (z.forma === 'susz') m = SUSZ_DLUGO.includes(z.czesc) ? 24 : 12;
        return dodajMies(z.data, m);
    }
    const dniDo = iso => Math.round((new Date(iso + 'T12:00:00') - new Date(new Date().toISOString().slice(0, 10) + 'T12:00:00')) / 864e5);
    const dataPl = iso => { if (!iso) return ''; const [y, m, d] = iso.split('-'); return `${+d} ${MIES_D[+m - 1]} ${y}`; };
    function czescNazwa(id, k) {
        const c = R[id] && R[id].cz.find(x => x.k === k);
        return c ? c.n : (k === 'cale' ? 'całe ziele' : k === 'inne' ? 'inna część' : (k || ''));
    }
    function znajdz(text, ile) {
        const q = norm(text);
        if (!q) return [];
        const a = [], b = [], c = [];
        P.forEach(p => {
            const n = norm(p.n), l = norm(p.lat);
            if (n === q || l === q) a.push(p);
            else if (n.startsWith(q) || l.startsWith(q) || n.split(' ').some(w => w.startsWith(q))) b.push(p);
            else if (n.includes(q) || l.includes(q)) c.push(p);
        });
        return a.concat(b, c).slice(0, ile || 8);
    }

    // ---------- start ----------
    fetch(root.dataset.json).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); }).then(d => {
        DATA = d;
        P = d.rosliny || [];
        P.forEach(p => { R[p.id] = p; });
        zakladki();
        wyszukiwarka();
        formularz();
        kopia();
        odswiezWszystko();
        zHash();
        window.addEventListener('hashchange', zHash);
    }).catch(() => {
        $('zlRosliny').innerHTML = '<p class="pal-muted">Nie udało się wczytać danych o roślinach. Odśwież stronę.</p>';
    });

    function odswiezWszystko() {
        rysujStat();
        rysujPropozycje();
        rysujRosliny();
        rysujSpizarnie();
        rysujCo();
        rysujKalendarz();
        wypelnijRosliny();
    }

    // ---------- zakładki ----------
    const TABY = [['zlTabRos', 'zlPanelRos'], ['zlTabSpi', 'zlPanelSpi'], ['zlTabCo', 'zlPanelCo'], ['zlTabKal', 'zlPanelKal']];
    function pokazTab(tabId) {
        TABY.forEach(([t, p]) => {
            const on = t === tabId;
            $(t).classList.toggle('active', on);
            $(t).setAttribute('aria-selected', on ? 'true' : 'false');
            $(t).tabIndex = on ? 0 : -1;
            $(p).hidden = !on;
        });
        try { sessionStorage.setItem('kw_zielnik_tab', tabId); } catch (e) { /* bez pamięci */ }
    }
    function zakladki() {
        TABY.forEach(([t], i) => {
            $(t).addEventListener('click', () => pokazTab(t));
            $(t).addEventListener('keydown', e => {
                if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
                const n = TABY[(i + (e.key === 'ArrowRight' ? 1 : TABY.length - 1)) % TABY.length][0];
                pokazTab(n); $(n).focus();
            });
        });
        let t = null;
        try { t = sessionStorage.getItem('kw_zielnik_tab'); } catch (e) { t = null; }
        pokazTab(TABY.some(x => x[0] === t) ? t : 'zlTabRos');
    }

    // ---------- statystyka ----------
    function rysujStat() {
        const d = stan();
        const ids = Object.keys(d.rosliny);
        const zap = d.zbiory.filter(z => !z.zuzyte).length;
        const pelne = DATA.przepisy.filter(p => p.r.every(id => d.rosliny[id])).length;
        const pilne = d.zbiory.filter(z => !z.zuzyte && zuzyjDo(z) && dniDo(zuzyjDo(z)) <= 30).length;
        if (!ids.length) { $('zlStat').innerHTML = ''; return; }
        $('zlStat').innerHTML = [
            `<span><strong>${ids.length}</strong> ${ids.length === 1 ? 'roślina' : (ids.length % 10 >= 2 && ids.length % 10 <= 4 && (ids.length % 100 < 10 || ids.length % 100 >= 20) ? 'rośliny' : 'roślin')}</span>`,
            `<span><strong>${zap}</strong> w spiżarni</span>`,
            `<span><strong>${pelne}</strong> ${pelne === 1 ? 'przepis' : 'przepisów'} z Twoich roślin</span>`,
            pilne ? `<span class="zl-stat-pilne"><strong>${pilne}</strong> do zużycia w ciągu miesiąca</span>` : ''
        ].join('');
    }

    // ---------- dodawanie roślin ----------
    function wyszukiwarka() {
        const inp = $('zlSzukaj'), box = $('zlPodpowiedzi');
        let wyn = [], akt = -1;
        const zamknij = () => { box.hidden = true; akt = -1; inp.setAttribute('aria-expanded', 'false'); };
        const rysuj = () => {
            const d = stan();
            wyn = znajdz(inp.value, 8);
            if (!wyn.length) {
                box.innerHTML = inp.value.trim() ? '<div class="zl-podp-brak">Nie ma takiej rośliny w Kwiatowniku.</div>' : '';
                box.hidden = !inp.value.trim();
                return;
            }
            box.innerHTML = wyn.map((p, i) => `<button type="button" role="option" data-i="${i}" class="${i === akt ? 'on' : ''}" aria-selected="${i === akt}">
                <span>${esc(p.n)} <em>${esc(p.lat)}</em></span>${d.rosliny[p.id] ? '<small>już masz</small>' : '<small>+ dodaj</small>'}</button>`).join('');
            box.hidden = false;
            inp.setAttribute('aria-expanded', 'true');
        };
        const wybierz = i => {
            const p = wyn[i];
            if (!p) return;
            Z.dodaj(p.id, p.n);
            inp.value = '';
            zamknij();
            odswiezWszystko();
            pokazTab('zlTabRos');
            otworzKarte(p.id);
            if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
        };
        inp.addEventListener('input', () => { akt = -1; rysuj(); });
        inp.addEventListener('keydown', e => {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                if (!wyn.length) return;
                akt = (akt + (e.key === 'ArrowDown' ? 1 : wyn.length - 1)) % wyn.length;
                rysuj();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                wybierz(akt >= 0 ? akt : 0);
            } else if (e.key === 'Escape') zamknij();
        });
        box.addEventListener('mousedown', e => e.preventDefault());
        box.addEventListener('click', e => { const b = e.target.closest('button[data-i]'); if (b) wybierz(+b.dataset.i); });
        inp.addEventListener('blur', () => setTimeout(zamknij, 120));
    }

    function stareUlubione() {
        let names = [];
        try { names = JSON.parse(localStorage.getItem('herbariumFavorites')) || []; } catch (e) { names = []; }
        const d = stan(), out = [];
        names.forEach(n => {
            const p = znajdz(n, 1)[0];
            if (p && norm(p.n).startsWith(norm(n).split(' ')[0]) && !d.rosliny[p.id] && !out.includes(p)) out.push(p);
        });
        return out;
    }

    function rysujPropozycje() {
        const box = $('zlProp'), d = stan();
        const html = [];
        const stare = stareUlubione();
        if (stare.length) {
            html.push(`<div class="zl-info"><p><i class="bi bi-arrow-repeat" aria-hidden="true"></i> W starych „Ulubionych” masz ${stare.length === 1 ? 'roślinę' : 'rośliny'}: <strong>${stare.map(p => esc(p.n)).join(', ')}</strong>.</p>
                <button type="button" class="btn pal-btn btn-sm" data-akcja="przenies">Przenieś do Mojego zielnika</button></div>`);
        }
        if (!Object.keys(d.rosliny).length) {
            const start = ['pokrzywa_zwyczajna', 'mniszek_lekarski', 'rumianek_pospolity', 'bez_czarny', 'lipa_drobnolistna', 'dzika_roza', 'dziurawiec_zwyczajny', 'krwawnik_pospolity', 'babka_lancetowata', 'skrzyp_polny']
                .filter(id => R[id]);
            const ile = id => R[id].prz.length;
            const lista = (start.length >= 4 ? start : P.slice().sort((a, b) => b.prz.length - a.prz.length).slice(0, 8).map(p => p.id));
            html.push(`<div class="zl-start"><p>Zacznij od roślin, które rosną najbliżej – albo od tych, z których jest najwięcej przepisów:</p>
                <div class="zl-chipy">${lista.map(id => `<button type="button" class="zl-chip" data-dodaj="${esc(id)}">+ ${esc(R[id].n)} <small>${ile(id)}</small></button>`).join('')}</div></div>`);
        }
        box.innerHTML = html.join('');
    }
    $('zlProp').addEventListener('click', e => {
        const b = e.target.closest('button');
        if (!b) return;
        if (b.dataset.akcja !== 'przenies') return;
        stareUlubione().forEach(p => Z.dodaj(p.id, p.n));
        odswiezWszystko();
        if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
    });

    // ---------- zakładka: Rośliny ----------
    function przepisyRosliny(id) {
        const d = stan(), grupy = {};
        (R[id] ? R[id].prz : []).forEach(nr => {
            const p = DATA.przepisy[nr];
            const brak = p.r.filter(x => !d.rosliny[x]);
            (grupy[p.k] = grupy[p.k] || []).push({ p, brak });
        });
        Object.values(grupy).forEach(g => g.sort((a, b) => a.brak.length - b.brak.length || a.p.t.localeCompare(b.p.t, 'pl')));
        return grupy;
    }
    function szczegoly(id, wZielniku) {
        const p = R[id];
        if (!p) return '<p class="pal-muted">Tej rośliny nie ma już w Kwiatowniku.</p>';
        const d = stan(), zap = zapasy(d), out = [];
        // szybkie możliwości
        const mozl = [];
        if (p.farb) mozl.push(`<a class="zl-mozl" href="/farbiarnia/?r=${encodeURIComponent(p.farb)}"><i class="bi bi-flower3" aria-hidden="true"></i> Ufarbuj wełnę lub tkaninę<small>Farbiarnia: kolor i receptura</small></a>`);
        if (p.pal) mozl.push(`<a class="zl-mozl" href="/paleta/"><i class="bi bi-palette" aria-hidden="true"></i> Ziołowa farba do włosów<small>Paleta Barw – ta roślina jest w mieszankach</small></a>`);
        if (p.gil.length) mozl.push(`<a class="zl-mozl" href="/gildie/?q=${encodeURIComponent(p.n)}"><i class="bi bi-diagram-3" aria-hidden="true"></i> Posadź w gildii<small>${p.gil.length} dobrych sąsiadów</small></a>`);
        mozl.push(`<a class="zl-mozl" href="${linkRosliny(id)}"><i class="bi bi-book" aria-hidden="true"></i> Pełna karta rośliny<small>opis, działanie, ciekawostki</small></a>`);
        out.push(`<div class="zl-mozl-wrap">${mozl.join('')}</div>`);

        if (p.och) out.push(`<p class="zl-och zl-och-${esc(p.och.s)}"><i class="bi ${p.och.s === 'inwazyjny' ? 'bi-exclamation-triangle' : 'bi-shield-check'}" aria-hidden="true"></i> <strong>${esc(p.och.n)}.</strong> ${esc(p.och.p)}</p>`);

        // przepisy wg kategorii
        const grupy = przepisyRosliny(id);
        const kat = Object.keys(DATA.kategorie).filter(k => grupy[k]);
        if (kat.length) {
            out.push('<h4>Przepisy</h4><div class="zl-przepisy">' + kat.map(k => {
                const g = grupy[k];
                const li = g.slice(0, 6).map(({ p: pr, brak }) => `<li><a href="${linkPrzepisu(pr.t)}">${ulubione.has(pr.t) ? '★ ' : ''}${esc(pr.t)}</a>${brak.length ? ` <small class="zl-brak">+ ${brak.map(nazwa).map(esc).join(', ')}</small>` : (pr.r.length > 1 ? ' <small class="zl-ok">masz wszystko</small>' : '')}</li>`).join('');
                const wiecej = g.length > 6 ? `<li class="zl-wiecej"><a href="/przepisy/?q=${encodeURIComponent(p.n)}">wszystkie (${g.length}) →</a></li>` : '';
                return `<div class="zl-kat-box"><h5>${esc(DATA.kategorie[k])} <span>${g.length}</span></h5><ul>${li}${wiecej}</ul></div>`;
            }).join('') + '</div>');
        } else out.push('<p class="pal-muted small">W Przepiśniku nie ma jeszcze receptury z tą rośliną.</p>');

        // zastosowania
        const zk = Object.keys(ZAST).filter(k => p.zast[k]);
        if (zk.length) out.push('<h4>Zastosowania</h4><dl class="zl-zast">' + zk.map(k => `<dt>${ZAST[k]}</dt><dd>${esc(p.zast[k])}</dd>`).join('') + '</dl>');

        // części i zbiór
        if (p.cz.length) {
            out.push('<h4>Co zbierać i kiedy</h4><ul class="zl-czesci">' + p.cz.map(c => `<li><strong>${esc(c.n)}</strong>${c.sur ? ` <em>(${esc(c.sur)})</em>` : ''}${c.czas ? `<span class="zl-czas"><i class="bi bi-clock" aria-hidden="true"></i> ${esc(c.czas)}</span>` : ''}${c.dz ? `<span class="zl-dz">${esc(c.dz)}</span>` : ''}</li>`).join('') + '</ul>');
        }
        // kalendarz rośliny
        if (p.kal.length) {
            const teraz = new Date().getMonth() + 1;
            out.push('<h4>Prace w roku</h4><ul class="zl-prace">' + p.kal.map(t => `<li class="${t.m.includes(teraz) ? 'teraz' : ''}"><span class="zl-mies">${t.m.map(m => MIES_D[m - 1]).join(', ')}</span> <strong>${esc(t.c)}</strong>${t.o ? ` – ${esc(t.o)}` : ''}${t.m.includes(teraz) ? ' <small class="zl-ok">teraz</small>' : ''}</li>`).join('') + '</ul>');
        }
        // sąsiedzi
        if (p.gil.length) {
            out.push('<h4>Dobrzy sąsiedzi</h4><ul class="zl-gil">' + p.gil.map(g => {
                const n = g.id ? `<a href="${linkRosliny(g.id)}">${esc(g.n)}</a>` : esc(g.n);
                const ma = g.id && d.rosliny[g.id] ? ' <small class="zl-ok">masz</small>' : (g.id && wZielniku ? ` <button type="button" class="zl-mini" data-dodaj="${esc(g.id)}">+ dodaj</button>` : '');
                return `<li><strong>${n}</strong>${ma}${g.rola ? ` – ${esc(g.rola)}` : ''}</li>`;
            }).join('') + '</ul>');
        }
        if (p.ostr) out.push(`<p class="zl-ostr"><i class="bi bi-exclamation-diamond" aria-hidden="true"></i> <strong>Ostrożnie:</strong> ${esc(p.ostr)}</p>`);

        if (wZielniku) {
            const w = d.rosliny[id] || {};
            out.push(`<label class="zl-notatka">Moja notatka <textarea data-notatka="${esc(id)}" rows="2" maxlength="2000" class="form-control pal-select" placeholder="gdzie rośnie, kiedy kwitła, co się udało…">${esc(w.notatka || '')}</textarea></label>`);
            out.push(`<div class="zl-akcje"><button type="button" class="btn pal-btn btn-sm" data-zbior="${esc(id)}"><i class="bi bi-basket" aria-hidden="true"></i> Zapisz zbiór${zap[id] ? ` (masz ${zap[id]})` : ''}</button>
                <button type="button" class="btn pal-btn-ghost btn-sm zl-wyczysc" data-usun="${esc(id)}">Usuń z zielnika</button></div>`);
        } else {
            out.push(`<div class="zl-akcje"><button type="button" class="btn pal-btn" data-dodaj="${esc(id)}"><i class="bi bi-plus-lg" aria-hidden="true"></i> Dodaj do Mojego zielnika</button></div>`);
        }
        return out.join('');
    }

    function karta(id, wZielniku, otwarta) {
        const p = R[id], d = stan(), zap = zapasy(d)[id] || 0;
        const n = nazwa(id);
        const ile = p ? p.prz.length : 0;
        const pelne = p ? p.prz.filter(nr => DATA.przepisy[nr].r.every(x => d.rosliny[x])).length : 0;
        const znaczki = [];
        if (p && p.och) znaczki.push(`<span class="zl-znak zl-znak-${esc(p.och.s)}" title="${esc(p.och.n)}">${p.och.s === 'inwazyjny' ? 'inwazyjna' : 'chroniona'}</span>`);
        if (zap) znaczki.push(`<span class="zl-znak zl-znak-zap" title="zapasy w spiżarni">w spiżarni: ${zap}</span>`);
        if (p && p.farb) znaczki.push('<span class="zl-znak" title="Farbiarnia">barwi</span>');
        const img = p && p.img ? `<img src="${esc(p.img)}" alt="" loading="lazy" width="64" height="64" onerror="this.remove()">` : '<span class="zl-img-brak" aria-hidden="true"><i class="ra ra-leaf"></i></span>';
        return `<details class="zl-karta${wZielniku ? '' : ' zl-podglad'}" data-id="${esc(id)}"${otwarta ? ' open' : ''}>
            <summary>${img}<span class="zl-karta-t"><strong>${esc(n)}</strong>${p && p.lat ? `<em>${esc(p.lat)}</em>` : ''}
                <span class="zl-karta-m">${ile ? `${ile} ${ile === 1 ? 'przepis' : 'przepisów'}${pelne ? ` · ${pelne} z kompletem roślin` : ''}` : 'brak przepisów'}</span>
                <span class="zl-znaki">${znaczki.join('')}</span></span><span class="zl-rozwin" aria-hidden="true">Co zrobić? ▾</span></summary>
            <div class="zl-karta-body" data-body="${esc(id)}">${otwarta ? szczegoly(id, wZielniku) : ''}</div>
        </details>`;
    }

    function rysujRosliny() {
        const d = stan();
        const ids = Object.keys(d.rosliny).sort((a, b) => nazwa(a).localeCompare(nazwa(b), 'pl'));
        const otwarte = new Set([...document.querySelectorAll('#zlRosliny details[open]')].map(x => x.dataset.id));
        $('zlRosliny').innerHTML = ids.length ? ids.map(id => karta(id, true, otwarte.has(id))).join('')
            : '<p class="zl-pusto"><i class="ra ra-sprout" aria-hidden="true"></i> Zielnik jest pusty. Dodaj roślinę wyszukiwarką powyżej albo przyciskiem „Dodaj do Mojego zielnika” na stronie rośliny.</p>';
    }
    function otworzKarte(id) {
        const el = document.querySelector(`#zlRosliny details[data-id="${CSS.escape(id)}"]`);
        if (!el) return;
        el.open = true;
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    // szczegóły dorysowywane przy otwarciu (szybciej przy wielu roślinach)
    root.addEventListener('toggle', e => {
        const det = e.target;
        if (!det.classList || !det.classList.contains('zl-karta') || !det.open) return;
        const body = det.querySelector('.zl-karta-body');
        if (!body.innerHTML.trim()) body.innerHTML = szczegoly(det.dataset.id, !det.classList.contains('zl-podglad'));
    }, true);

    let notTimer = null;
    root.addEventListener('input', e => {
        const t = e.target;
        if (!t.dataset || !t.dataset.notatka) return;
        clearTimeout(notTimer);
        notTimer = setTimeout(() => Z.notatka(t.dataset.notatka, t.value), 400);
    });
    root.addEventListener('click', e => {
        const b = e.target.closest('button');
        if (!b || !root.contains(b)) return;
        if (b.dataset.dodaj) {
            const id = b.dataset.dodaj;
            const otworz = !b.closest('#zlCo') && !b.closest('.zl-gil');
            Z.dodaj(id, nazwa(id));
            if (b.closest('.zl-podglad')) history.replaceState(null, '', location.pathname + location.search);
            odswiezWszystko();
            if (otworz) { pokazTab('zlTabRos'); otworzKarte(id); }
            if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
        } else if (b.dataset.usun) {
            const id = b.dataset.usun;
            const ile = stan().zbiory.filter(z => z.id === id).length;
            if (ile && !window.confirm(`Usunąć ${nazwa(id)} z zielnika? Wpisy w spiżarni (${ile}) zostaną.`)) return;
            Z.usun(id);
            odswiezWszystko();
            if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
        } else if (b.dataset.zbior) {
            pokazTab('zlTabSpi');
            ustawRosline(b.dataset.zbior);
            $('zlZbiorForm').scrollIntoView({ behavior: 'smooth', block: 'start' });
            $('zlZbiorForm').elements.czesc.focus({ preventScroll: true });
        } else if (b.dataset.kat !== undefined && b.closest('#zlKat')) {
            katCo = b.dataset.kat; ileCo = Object.assign({}, ILE); rysujCo();
        } else if (b.dataset.wiecej) {
            ileCo[b.dataset.wiecej] += 40; rysujCo();
        } else if (b.dataset.zuzyte) {
            const z = stan().zbiory.find(x => x.uid === b.dataset.zuzyte);
            if (z) Z.zmienZbior(z.uid, { zuzyte: !z.zuzyte });
            rysujSpizarnie(); rysujStat(); rysujRosliny(); rysujCo(); rysujKalendarz();
        } else if (b.dataset.usunZbior) {
            if (!window.confirm('Usunąć ten wpis ze spiżarni?')) return;
            Z.usunZbior(b.dataset.usunZbior);
            rysujSpizarnie(); rysujStat(); rysujRosliny(); rysujCo(); rysujKalendarz();
        }
    });

    // #r=<id> – z przycisku „Co zrobić z tą rośliną?” na stronie rośliny
    function zHash() {
        const m = location.hash.match(/r=([^&]+)/);
        if (!m) return;
        const id = decodeURIComponent(m[1]);
        if (!R[id]) return;
        pokazTab('zlTabRos');
        if (stan().rosliny[id]) { $('zlProp').innerHTML = ''; rysujPropozycje(); otworzKarte(id); return; }
        $('zlProp').innerHTML = `<p class="zl-podglad-h">Podgląd – tej rośliny nie ma jeszcze w Twoim zielniku:</p>${karta(id, false, true)}`;
        $('zlProp').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ---------- zakładka: Spiżarnia ----------
    function wypelnijRosliny() {
        const sel = $('zlZbiorForm').elements.id;
        const d = stan(), wybrana = sel.value;
        const moje = Object.keys(d.rosliny).filter(id => R[id]).sort((a, b) => nazwa(a).localeCompare(nazwa(b), 'pl'));
        const reszta = P.filter(p => !d.rosliny[p.id]);
        sel.innerHTML = '<option value="">— wybierz —</option>' +
            (moje.length ? `<optgroup label="Mój zielnik">${moje.map(id => `<option value="${esc(id)}">${esc(nazwa(id))}</option>`).join('')}</optgroup>` : '') +
            `<optgroup label="Wszystkie rośliny">${reszta.map(p => `<option value="${esc(p.id)}">${esc(p.n)}</option>`).join('')}</optgroup>`;
        if (wybrana && R[wybrana]) sel.value = wybrana;
        ustawCzesci();
    }
    function ustawCzesci() {
        const f = $('zlZbiorForm').elements, p = R[f.id.value];
        const opcje = (p ? p.cz.map(c => [c.k, c.n]) : []).concat([['cale', 'całe ziele'], ['inne', 'inna część']]);
        const by = f.czesc.value;
        f.czesc.innerHTML = opcje.map(([k, n]) => `<option value="${esc(k)}">${esc(n)}</option>`).join('');
        if (opcje.some(o => o[0] === by)) f.czesc.value = by;
        // podpowiedź terminu zbioru wybranej części
        const c = p && p.cz.find(x => x.k === f.czesc.value);
        $('zlZbiorInfo').textContent = c && c.czas ? 'Termin zbioru: ' + c.czas : '';
    }
    function ustawRosline(id) {
        const f = $('zlZbiorForm').elements;
        f.id.value = id;
        ustawCzesci();
    }
    function formularz() {
        const form = $('zlZbiorForm'), f = form.elements;
        f.forma.innerHTML = Object.entries(FORMY).map(([k, v]) => `<option value="${k}">${esc(v.n)}</option>`).join('');
        f.data.value = new Date().toISOString().slice(0, 10);
        f.id.addEventListener('change', ustawCzesci);
        f.czesc.addEventListener('change', ustawCzesci);
        form.addEventListener('submit', e => {
            e.preventDefault();
            if (!f.id.value) { $('zlZbiorInfo').textContent = 'Wybierz roślinę.'; f.id.focus(); return; }
            const il = parseFloat(String(f.ilosc.value).replace(',', '.'));
            Z.dodajZbior({
                id: f.id.value, nazwa: nazwa(f.id.value), czesc: f.czesc.value, forma: f.forma.value,
                ilosc: isFinite(il) && il > 0 ? il : null, jedn: f.jedn.value,
                data: f.data.value || new Date().toISOString().slice(0, 10),
                miejsce: f.miejsce.value.trim().slice(0, 80), notatka: f.notatka.value.trim().slice(0, 200)
            });
            $('zlZbiorInfo').textContent = 'Zapisano: ' + nazwa(f.id.value) + '.';
            f.ilosc.value = ''; f.notatka.value = '';
            odswiezWszystko();
            if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
        });
        $('zlPokazZuzyte').addEventListener('change', rysujSpizarnie);
        $('zlEtykiety').addEventListener('click', drukujEtykiety);
    }
    function rysujSpizarnie() {
        const d = stan(), pokaz = $('zlPokazZuzyte').checked;
        const lista = d.zbiory.filter(z => pokaz || !z.zuzyte).map(z => Object.assign({}, z, { _do: zuzyjDo(z) }))
            .sort((a, b) => (a.zuzyte - b.zuzyte) || String(a._do).localeCompare(String(b._do)));
        if (!lista.length) {
            $('zlSpizarnia').innerHTML = `<p class="zl-pusto">${d.zbiory.length ? 'Wszystko zużyte. ' : ''}Zapisz tu swoje zbiory i zapasy (susz, nalewki, oleje) – Kwiatownik podpowie, co zużyć najpierw i wydrukuje etykiety.</p>`;
            $('zlEtykiety').disabled = true;
            return;
        }
        $('zlEtykiety').disabled = !lista.some(z => !z.zuzyte);
        $('zlSpizarnia').innerHTML = '<ul class="zl-spi">' + lista.map(z => {
            const dni = z._do ? dniDo(z._do) : null;
            const klasa = z.zuzyte ? 'zuzyte' : dni !== null && dni < 0 ? 'po' : dni !== null && dni <= 30 ? 'wkrotce' : '';
            const termin = z.zuzyte ? 'zużyte' : dni === null ? '' : dni < 0 ? `po terminie (${dataPl(z._do)})` : dni <= 30 ? `zużyj do ${dataPl(z._do)} · ${dni} dni` : `zużyj do ${dataPl(z._do)}`;
            const il = z.ilosc ? `${String(z.ilosc).replace('.', ',')} ${esc(z.jedn || '')}` : '';
            return `<li class="${klasa}">
                <div class="zl-spi-t"><a href="${linkRosliny(z.id)}">${esc(nazwa(z.id))}</a> <span>${esc(czescNazwa(z.id, z.czesc))} · ${esc((FORMY[z.forma] || FORMY.inne).n)}${il ? ' · ' + il : ''}</span></div>
                <div class="zl-spi-m"><span><i class="bi bi-calendar-check" aria-hidden="true"></i> ${dataPl(z.data)}</span>${z.miejsce ? `<span><i class="bi bi-geo-alt" aria-hidden="true"></i> ${esc(z.miejsce)}</span>` : ''}<span class="zl-termin">${termin}</span></div>
                ${z.notatka ? `<div class="zl-spi-n">${esc(z.notatka)}</div>` : ''}
                <div class="zl-spi-a"><button type="button" class="zl-mini" data-zuzyte="${esc(z.uid)}">${z.zuzyte ? 'przywróć' : 'zużyte'}</button><button type="button" class="zl-mini zl-wyczysc" data-usun-zbior="${esc(z.uid)}" aria-label="Usuń wpis">usuń</button></div>
            </li>`;
        }).join('') + '</ul>';
    }

    // etykiety na słoiki (coś do wydruku na papierze samoprzylepnym)
    function drukujEtykiety() {
        const d = stan();
        const lista = d.zbiory.filter(z => !z.zuzyte);
        if (!lista.length) return;
        $('zlDruk').innerHTML = '<div class="zl-etykiety">' + lista.map(z => {
            const p = R[z.id] || {};
            const doD = zuzyjDo(z);
            return `<div class="zl-ety"><div class="zl-ety-n">${esc(nazwa(z.id))}</div>${p.lat ? `<div class="zl-ety-l">${esc(p.lat)}</div>` : ''}
                <div class="zl-ety-c">${esc(czescNazwa(z.id, z.czesc))} · ${esc((FORMY[z.forma] || FORMY.inne).n)}</div>
                <div class="zl-ety-d">zebrano: ${dataPl(z.data)}${doD ? `<br>zużyj do: ${dataPl(doD)}` : ''}</div>
                ${z.miejsce ? `<div class="zl-ety-m">${esc(z.miejsce)}</div>` : ''}<div class="zl-ety-k">Kwiatownik</div></div>`;
        }).join('') + '</div>';
        document.body.classList.add('zl-drukuje');
        const koniec = () => { document.body.classList.remove('zl-drukuje'); window.removeEventListener('afterprint', koniec); };
        window.addEventListener('afterprint', koniec);
        window.print();
        setTimeout(koniec, 1500);
    }

    // ---------- zakładka: Co zrobić ----------
    function rysujCo() {
        const d = stan(), moje = d.rosliny, zap = zapasy(d);
        const ids = Object.keys(moje);
        if (!ids.length) {
            $('zlKat').innerHTML = '';
            $('zlCo').innerHTML = '<p class="zl-pusto">Dodaj kilka roślin, a pokażę, co możesz z nich zrobić.</p>';
            return;
        }
        const wszystkie = DATA.przepisy.map((p, nr) => {
            const ma = p.r.filter(x => moje[x]);
            if (!ma.length) return null;
            const brak = p.r.filter(x => !moje[x]);
            const zapasem = ma.filter(x => zap[x]).length;
            return { p, nr, ma, brak, zapasem, wynik: -brak.length * 10 + zapasem * 2 + (ulubione.has(p.t) ? 3 : 0) + Math.min(ma.length, 3) };
        }).filter(Boolean);
        const naKat = {};
        wszystkie.forEach(x => { naKat[x.p.k] = (naKat[x.p.k] || 0) + 1; });
        $('zlKat').innerHTML = `<button type="button" data-kat="all" class="zl-chip${katCo === 'all' ? ' on' : ''}" aria-pressed="${katCo === 'all'}">Wszystkie <small>${wszystkie.length}</small></button>` +
            Object.keys(DATA.kategorie).filter(k => naKat[k]).map(k => `<button type="button" data-kat="${k}" class="zl-chip${katCo === k ? ' on' : ''}" aria-pressed="${katCo === k}">${esc(DATA.kategorie[k])} <small>${naKat[k]}</small></button>`).join('');
        const lista = wszystkie.filter(x => katCo === 'all' || x.p.k === katCo).sort((a, b) => b.wynik - a.wynik || a.p.t.localeCompare(b.p.t, 'pl'));
        const out = [];

        // inne możliwości: barwienie
        const farb = ids.filter(id => R[id] && R[id].farb), pal = ids.filter(id => R[id] && R[id].pal);
        if (katCo === 'all' && (farb.length || pal.length)) {
            out.push('<div class="zl-mozl-wrap">' +
                (farb.length ? `<div class="zl-mozl zl-mozl-lista"><i class="bi bi-flower3" aria-hidden="true"></i> Barwienie wełny i tkanin<small>${farb.map(id => `<a href="/farbiarnia/?r=${encodeURIComponent(R[id].farb)}">${esc(nazwa(id))}</a>`).join(', ')}</small></div>` : '') +
                (pal.length ? `<div class="zl-mozl zl-mozl-lista"><i class="bi bi-palette" aria-hidden="true"></i> Ziołowe farbowanie włosów<small><a href="/paleta/">Paleta Barw</a>: ${pal.map(id => esc(nazwa(id))).join(', ')}</small></div>` : '') +
                '</div>');
        }

        // „dodaj jedną roślinę, a odblokujesz…” – podpowiedź, co warto zebrać lub posadzić
        const klucz = {};
        wszystkie.forEach(x => { if (x.brak.length === 1) klucz[x.brak[0]] = (klucz[x.brak[0]] || 0) + 1; });
        const top = Object.entries(klucz).filter(([id]) => R[id]).sort((a, b) => b[1] - a[1]).slice(0, 5);
        if (top.length && katCo === 'all') {
            out.push(`<div class="zl-info"><p><i class="bi bi-lightbulb" aria-hidden="true"></i> <strong>Warto dozbierać:</strong> brakuje Ci jednej rośliny do kolejnych przepisów.</p><div class="zl-chipy">` +
                top.map(([id, n]) => `<button type="button" class="zl-chip" data-dodaj="${esc(id)}">+ ${esc(nazwa(id))} <small>+${n}</small></button>`).join('') + '</div></div>');
        }

        const sekcja = (klucz, tytul, cale) => {
            if (!cale.length) return '';
            const el = cale.slice(0, ileCo[klucz]);
            const wiecej = cale.length > el.length ? `<button type="button" class="btn pal-btn-ghost btn-sm" data-wiecej="${klucz}">Pokaż więcej (${cale.length - el.length})</button>` : '';
            return `<h4>${tytul} <span class="pal-muted">(${cale.length})</span></h4><ul class="zl-co">` + el.map(x => {
            const tagi = x.ma.map(id => `<span class="zl-tag${zap[id] ? ' zap' : ''}" title="${zap[id] ? 'masz zapas w spiżarni' : 'w Twoim zielniku'}">${esc(nazwa(id))}</span>`).join('') +
                x.brak.map(id => `<span class="zl-tag brak" title="brakuje">${esc(nazwa(id))}</span>`).join('');
            return `<li><a href="${linkPrzepisu(x.p.t)}">${ulubione.has(x.p.t) ? '★ ' : ''}${esc(x.p.t)}</a> <small class="pal-muted">${esc(DATA.kategorie[x.p.k] || '')}</small><div class="zl-tagi">${tagi}</div></li>`;
            }).join('') + '</ul>' + wiecej;
        };
        out.push(sekcja('pelne', 'Masz wszystkie rośliny', lista.filter(x => !x.brak.length)));
        out.push(sekcja('jedna', 'Brakuje jednej rośliny', lista.filter(x => x.brak.length === 1)));
        out.push(sekcja('kilka', 'Brakuje kilku roślin', lista.filter(x => x.brak.length > 1)));
        if (!lista.length) out.push('<p class="pal-muted">Brak przepisów w tej kategorii.</p>');
        $('zlCo').innerHTML = out.join('');
    }

    // ---------- zakładka: Kalendarz ----------
    function rysujKalendarz() {
        const d = stan(), ids = Object.keys(d.rosliny).filter(id => R[id]).sort((a, b) => nazwa(a).localeCompare(nazwa(b), 'pl'));
        const m = new Date().getMonth() + 1, nast = m % 12 + 1;
        if (!ids.length) {
            $('zlTeraz').innerHTML = '<p class="zl-pusto">Dodaj rośliny, a zobaczysz, kiedy je zbierać i co robić w ogrodzie.</p>';
            $('zlKalendarz').innerHTML = '';
            return;
        }
        const zadania = mm => {
            const out = [];
            ids.forEach(id => R[id].kal.forEach(t => { if (t.m.includes(mm)) out.push({ id, t }); }));
            ids.forEach(id => R[id].cz.forEach(c => {
                // część bez osobnej pracy w kalendarzu, ale z nazwą miesiąca w terminie zbioru
                const n = norm(c.czas);
                if (n.includes(norm(MIES[mm - 1]).slice(0, 5)) && !R[id].kal.some(t => t.m.includes(mm) && norm(t.c).includes(norm(c.n).slice(0, 4))))
                    out.push({ id, t: { c: 'Zbiór: ' + c.n, o: c.czas } });
            }));
            return out;
        };
        const li = arr => arr.map(({ id, t }) => `<li><a href="${linkRosliny(id)}">${esc(nazwa(id))}</a> – <strong>${esc(t.c)}</strong>${t.o ? `<span>${esc(t.o)}</span>` : ''}</li>`).join('');
        const teraz = zadania(m), potem = zadania(nast);
        const pilne = d.zbiory.filter(z => !z.zuzyte && zuzyjDo(z) && dniDo(zuzyjDo(z)) <= 31);
        let html = `<div class="zl-teraz"><div><h4><i class="bi bi-sun" aria-hidden="true"></i> ${MIES[m - 1][0].toUpperCase() + MIES[m - 1].slice(1)} – teraz</h4>${teraz.length ? `<ul>${li(teraz)}</ul>` : '<p class="pal-muted">W tym miesiącu Twoje rośliny odpoczywają.</p>'}`;
        if (pilne.length) html += `<h5>Ze spiżarni zużyj najpierw</h5><ul>${pilne.map(z => `<li><strong>${esc(nazwa(z.id))}</strong> – ${esc(czescNazwa(z.id, z.czesc))}, ${esc((FORMY[z.forma] || FORMY.inne).n)} <span>${dniDo(zuzyjDo(z)) < 0 ? 'po terminie' : 'do ' + dataPl(zuzyjDo(z))}</span></li>`).join('')}</ul>`;
        html += `</div><div><h4><i class="bi bi-calendar-event" aria-hidden="true"></i> ${MIES[nast - 1][0].toUpperCase() + MIES[nast - 1].slice(1)} – przygotuj się</h4>${potem.length ? `<ul>${li(potem)}</ul>` : '<p class="pal-muted">Nic zaplanowanego.</p>'}</div></div>`;
        $('zlTeraz').innerHTML = html;

        // roczna siatka: roślina × miesiąc
        const wiersze = ids.map(id => {
            const mies = Array.from({ length: 12 }, (_, i) => R[id].kal.filter(t => t.m.includes(i + 1)).map(t => t.c));
            return `<div class="zl-kal-n"><a href="${linkRosliny(id)}">${esc(nazwa(id))}</a></div>` + mies.map((t, i) =>
                `<div class="zl-kal-c${t.length ? ' on' : ''}${i + 1 === m ? ' teraz' : ''}"${t.length ? ` title="${esc(MIES[i] + ': ' + t.join('; '))}"` : ''}>${t.length ? `<span class="visually-hidden">${esc(MIES[i] + ': ' + t.join('; '))}</span>` : ''}</div>`).join('');
        }).join('');
        $('zlKalendarz').innerHTML = `<h4>Rok w Twoim zielniku</h4><div class="zl-kal" role="table" aria-label="Prace przy roślinach w kolejnych miesiącach">
            <div class="zl-kal-n zl-kal-h"></div>${MIES_1.map((x, i) => `<div class="zl-kal-h${i + 1 === m ? ' teraz' : ''}" title="${MIES[i]}">${x}</div>`).join('')}${wiersze}</div>
            <p class="pal-muted small">Zielone pole = zbiór lub praca w ogrodzie. Najedź lub przytrzymaj, aby zobaczyć szczegóły (pełne opisy w karcie rośliny).</p>`;
    }

    // ---------- kopia zapasowa ----------
    function kopia() {
        $('zlEksport').addEventListener('click', () => {
            const d = stan();
            const blob = new Blob([JSON.stringify({ kwiatownik: 'moj_zielnik', zapisano: new Date().toISOString(), dane: d }, null, 1)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'moj-zielnik-' + new Date().toISOString().slice(0, 10) + '.json';
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(() => URL.revokeObjectURL(a.href), 2000);
            $('zlKopiaInfo').textContent = 'Zapisano plik ' + a.download + '.';
        });
        $('zlImport').addEventListener('change', e => {
            const f = e.target.files && e.target.files[0];
            if (!f) return;
            const rd = new FileReader();
            rd.onload = () => {
                try {
                    const j = JSON.parse(rd.result);
                    const nowe = j && j.dane ? j.dane : j;
                    if (!nowe || typeof nowe.rosliny !== 'object' || !Array.isArray(nowe.zbiory)) throw new Error('format');
                    const d = stan();
                    let r = 0, z = 0;
                    Object.entries(nowe.rosliny).forEach(([id, w]) => {
                        if (typeof id !== 'string' || id.length > 80) return;
                        if (!d.rosliny[id]) r++;
                        d.rosliny[id] = Object.assign({ dodano: new Date().toISOString().slice(0, 10), notatka: '' }, d.rosliny[id] || {}, w && typeof w === 'object' ? {
                            nazwa: String(w.nazwa || (d.rosliny[id] || {}).nazwa || '').slice(0, 80),
                            notatka: String(w.notatka || (d.rosliny[id] || {}).notatka || '').slice(0, 2000),
                            dodano: String(w.dodano || (d.rosliny[id] || {}).dodano || '').slice(0, 10)
                        } : {});
                    });
                    const uidy = new Set(d.zbiory.map(x => x.uid));
                    nowe.zbiory.forEach(x => {
                        if (!x || typeof x !== 'object' || !x.id || uidy.has(x.uid)) return;
                        d.zbiory.push({
                            uid: String(x.uid || Date.now().toString(36) + Math.random().toString(36).slice(2, 7)).slice(0, 30), id: String(x.id).slice(0, 80),
                            czesc: String(x.czesc || '').slice(0, 30), forma: FORMY[x.forma] ? x.forma : 'inne', ilosc: Number(x.ilosc) || null, jedn: String(x.jedn || '').slice(0, 10),
                            data: /^\d{4}-\d{2}-\d{2}$/.test(x.data) ? x.data : new Date().toISOString().slice(0, 10),
                            miejsce: String(x.miejsce || '').slice(0, 80), notatka: String(x.notatka || '').slice(0, 200), zuzyte: !!x.zuzyte
                        });
                        z++;
                    });
                    Z.zapisz(d);
                    $('zlKopiaInfo').textContent = `Wczytano: ${r} nowych roślin, ${z} wpisów spiżarni.`;
                    odswiezWszystko();
                    if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
                } catch (err) {
                    $('zlKopiaInfo').textContent = 'To nie jest plik kopii Mojego zielnika.';
                }
                e.target.value = '';
            };
            rd.readAsText(f);
        });
        $('zlWyczysc').addEventListener('click', () => {
            if (!window.confirm('Na pewno usunąć wszystkie rośliny i wpisy spiżarni z tej przeglądarki? Najpierw możesz zapisać kopię.')) return;
            Z.zapisz({ wersja: 1, rosliny: {}, zbiory: [] });
            $('zlKopiaInfo').textContent = 'Zielnik wyczyszczony.';
            odswiezWszystko();
            if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
        });
    }
})();
