/* =====================================================================
   PALETA BARW ZIELARZA – model koloru (bez DOM; działa też w Node do testów)
   ---------------------------------------------------------------------
   Barwnik roślinny nie rozjaśnia włosa, tylko się na nim osadza – jak przezroczysty
   filtr. Dlatego kolor po farbowaniu liczymy mnożąco w liniowym RGB (prawo Beera–Lamberta):
       wynik = włos × Π (kolor_zioła ^ a)
   gdzie a = udział zioła w paście × siła zioła × chłonność włosa × czas.
   Siwe i pigmentowane włosy liczone są osobno (henna na siwym = jaskrawa miedź,
   na ciemnym – tylko refleks), a podgląd miesza je według % siwizny.
   ===================================================================== */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.KwPaletaModel = api;
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ---------- kolory ----------
    function hexToRgb(hex) {
        const h = String(hex || '#000000').replace('#', '');
        const n = parseInt(h.length === 3 ? h.split('').map(c => c + c).join('') : h, 16);
        return [(n >> 16 & 255) / 255, (n >> 8 & 255) / 255, (n & 255) / 255];
    }
    const toLin = v => v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    const toSrgb = v => v <= 0.0031308 ? 12.92 * v : 1.055 * Math.pow(v, 1 / 2.4) - 0.055;
    const clamp01 = v => Math.min(1, Math.max(0, v));
    const lin = hex => hexToRgb(hex).map(toLin);
    function hexFromLin(c) {
        return '#' + c.map(v => Math.round(clamp01(toSrgb(clamp01(v))) * 255).toString(16).padStart(2, '0')).join('');
    }
    function labFromLin(c) {
        const [r, g, b] = c;
        const X = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047;
        const Y = (0.2126 * r + 0.7152 * g + 0.0722 * b);
        const Z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883;
        const f = t => t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116;
        const fx = f(X), fy = f(Y), fz = f(Z);
        return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
    }
    const labFromHex = hex => labFromLin(lin(hex));
    function deltaE(l1, l2) { return Math.hypot(l1[0] - l2[0], l1[1] - l2[1], l1[2] - l2[2]); }
    // Do doboru: jasność liczy się słabiej niż odcień (podobnie jak w normie CMC l:c z farbiarstwa tekstyliów) –
    // ważniejsze jest trafienie w odcień, bo zioła i tak nie rozjaśnią włosa.
    function deltaEDobor(l1, l2) { return Math.hypot((l1[0] - l2[0]) / 1.5, l1[1] - l2[1], l1[2] - l2[2]); }
    function mixLin(a, b, t) { return a.map((v, i) => v * (1 - t) + b[i] * t); }

    // ---------- profil włosa → chłonność ----------
    const POROWATOSC = { niska: 0.75, srednia: 1.0, wysoka: 1.3 };
    const GRUBOSC = { cienkie: 1.12, srednie: 1.0, grube: 0.88 };
    const GRAMY_GRUBOSC = { cienkie: 0.8, srednie: 1.0, grube: 1.25 };
    const OPORNOSC_SIWYCH = 0.9;      // siwe włosy zwykle słabiej łapią barwnik
    const SLABE_WIAZANIE = 0.55;      // indygo/katam bez podkładu z henny

    function chlonnosc(profil) {
        let k = (POROWATOSC[profil.porowatosc] || 1) * (GRUBOSC[profil.grubosc] || 1);
        if (profil.chemia && profil.chemia.rozjasniane) k *= 1.15;   // rozjaśniony włos jest porowaty
        const p = profil.produkty || {};
        if (p.silikony || p.oleje || p.suchy_szampon) k *= 0.85;      // osad blokuje barwnik (bez mycia oczyszczającego)
        return k;
    }
    function czynnikCzasu(godziny) {
        const h = Math.max(0.25, Number(godziny) || 3.5);
        return (1 - Math.exp(-h / 1.6)) / (1 - Math.exp(-3.5 / 1.6));
    }

    function kolorZiola(z, ph, zwiazane) {
        if (z.wymaga_podkladu && !zwiazane && z.kolor_bez_podkladu) return z.kolor_bez_podkladu;
        if (z.ph && ph && z.ph[ph]) return z.ph[ph];
        return z.kolor;
    }

    // Jedno pasmo (siwe albo pigmentowane) przez cały plan farbowania.
    // Część światła odbija się od powierzchni łuski bez przejścia przez barwnik (połysk) – tej części
    // zioła nie barwią. Bez tego ciemne i średnie włosy wychodziłyby po hennie prawie czarne.
    function polysk(baza) { return Math.min(0.02, 0.35 * Math.min(...baza)); }

    function pasmo(bazaHex, siwe, profil, plan, Z) {
        const baza = lin(bazaHex);
        const s0 = polysk(baza);
        let c = baza.map(v => v - s0);
        const k = chlonnosc(profil) * (siwe ? OPORNOSC_SIWYCH : 1);
        let zwiazane = !!(profil.produkty && profil.produkty.henna);
        for (const krok of plan.kroki || []) {
            const sk = (krok.skladniki || []).filter(s => Z[s.id] && s.czesci > 0);
            const suma = sk.reduce((s, x) => s + x.czesci, 0);
            if (!suma) continue;
            const udzialHenny = sk.filter(s => s.id === 'henna').reduce((s, x) => s + x.czesci, 0) / suma;
            const zwiazaneKrok = zwiazane || udzialHenny >= 0.25;
            const tf = czynnikCzasu(krok.godziny);
            for (const s of sk) {
                const z = Z[s.id];
                let a = (s.czesci / suma) * z.sila * k * tf;
                if (z.wymaga_podkladu && !zwiazaneKrok) a *= SLABE_WIAZANIE;
                const T = lin(kolorZiola(z, s.ph, zwiazaneKrok));
                c = c.map((v, i) => v * Math.pow(Math.max(T[i], 1e-4), a));
            }
            if (udzialHenny >= 0.25) zwiazane = true;
        }
        for (const p of plan.plukanki || []) {
            const z = Z[p.id];
            if (!z || !(p.razy > 0)) continue;
            const a = z.sila * Math.pow(p.razy, 0.75) * k;
            const T = lin(kolorZiola(z, p.ph, zwiazane));
            c = c.map((v, i) => v * Math.pow(Math.max(T[i], 1e-4), a));
        }
        return c.map(v => v + s0);
    }

    function bazaWlosa(profil, dane) {
        const lv = dane.poziomy.find(p => p.poziom === Number(profil.poziom)) || dane.poziomy[5];
        return { pig: lv.hex, siwy: dane.siwy };
    }

    function przewiduj(profil, plan, Z, dane) {
        const baza = bazaWlosa(profil, dane);
        const g = clamp01((Number(profil.siwizna) || 0) / 100);
        const przedPig = lin(baza.pig), przedSiwy = lin(baza.siwy);
        const poPig = pasmo(baza.pig, false, profil, plan, Z);
        const poSiwy = pasmo(baza.siwy, true, profil, plan, Z);
        return {
            siwizna: g,
            przed: { pig: baza.pig, siwy: baza.siwy, srednio: hexFromLin(mixLin(przedPig, przedSiwy, g)) },
            po: { pig: hexFromLin(poPig), siwy: hexFromLin(poSiwy), srednio: hexFromLin(mixLin(poPig, poSiwy, g)) },
            _lin: { poPig, poSiwy, przedPig, przedSiwy }
        };
    }

    // ---------- dobór mieszanki do koloru docelowego ----------
    function* podzbiory(arr, k, start = 0, acc = []) {
        if (acc.length === k) { yield acc.slice(); return; }
        for (let i = start; i < arr.length; i++) { acc.push(arr[i]); yield* podzbiory(arr, k, i + 1, acc); acc.pop(); }
    }
    function proporcje(n) {          // w częściach na 10
        if (n === 1) return [[10]];
        if (n === 2) return [1, 2, 3, 4, 5, 6, 7, 8, 9].map(a => [a, 10 - a]);
        const out = [];
        for (let a = 1; a <= 8; a++) for (let b = 1; a + b <= 9; b++) out.push([a, b, 10 - a - b]);
        return out;
    }
    const PH = ['kwasne', 'obojetne', 'zasadowe'];

    function ocena(profil, plan, Z, dane, celLab) {
        const w = przewiduj(profil, plan, Z, dane);
        const g = w.siwizna;
        const ePig = deltaEDobor(labFromLin(w._lin.poPig), celLab);
        const eSiwy = deltaEDobor(labFromLin(w._lin.poSiwy), celLab);
        return { wynik: w, dE: ePig * (1 - g) + eSiwy * g, ePig, eSiwy };
    }

    // Klucz różnorodności: drobne dodatki (do 20% pasty) nie tworzą „nowej” propozycji.
    function klucz(plan) {
        const ids = [];
        (plan.kroki || []).forEach((k, i) => {
            const suma = k.skladniki.reduce((s, x) => s + x.czesci, 0) || 1;
            k.skladniki.forEach(s => { if (s.czesci / suma > 0.2) ids.push(i + ':' + s.id); });
        });
        (plan.plukanki || []).forEach(p => ids.push('p:' + p.id));
        return ids.sort().join('|');
    }

    const TRWALE = new Set(['trwała']);

    function dobierz(profil, celHex, Z, dane, opcje = {}) {
        const celLab = labFromHex(celHex);
        const ziola = Object.values(Z).filter(z => {
            if (opcje.tylkoRodzime && !z.rodzime) return false;
            if (opcje.bezTrwalych && TRWALE.has(z.trwalosc)) return false;
            if (opcje.wykluczone && opcje.wykluczone.includes(z.id)) return false;
            return true;
        });
        const pasty = opcje.tylkoPlukanki ? [] : ziola.filter(z => z.rodzaj === 'pasta' || z.rodzaj === 'olej');
        const plukanki = ziola.filter(z => z.rodzaj === 'plukanka');
        const wyniki = [];
        const KARA_PEWNOSC = { potwierdzone: 0, tradycyjne: 0.5, niepewne: 1.2 };
        const dodaj = (plan, kara) => {
            const o = ocena(profil, plan, Z, dane, celLab);
            // przy podobnym efekcie wygrywa to, co lepiej opisane i łagodniejsze (nietrwałe)
            [...plan.kroki.flatMap(k => k.skladniki), ...plan.plukanki].forEach(s => {
                kara += (KARA_PEWNOSC[Z[s.id].pewnosc] || 0) + (Z[s.id].trwalosc === 'trwała' ? 0.6 : 0);
            });
            wyniki.push({ plan, dE: o.dE, wynik: o.wynik, score: o.dE + kara });
        };
        const wariantyPh = sub => {
            const zph = sub.filter(z => z.ph);
            if (!zph.length) return [{}];
            return PH.map(ph => Object.fromEntries(zph.map(z => [z.id, ph])));
        };

        // A) pasta jednoetapowa: 1–3 zioła
        const BAZY = new Set(['henna', 'cassia', 'indygo']);
        const DLUGIE = new Set(['henna', 'cassia', 'indygo', 'katam', 'urzet', 'amla', 'marzanna', 'sandalowiec']);
        for (let n = 1; n <= 3; n++) {
            for (const sub of podzbiory(pasty, n)) {
                if (n === 3 && !sub.some(z => BAZY.has(z.id))) continue;   // 3 zioła tylko wokół henny/cassii/indygo
                for (const phMap of wariantyPh(sub)) {
                    for (const prop of proporcje(n)) {
                        if (sub.some((z, i) => z.max_udzial && prop[i] / 10 > z.max_udzial + 1e-9)) continue;
                        // indygo/katam/urzet bez podkładu (henna < 25% i włosy nie po hennie) – nie proponujemy
                        const hennaUdzial = sub.reduce((a, z, i) => a + (z.id === 'henna' ? prop[i] : 0), 0) / 10;
                        if (sub.some(z => z.wymaga_podkladu) && hennaUdzial < 0.25 && !(profil.produkty && profil.produkty.henna)) continue;
                        const plan = { kroki: [{ godziny: sub.some(z => DLUGIE.has(z.id)) ? 3.5 : 2, skladniki: sub.map((z, i) => ({ id: z.id, czesci: prop[i], ph: phMap[z.id] })) }], plukanki: [] };
                        dodaj(plan, (n - 1) * 0.6);
                    }
                }
            }
        }
        // B) dwuetapowo: najpierw henna (z dodatkiem), potem indygo/katam
        const jest = id => pasty.some(z => z.id === id);
        if (jest('henna')) {
            const krok1 = [[['henna', 10]], [['henna', 5], ['cassia', 5]], [['henna', 8], ['marzanna', 2]], [['henna', 9], ['amla', 1]]]
                .filter(k => k.every(([id]) => jest(id)));
            const krok2 = [[['indygo', 10]], [['indygo', 5], ['henna', 5]], [['katam', 10]], [['indygo', 5], ['katam', 5]], [['urzet', 10]], [['indygo', 7], ['amla', 3]]]
                .filter(k => k.every(([id]) => jest(id)));
            for (const a of krok1) for (const b of krok2) {
                const plan = { kroki: [
                    { godziny: 3.5, skladniki: a.map(([id, c]) => ({ id, czesci: c })) },
                    { godziny: 3.5, skladniki: b.map(([id, c]) => ({ id, czesci: c })) }], plukanki: [] };
                dodaj(plan, 1.2 + (a.length + b.length - 2) * 0.6);
            }
        }
        // C) same płukanki: 1–2 zioła, 3/6/10 płukań
        for (let n = 1; n <= 2; n++) {
            for (const sub of podzbiory(plukanki, n)) {
                for (const phMap of wariantyPh(sub)) {
                    for (const razy of [3, 6, 10]) {
                        dodaj({ kroki: [], plukanki: sub.map(z => ({ id: z.id, razy, ph: phMap[z.id] })) }, (n - 1) * 0.6 + razy * 0.08);
                    }
                }
            }
        }

        wyniki.sort((a, b) => a.score - b.score);
        const out = [], widziane = new Set();
        for (const w of wyniki) {
            const kl = klucz(w.plan);
            if (widziane.has(kl)) continue;
            widziane.add(kl);
            out.push(w);
            if (out.length >= (opcje.ile || 3)) break;
        }
        // łagodna alternatywa: najlepsze same płukanki, jeśli nie trafiły do czołówki
        if (!opcje.tylkoPlukanki && !out.some(w => !w.plan.kroki.length)) {
            const plk = wyniki.find(w => !w.plan.kroki.length);
            if (plk && plk.dE < 20 && plk.dE < Math.max(6, out[0].dE * 1.35)) out.push(Object.assign({ lagodna: true }, plk));
        }
        const bazaL = labFromHex(bazaWlosa(profil, dane).pig)[0];
        return {
            cel: celHex, wyniki: out, oceniono: wyniki.length,
            jasniejszyNizWlos: celLab[0] > bazaL + 4 && (Number(profil.siwizna) || 0) < 50
        };
    }

    function jakosc(dE) {
        if (dE < 6) return { klasa: 'b-blisko', tekst: 'bardzo blisko' };
        if (dE < 12) return { klasa: 'blisko', tekst: 'blisko' };
        if (dE < 20) return { klasa: 'przyblizenie', tekst: 'w przybliżeniu' };
        return { klasa: 'poza', tekst: 'poza zasięgiem ziół' };
    }

    // ---------- receptura ----------
    function gramy(profil, dane) {
        const d = dane.dlugosci.find(x => x.klucz === profil.dlugosc) || dane.dlugosci[1];
        const f = GRAMY_GRUBOSC[profil.grubosc] || 1;
        const r5 = v => Math.max(5, Math.round(v * f / 5) * 5);
        return [r5(d.gramy[0]), r5(d.gramy[1])];
    }

    function trwalosc(plan, Z) {
        const ids = [];
        (plan.kroki || []).forEach(k => k.skladniki.forEach(s => ids.push(s.id)));
        (plan.plukanki || []).forEach(p => ids.push(p.id));
        const t = ids.map(id => Z[id] && Z[id].trwalosc);
        if (t.includes('trwała')) return 'trwała';
        if (t.includes('półtrwała')) return 'półtrwała';
        return 'zmywalna';
    }

    function ostrzezenia(profil, plan, Z) {
        const out = [];   // {poziom: 'stop'|'uwaga'|'info', tekst}
        const ch = profil.chemia || {}, p = profil.produkty || {};
        const ids = new Set();
        (plan.kroki || []).forEach(k => k.skladniki.forEach(s => ids.add(s.id)));
        (plan.plukanki || []).forEach(x => ids.add(x.id));
        const ma = id => ids.has(id);
        const trwale = [...ids].some(id => Z[id] && Z[id].trwalosc === 'trwała');
        const podklad = [...ids].some(id => Z[id] && Z[id].wymaga_podkladu);

        if (p.uczulenie_ppd)
            out.push({ poziom: 'stop', tekst: 'Miałeś(-aś) reakcję na farbę z PPD lub „czarną hennę”. Osoby uczulone na PPD mogą reagować także na pokrewne związki – przed każdym ziołem zrób próbę uczuleniową na skórze (48 h), a przy wątpliwościach skonsultuj się z dermatologiem.' });
        if (p.czarna_henna)
            out.push({ poziom: 'stop', tekst: '„Czarna henna” zwykle zawiera PPD lub sole metali. Nie nakładaj jej ponownie; przed ziołami zrób test pasma.' });
        if (p.henna_zlozona || p.farby_progresywne)
            out.push({ poziom: 'stop', tekst: 'Na włosach mogą być sole metali (henna „złożona”, odsiwiacze stopniowe). Mogą reagować z innymi farbami, rozjaśniaczem i trwałą: nieprzewidywalny kolor, gorąco, łamliwość. Najpierw test pasma; jeśli pasmo reaguje, nie farbuj – poczekaj, aż włosy odrosną.' });
        if (podklad && ch.rozjasniane)
            out.push({ poziom: 'uwaga', tekst: 'Indygo, katam lub urzet na rozjaśnionych włosach może dać zielonkawy odcień. Zacznij od pasma.' });
        if (podklad)
            out.push({ poziom: 'info', tekst: 'Rozjaśnianie włosów po indygo lub katamie może dać zielone, nieprzewidywalne tony.' });
        if (podklad && !(p.henna) && !(plan.kroki || []).some(k => k.skladniki.some(s => s.id === 'henna')))
            out.push({ poziom: 'uwaga', tekst: 'Indygo/katam bez henny słabo się trzyma i bywa niebieskozielone – dodaj hennę albo nałóż ją wcześniej.' });
        if (trwale && (ch.farba || ch.trwala || ch.prostowanie || ch.keratyna))
            out.push({ poziom: 'uwaga', tekst: 'Włosy po zabiegach chemicznych mogą chłonąć barwnik nierówno. Zrób test pasma (włosy z grzebienia) przed nałożeniem na całą głowę.' });
        if (ma('henna') || ma('cassia'))
            out.push({ poziom: 'info', tekst: 'Henna i cassia mogą rozluźnić skręt loków.' });
        if (ma('henna'))
            out.push({ poziom: 'info', tekst: 'Henna jest trwała – późniejsze rozjaśnienie lub zmiana na chłodny kolor będą bardzo trudne.' });
        if (p.silikony || p.oleje || p.suchy_szampon)
            out.push({ poziom: 'info', tekst: 'Przed farbowaniem umyj włosy szamponem oczyszczającym – silikony, oleje i suchy szampon blokują barwnik.' });
        for (const id of ids) {
            const z = Z[id];
            (z && z.ostrzezenia || []).forEach(t => out.push({ poziom: 'uwaga', tekst: z.nazwa + ': ' + t }));
        }
        if ([...(plan.kroki || []).flatMap(k => k.skladniki), ...(plan.plukanki || [])].some(s => s.ph === 'zasadowe'))
            out.push({ poziom: 'info', tekst: 'Zasadowe pH (soda) szorstkuje łuskę włosa – trzymaj krótko i zakończ kwaśną płukanką lub odżywką.' });
        out.push({ poziom: 'info', tekst: 'Zawsze: test pasma przed całą głową, próba uczuleniowa na skórze 48 h wcześniej, rękawiczki. Nie nakładaj na brwi i rzęsy.' });
        const seen = new Set();
        return out.filter(o => !seen.has(o.tekst) && seen.add(o.tekst));
    }

    function receptura(profil, plan, Z, dane) {
        const [gMin, gMax] = gramy(profil, dane);
        const kroki = (plan.kroki || []).map((k, i) => {
            const suma = k.skladniki.reduce((s, x) => s + x.czesci, 0) || 1;
            return {
                nr: i + 1, godziny: k.godziny,
                skladniki: k.skladniki.map(s => {
                    const z = Z[s.id];
                    const f = s.czesci / suma;
                    const g = v => Math.max(5, Math.round(v * f / 5) * 5);
                    return { id: s.id, z, procent: Math.round(f * 100), gramy: [g(gMin), g(gMax)], ph: s.ph };
                })
            };
        });
        const plukanki = (plan.plukanki || []).map(p => ({ id: p.id, z: Z[p.id], razy: p.razy, ph: p.ph }));
        return { gramy: [gMin, gMax], kroki, plukanki, trwalosc: trwalosc(plan, Z), ostrzezenia: ostrzezenia(profil, plan, Z) };
    }

    return {
        hexToRgb, lin, hexFromLin, labFromHex, deltaE, przewiduj, dobierz, jakosc, receptura, gramy, chlonnosc,
        czynnikCzasu, kolorZiola, PH
    };
});
