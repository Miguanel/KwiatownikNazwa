/* =====================================================================
   MÓJ ZIELNIK – zapis w przeglądarce (localStorage „kw_zielnik_v1”)
   Wspólne dla strony rośliny (przycisk „Dodaj do Mojego zielnika”) i strony /zielnik/.
   Dane zostają tylko w tej przeglądarce – na stronie Zielnika jest eksport i import pliku.
   {
     wersja: 1,
     rosliny: { "<id rośliny>": { dodano: "RRRR-MM-DD", nazwa: "Pokrzywa zwyczajna", notatka: "" } },
     zbiory:  [ { uid, id, czesc, forma, ilosc, jedn, data, miejsce, notatka, zuzyte } ]
   }
   ===================================================================== */
(function () {
    'use strict';
    const KEY = 'kw_zielnik_v1';
    const pusty = () => ({ wersja: 1, rosliny: {}, zbiory: [] });
    const dzis = () => new Date().toISOString().slice(0, 10);

    function wczytaj() {
        try {
            const d = JSON.parse(localStorage.getItem(KEY) || 'null');
            if (d && typeof d === 'object' && d.rosliny && Array.isArray(d.zbiory)) return d;
        } catch (e) { /* brak pamięci albo uszkodzony zapis */ }
        return pusty();
    }
    function zapisz(d) {
        try { localStorage.setItem(KEY, JSON.stringify(d)); return true; } catch (e) { return false; }
    }
    function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

    const api = {
        KEY,
        wczytaj,
        zapisz,
        ma: id => !!wczytaj().rosliny[id],
        dodaj(id, nazwa) {
            const d = wczytaj();
            if (!d.rosliny[id]) d.rosliny[id] = { dodano: dzis(), notatka: '' };
            if (nazwa) d.rosliny[id].nazwa = String(nazwa).slice(0, 80);
            return zapisz(d);
        },
        usun(id) {
            const d = wczytaj();
            delete d.rosliny[id];
            return zapisz(d);
        },
        notatka(id, tekst) {
            const d = wczytaj();
            if (d.rosliny[id]) d.rosliny[id].notatka = String(tekst || '').slice(0, 2000);
            return zapisz(d);
        },
        dodajZbior(z) {
            const d = wczytaj();
            const wpis = Object.assign({ uid: uid(), data: dzis(), zuzyte: false }, z);
            d.zbiory.push(wpis);
            if (wpis.id && !d.rosliny[wpis.id]) d.rosliny[wpis.id] = { dodano: dzis(), notatka: '', nazwa: z.nazwa || '' };
            delete wpis.nazwa;
            zapisz(d);
            return wpis;
        },
        zmienZbior(uidZ, zmiany) {
            const d = wczytaj();
            const z = d.zbiory.find(x => x.uid === uidZ);
            if (z) Object.assign(z, zmiany);
            return zapisz(d);
        },
        usunZbior(uidZ) {
            const d = wczytaj();
            d.zbiory = d.zbiory.filter(x => x.uid !== uidZ);
            return zapisz(d);
        },
        // przycisk na stronie rośliny: dodaj / usuń
        przycisk(btn) {
            if (!btn) return;
            const id = btn.dataset.id;
            const opis = btn.querySelector('span');
            const odswiez = () => {
                const jest = api.ma(id);
                btn.setAttribute('aria-pressed', jest ? 'true' : 'false');
                opis.textContent = jest ? 'W Moim zielniku' : 'Dodaj do Mojego zielnika';
                btn.title = jest ? 'Kliknij, aby usunąć z Mojego zielnika' : 'Zapisz roślinę w Moim zielniku (w tej przeglądarce)';
            };
            btn.hidden = false;
            btn.addEventListener('click', () => {
                api.ma(id) ? api.usun(id) : api.dodaj(id, btn.dataset.nazwa);
                odswiez();
                if (window.renderFavoritesDropdown) window.renderFavoritesDropdown();
            });
            odswiez();
        }
    };
    window.KwZielnik = api;
})();
