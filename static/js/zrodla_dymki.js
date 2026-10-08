// ==========================================
// ZDJĘCIA POMYŁEK I DYMKI ŹRÓDEŁ (KwZrodla)
//
// 1) „Możliwe pomyłki” na stronie rośliny (.kw-mylka[data-kw-mylka="Bez hebd (Sambucus ebulus)"]):
//    skrypt dobiera zdjęcie rośliny, z którą łatwo się pomylić – najpierw polska Wikipedia, potem Wikipedie
//    w innych językach (przez Wikidane), na końcu iNaturalist. Kliknięcie w zdjęcie = dymek z informacją,
//    skąd pochodzi zdjęcie (strona, autor, licencja). Własne zdjęcie można wpisać w JSON-ie rośliny:
//    "mozliwe_pomyłki": [{"nazwa": "...", "roznica": "...",
//        "zdjecie": {"url": "https://...jpg", "strona": "https://...", "serwis": "Nazwa strony", "autor": "...", "licencja": "CC BY 4.0"}}]
//
// 2) Źródła przepisów (a[data-kw-src]): kliknięcie pokazuje dymek z podglądem strony – tytuł, opis, obrazek,
//    czy strona wciąż działa (data/zrodla_podglad.json z sprawdz_zrodla.py + szybkie sprawdzenie w przeglądarce),
//    mały podgląd strony w ramce (gdy strona na to pozwala) i link do kopii w Web Archive.
//    Ctrl/⌘ + klik albo środkowy przycisk – od razu otwiera stronę, jak zwykły link.
//
// Działa w wersji statycznej: API Wikipedii, Wikidanych, Commons i iNaturalist mają CORS i nie wymagają klucza.
// ==========================================
(function () {
    'use strict';

    function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
    function httpsOnly(u) { return typeof u === 'string' && /^https:\/\//i.test(u) ? u : ''; }
    function httpUrl(u) { return typeof u === 'string' && /^https?:\/\//i.test(u) ? u : ''; }
    function domainOf(u) { try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; } }
    function stripHtml(h) {
        const d = document.createElement('div');
        d.innerHTML = String(h || '');
        return d.textContent.replace(/\s+/g, ' ').trim();
    }
    const MONTHS = ['sty', 'lut', 'mar', 'kwi', 'maj', 'cze', 'lip', 'sie', 'wrz', 'paź', 'lis', 'gru'];
    function plDate(iso) {
        const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso || ''));
        return m ? `${+m[3]} ${MONTHS[+m[2] - 1]} ${m[1]}` : '';
    }
    const LANG_NAMES = { pl: 'polska', en: 'angielska', de: 'niemiecka', fr: 'francuska', cs: 'czeska', uk: 'ukraińska',
        ru: 'rosyjska', es: 'hiszpańska', it: 'włoska', la: 'łacińska', sk: 'słowacka', nl: 'niderlandzka', sv: 'szwedzka',
        ja: 'japońska', zh: 'chińska', hu: 'węgierska', lt: 'litewska', be: 'białoruska' };
    const LANG_PO = { en: 'angielsku', de: 'niemiecku', fr: 'francusku', cs: 'czesku', uk: 'ukraińsku', ru: 'rosyjsku',
        es: 'hiszpańsku', it: 'włosku', la: 'łacinie', sk: 'słowacku', nl: 'niderlandzku', sv: 'szwedzku', ja: 'japońsku',
        zh: 'chińsku', hu: 'węgiersku', lt: 'litewsku', be: 'białorusku', pt: 'portugalsku', ro: 'rumuńsku', fi: 'fińsku' };
    async function getJson(url, ms) {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), ms || 8000);
        try {
            const r = await fetch(url, { signal: ctrl.signal, headers: { 'Accept': 'application/json' } });
            if (r.status === 404) return null;
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return await r.json();
        } finally { clearTimeout(t); }
    }

    function store(key, val) {
        try {
            if (val === undefined) {
                const v = localStorage.getItem(key);
                if (!v) return undefined;
                const d = JSON.parse(v);
                return d && d.exp > Date.now() ? d.v : undefined;
            }
            localStorage.setItem(key, JSON.stringify({ v: val, exp: Date.now() + 30 * 864e5 }));
        } catch (e) { /* prywatne okno / brak miejsca */ }
        return undefined;
    }

    // ------------------------------------------
    // WSPÓLNY DYMEK (wygląd jak dymki Wikipedii – static/css/wiki.css)
    // ------------------------------------------
    let tip = null, anchor = null, onClose = null;

    function ensureTip() {
        if (tip) return tip;
        tip = document.createElement('div');
        tip.className = 'kw-wiki-tip kw-src-tip';
        tip.setAttribute('role', 'dialog');
        tip.setAttribute('aria-live', 'polite');
        tip.hidden = true;
        document.body.appendChild(tip);
        tip.addEventListener('click', e => { if (e.target.closest('.kw-wiki-close')) { e.preventDefault(); closeTip(); } });
        return tip;
    }

    function openTip(el, html, extraClass) {
        ensureTip();
        if (anchor && anchor !== el) anchor.classList.remove('kw-src-active');
        if (onClose) { const f = onClose; onClose = null; f(); }
        anchor = el;
        anchor.classList.add('kw-src-active');
        anchor.setAttribute('aria-expanded', 'true');
        tip.className = 'kw-wiki-tip kw-src-tip' + (extraClass ? ' ' + extraClass : '');
        tip.innerHTML = `<button type="button" class="kw-wiki-close" aria-label="Zamknij">&times;</button>` + html;
        tip.hidden = false;
        position();
        return tip;
    }

    function setTip(html) {
        if (!tip || tip.hidden) return;
        tip.innerHTML = `<button type="button" class="kw-wiki-close" aria-label="Zamknij">&times;</button>` + html;
        position();
    }

    function closeTip() {
        if (!tip || tip.hidden) return;
        tip.hidden = true;
        tip.innerHTML = '';
        if (onClose) { const f = onClose; onClose = null; f(); }
        if (anchor) { anchor.classList.remove('kw-src-active'); anchor.setAttribute('aria-expanded', 'false'); }
        anchor = null;
    }

    function position() {
        if (!tip || tip.hidden || !anchor) return;
        if (!document.body.contains(anchor)) { closeTip(); return; }
        if (window.innerWidth < 576) { tip.classList.add('kw-wiki-sheet'); tip.style.left = ''; tip.style.top = ''; return; }
        tip.classList.remove('kw-wiki-sheet');
        const r = anchor.getBoundingClientRect();
        const tw = tip.offsetWidth, th = tip.offsetHeight, gap = 8, margin = 8;
        let top = r.bottom + gap;
        if (top + th > window.innerHeight - margin && r.top - gap - th > margin) top = r.top - gap - th;
        if (top + th > window.innerHeight - margin) top = Math.max(margin, window.innerHeight - margin - th);
        let left = r.left + r.width / 2 - tw / 2;
        left = Math.max(margin, Math.min(left, window.innerWidth - tw - margin));
        tip.style.left = `${Math.round(left)}px`;
        tip.style.top = `${Math.round(Math.max(margin, top))}px`;
    }

    window.addEventListener('scroll', () => requestAnimationFrame(position), true);
    window.addEventListener('resize', () => requestAnimationFrame(position));
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && tip && !tip.hidden) { const a = anchor; closeTip(); if (a && a.focus) a.focus(); }
    });

    // ==========================================
    // 1) ZDJĘCIA „MOŻLIWYCH POMYŁEK”
    // ==========================================
    const CACHE = 'kw_mylka_v1:';
    const WIKI_LANGS = ['en', 'de', 'cs', 'fr', 'uk', 'ru', 'sk', 'nl', 'it', 'es', 'sv', 'la'];

    // „Borówka bagienna (Pijanica) (Vaccinium uliginosum)” -> { pl: „Borówka bagienna”, latin: „Vaccinium uliginosum” }
    function parseName(name) {
        const s = String(name || '').trim();
        let latin = '';
        const groups = s.match(/\(([^()]+)\)/g) || [];
        for (let i = groups.length - 1; i >= 0; i--) {
            const g = groups[i].slice(1, -1).trim().replace(/\s+(spp?|ssp|agg)\.?$/i, '');
            if (/^[A-Z][a-zë-]+(?:\s+(?:×\s*)?[a-zë-]+){0,3}$/.test(g) && !/[ąćęłńóśźż]/i.test(g)) { latin = g; break; }
        }
        const pl = s.replace(/\([^()]*\)/g, '').replace(/\s+/g, ' ').trim();
        return { pl, latin };
    }

    async function wikiSummary(title, lang) {
        const host = `https://${lang}.wikipedia.org`;
        const d = await getJson(`${host}/api/rest_v1/page/summary/${encodeURIComponent(title.replace(/ /g, '_'))}`);
        if (!d || d.type === 'disambiguation' || !d.title) return null;
        return {
            title: d.title, lang,
            img: httpsOnly(d.thumbnail && d.thumbnail.source),
            full: httpsOnly(d.originalimage && d.originalimage.source),
            page: (d.content_urls && d.content_urls.desktop && d.content_urls.desktop.page) || `${host}/wiki/${encodeURIComponent(d.title.replace(/ /g, '_'))}`
        };
    }

    function fromWiki(s) {
        return { kind: 'wikipedia', img: s.img, full: s.full || s.img, page: s.page, pageTitle: s.title, lang: s.lang };
    }

    // Wikidane: obiekt dla nazwy łacińskiej (albo polskiej) -> Wikipedie w innych językach i zdjęcie P18
    async function viaWikidata(q, latin) {
        const found = await getJson(`https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(q)}&language=${latin ? 'en' : 'pl'}&uselang=pl&type=item&limit=4&format=json&origin=*`);
        const hits = (found && found.search) || [];
        if (!hits.length) return null;
        const ent = await getJson(`https://www.wikidata.org/w/api.php?action=wbgetentities&ids=${hits.map(h => h.id).join('|')}&props=sitelinks|claims|labels&languages=pl|en&format=json&origin=*`);
        const ents = (ent && ent.entities) || {};
        const claim = (e, p) => { try { return e.claims[p][0].mainsnak.datavalue.value; } catch (x) { return null; } };
        const norm = t => String(t || '').toLowerCase().trim();
        // najpierw takson o dokładnie tej nazwie (P225), potem etykieta, potem pierwszy wynik
        const ordered = hits.map(h => ents[h.id]).filter(Boolean).sort((a, b) => {
            const score = e => (latin && norm(claim(e, 'P225')) === norm(latin) ? 4 : 0)
                + ((e.labels && ((e.labels.pl && norm(e.labels.pl.value) === norm(q)) || (e.labels.en && norm(e.labels.en.value) === norm(q)))) ? 2 : 0)
                + (claim(e, 'P225') ? 1 : 0);
            return score(b) - score(a);
        });
        const e = ordered[0];
        if (!e) return null;
        if (latin && claim(e, 'P225') && norm(claim(e, 'P225')) !== norm(latin)) {
            // inna roślina niż szukana – nie ryzykujemy złego zdjęcia przy ostrzeżeniu o pomyłkach
            const genus = norm(latin).split(' ')[0];
            if (!norm(claim(e, 'P225')).startsWith(genus)) return null;
        }
        const links = e.sitelinks || {};
        let tries = 0;
        for (const lang of WIKI_LANGS) {
            const sl = links[`${lang}wiki`];
            if (!sl) continue;
            if (++tries > 3) break;
            const s = await wikiSummary(sl.title, lang).catch(() => null);
            if (s && s.img) return Object.assign(fromWiki(s), { wd: e.id });
        }
        const file = claim(e, 'P18');
        if (file) {
            const fp = `https://commons.wikimedia.org/wiki/Special:FilePath/${encodeURIComponent(file)}`;
            let page = `https://www.wikidata.org/wiki/${e.id}`, pageTitle = (e.labels && (e.labels.pl || e.labels.en) || {}).value || q, lang = '';
            for (const l of ['pl'].concat(WIKI_LANGS)) {
                const sl = links[`${l}wiki`];
                if (sl) { page = `https://${l}.wikipedia.org/wiki/${encodeURIComponent(sl.title.replace(/ /g, '_'))}`; pageTitle = sl.title; lang = l; break; }
            }
            return { kind: lang ? 'wikipedia' : 'wikidata', img: fp + '?width=330', full: fp, page, pageTitle, lang,
                file: { project: 'commons', name: file }, wd: e.id };
        }
        return null;
    }

    async function viaINaturalist(q, latin) {
        const d = await getJson(`https://api.inaturalist.org/v1/taxa?q=${encodeURIComponent(q)}&per_page=5&locale=pl&is_active=true`);
        const res = ((d && d.results) || []).filter(t => t.default_photo && t.default_photo.medium_url);
        const norm = t => String(t || '').toLowerCase();
        const t = latin ? res.find(r => norm(r.name) === norm(latin)) || res.find(r => norm(r.name).startsWith(norm(latin).split(' ')[0] + ' ')) : res[0];
        if (!t) return null;
        const p = t.default_photo;
        const code = String(p.license_code || '').toLowerCase();
        const lic = code === 'cc0' ? 'CC0' : code ? code.toUpperCase().replace(/^CC-/, 'CC ') : '';
        const licUrl = code === 'cc0' ? 'https://creativecommons.org/publicdomain/zero/1.0/'
            : code ? `https://creativecommons.org/licenses/${code.replace(/^cc-/, '')}/4.0/` : '';
        return {
            kind: 'inaturalist', img: httpsOnly(p.medium_url), full: httpsOnly(p.medium_url).replace('/medium.', '/large.'),
            page: `https://www.inaturalist.org/taxa/${t.id}`, pageTitle: t.preferred_common_name ? `${t.preferred_common_name} (${t.name})` : t.name,
            photoPage: p.id ? `https://www.inaturalist.org/photos/${p.id}` : '', author: p.attribution || '',
            license: lic, licenseUrl: licUrl
        };
    }

    const inflight = new Map();
    function findPhoto(name) {
        const key = CACHE + name;
        const cached = store(key);
        if (cached !== undefined) return Promise.resolve(cached);
        if (inflight.has(name)) return inflight.get(name);
        const p = (async () => {
            const { pl, latin } = parseName(name);
            let res = null, failed = false;
            const steps = [
                () => latin ? wikiSummary(latin, 'pl').then(s => s && s.img ? fromWiki(s) : null) : null,
                () => pl && pl !== latin ? wikiSummary(pl, 'pl').then(s => s && s.img ? fromWiki(s) : null) : null,
                () => viaWikidata(latin || pl, !!latin),
                () => latin && pl ? viaWikidata(pl, false) : null,
                () => viaINaturalist(latin || pl, latin)
            ];
            for (const step of steps) {
                try { res = await step(); } catch (e) { failed = true; res = null; }
                if (res && res.img) break;
                res = null;
            }
            if (res || !failed) store(key, res || null);   // błąd sieci = nie zapamiętujemy „braku”
            inflight.delete(name);
            return res;
        })();
        inflight.set(name, p);
        return p;
    }

    // Autor i licencja pliku z Wikimedia Commons (pobierane dopiero po kliknięciu w zdjęcie)
    function fileFromUrl(u) {
        try {
            const url = new URL(u);
            if (url.hostname === 'commons.wikimedia.org') {
                const m = /Special:FilePath\/([^?]+)/.exec(url.pathname);
                return m ? { project: 'commons', name: decodeURIComponent(m[1]) } : null;
            }
            if (url.hostname !== 'upload.wikimedia.org') return null;
            const seg = url.pathname.split('/').filter(Boolean);   // wikipedia/commons/thumb/7/7b/Plik.jpg/320px-Plik.jpg
            const project = seg[1];
            const name = seg[2] === 'thumb' ? seg[5] : seg[4];
            return name ? { project, name: decodeURIComponent(name) } : null;
        } catch (e) { return null; }
    }

    async function fileInfo(info) {
        const f = info.file || fileFromUrl(info.full || info.img);
        if (!f) return null;
        const key = CACHE + 'plik:' + f.project + ':' + f.name;
        const cached = store(key);
        if (cached !== undefined) return cached;
        const api = f.project === 'commons' ? 'https://commons.wikimedia.org/w/api.php' : `https://${f.project}.wikipedia.org/w/api.php`;
        const d = await getJson(`${api}?action=query&format=json&origin=*&prop=imageinfo&iiprop=extmetadata|url&iiextmetadatafilter=Artist|LicenseShortName|LicenseUrl|Credit|ObjectName&titles=${encodeURIComponent('File:' + f.name)}`);
        const pages = d && d.query && d.query.pages ? Object.values(d.query.pages) : [];
        const ii = pages[0] && pages[0].imageinfo && pages[0].imageinfo[0];
        if (!ii) return null;
        const m = ii.extmetadata || {};
        const out = {
            author: stripHtml(m.Artist && m.Artist.value).slice(0, 120) || stripHtml(m.Credit && m.Credit.value).slice(0, 120),
            license: stripHtml(m.LicenseShortName && m.LicenseShortName.value),
            licenseUrl: httpUrl(m.LicenseUrl && m.LicenseUrl.value),
            filePage: httpsOnly(ii.descriptionurl), fileName: f.name.replace(/_/g, ' '),
            commons: f.project === 'commons'
        };
        store(key, out);
        return out;
    }

    function photoTipHtml(card, info, meta, loadingMeta) {
        const name = card.dataset.kwMylka || '';
        const { pl, latin } = parseName(name);
        let html = `<div class="kw-wiki-head">${esc(pl || name)}</div>`;
        if (latin) html += `<div class="kw-wiki-sub">${esc(latin)}</div>`;
        html += `<a class="kw-mylka-big" href="${esc(info.full || info.img)}" target="_blank" rel="noopener" title="Otwórz zdjęcie w pełnym rozmiarze">
            <img src="${esc(info.img)}" alt="${esc(pl || name)} – zdjęcie poglądowe" loading="lazy"></a>`;

        let from;
        if (info.kind === 'wikipedia') {
            const lang = info.lang || 'pl';
            from = `<a href="${esc(info.page)}" target="_blank" rel="noopener">Wikipedia ${esc(LANG_NAMES[lang] || lang)} – „${esc(info.pageTitle)}” ↗</a>`;
        } else if (info.kind === 'wikidata') {
            from = `<a href="${esc(info.page)}" target="_blank" rel="noopener">Wikidane – „${esc(info.pageTitle)}” ↗</a>`;
        } else if (info.kind === 'inaturalist') {
            from = `<a href="${esc(info.page)}" target="_blank" rel="noopener">iNaturalist – ${esc(info.pageTitle)} ↗</a>`;
        } else {
            const dom = info.page ? domainOf(info.page) : '';
            from = info.page ? `<a href="${esc(info.page)}" target="_blank" rel="noopener nofollow">${esc(info.site || dom)} ↗</a>` : esc(info.site || 'Kwiatownik');
        }
        const rows = [`<div><span class="kw-src-k">Źródło zdjęcia:</span> ${from}</div>`];
        const author = (meta && meta.author) || info.author;
        const lic = (meta && meta.license) || info.license;
        const licUrl = (meta && meta.licenseUrl) || info.licenseUrl;
        if (author) rows.push(`<div><span class="kw-src-k">Autor:</span> ${esc(author)}</div>`);
        if (lic) rows.push(`<div><span class="kw-src-k">Licencja:</span> ${licUrl ? `<a href="${esc(licUrl)}" target="_blank" rel="noopener">${esc(lic)}</a>` : esc(lic)}</div>`);
        if (meta && meta.filePage) rows.push(`<div><span class="kw-src-k">Plik:</span> <a href="${esc(meta.filePage)}" target="_blank" rel="noopener">${meta.commons ? 'Wikimedia Commons' : 'strona pliku'} ↗</a></div>`);
        else if (info.photoPage) rows.push(`<div><span class="kw-src-k">Zdjęcie:</span> <a href="${esc(info.photoPage)}" target="_blank" rel="noopener">strona zdjęcia ↗</a></div>`);
        if (loadingMeta) rows.push(`<div class="kw-wiki-loading"><span class="kw-wiki-spinner"></span> Sprawdzam autora i licencję…</div>`);
        html += `<div class="kw-src-meta">${rows.join('')}</div>`;
        html += `<p class="kw-mylka-note">Zdjęcie poglądowe – rośliny się zmieniają z porą roku. Zawsze porównuj kilka cech opisanych obok.</p>`;
        return html;
    }

    function showPhotoTip(btn) {
        const card = btn.closest('.kw-mylka');
        const info = card && card._kwPhoto;
        if (!info) return;
        if (anchor === btn && tip && !tip.hidden) { closeTip(); return; }
        const needMeta = !info.author && !info.license && (info.kind === 'wikipedia' || info.kind === 'wikidata');
        openTip(btn, photoTipHtml(card, info, null, needMeta), 'kw-mylka-tip');
        if (needMeta) {
            fileInfo(info).catch(() => null).then(meta => {
                if (anchor === btn) setTip(photoTipHtml(card, info, meta, false));
            });
        }
    }

    function applyPhoto(card, info) {
        const btn = card.querySelector('.kw-mylka-foto');
        if (!btn) return;
        if (!info || !info.img) { card.classList.add('kw-mylka-brak'); card.classList.remove('kw-mylka-wait'); return; }
        card._kwPhoto = info;
        const { pl } = parseName(card.dataset.kwMylka);
        const img = new Image();
        img.alt = `${pl} – zdjęcie poglądowe`;
        img.decoding = 'async';
        img.onload = () => {
            btn.innerHTML = '';
            btn.appendChild(img);
            const i = document.createElement('span');
            i.className = 'kw-mylka-i';
            i.setAttribute('aria-hidden', 'true');
            i.textContent = 'i';
            btn.appendChild(i);
            btn.disabled = false;
            btn.title = 'Kliknij, aby zobaczyć, skąd pochodzi zdjęcie';
            card.classList.remove('kw-mylka-wait');
        };
        img.onerror = () => { card.classList.add('kw-mylka-brak'); card.classList.remove('kw-mylka-wait'); };
        img.src = info.img;
    }

    function loadCard(card) {
        if (card.dataset.kwLoaded) return;
        card.dataset.kwLoaded = '1';
        card.classList.add('kw-mylka-wait');
        let own = null;
        try { own = card.dataset.kwZdjecie ? JSON.parse(card.dataset.kwZdjecie) : null; } catch (e) { own = null; }
        if (own && typeof own === 'string') own = { url: own };
        if (own && httpsOnly(own.url)) {
            applyPhoto(card, { kind: 'wlasne', img: own.url, full: own.url, page: httpUrl(own.strona || own.zrodlo), site: own.serwis || '',
                author: own.autor || '', license: own.licencja || '', licenseUrl: httpUrl(own.licencja_url) });
            return;
        }
        findPhoto(card.dataset.kwMylka).then(info => applyPhoto(card, info), () => applyPhoto(card, null));
    }

    function initPhotos(root) {
        const cards = Array.from((root || document).querySelectorAll('.kw-mylka[data-kw-mylka]'));
        if (!cards.length) return;
        if (!('IntersectionObserver' in window)) { cards.forEach(loadCard); return; }
        const io = new IntersectionObserver(entries => entries.forEach(en => {
            if (en.isIntersecting) { io.unobserve(en.target); loadCard(en.target); }
        }), { rootMargin: '300px' });
        cards.forEach(c => io.observe(c));
        // zakładka „Możliwe pomyłki” otwarta = od razu pobieramy wszystkie zdjęcia w niej
        document.addEventListener('toggle', e => {
            const d = e.target;
            if (d && d.tagName === 'DETAILS' && d.open) d.querySelectorAll('.kw-mylka[data-kw-mylka]').forEach(loadCard);
        }, true);
    }

    // ==========================================
    // 2) DYMEK ŹRÓDŁA PRZEPISU
    // ==========================================
    let podglad = null;
    function srcKey(u) {
        try {
            const x = new URL(u);
            let k = `${x.protocol}//${x.host.toLowerCase()}${x.pathname || '/'}${x.search}`;
            try { k = decodeURI(k); } catch (e) { /* zostaje zakodowany */ }
            return k;
        } catch (e) { return String(u || ''); }
    }
    function loadPodglad() {
        if (podglad) return podglad;
        const s = (document.querySelector('script[src*="zrodla_dymki.js"]') || {}).src || '';
        const url = s ? s.replace(/static\/js\/zrodla_dymki\.js.*$/, 'api/zrodla_podglad.json') : '/api/zrodla_podglad.json';
        podglad = fetch(url, { cache: 'no-cache' }).then(r => r.ok ? r.json() : {}).then(d => {
            const map = new Map();
            Object.entries((d && d.zrodla) || {}).forEach(([k, v]) => map.set(srcKey(k), v));
            return map;
        }).catch(() => new Map());
        return podglad;
    }

    // Czy serwer strony w ogóle odpowiada (bez czytania treści – „no-cors”). Blokery reklam mogą dać fałszywe „nie”.
    const probes = new Map();
    function probe(url) {
        if (!/^https:\/\//i.test(url)) return Promise.resolve('unknown');   // http z https zablokuje przeglądarka
        if (probes.has(url)) return probes.get(url);
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 8000);
        const p = fetch(url, { mode: 'no-cors', method: 'HEAD', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: ctrl.signal })
            .then(() => 'ok', e => (e && e.name === 'AbortError') ? 'slow' : 'fail')
            .finally(() => clearTimeout(t));
        probes.set(url, p);
        return p;
    }

    function statusHtml(info, live) {
        const when = info && info.sprawdzono ? ` · sprawdzono ${esc(plDate(info.sprawdzono))}` : '';
        const stan = info && info.stan;
        const reason = info && info.blad ? esc(info.blad) : '';
        if (live === 'pending' && !stan) return `<div class="kw-src-status"><span class="kw-wiki-spinner"></span> Sprawdzam, czy strona wciąż działa…</div>`;
        if (stan === 'brak') {
            const last = info.ostatnio_dzialala ? ` Ostatnio działała ${esc(plDate(info.ostatnio_dzialala))}.` : '';
            return `<div class="kw-src-status kw-src-bad">✗ Tej strony już nie ma – ${reason}${when}.${last} Zobacz kopię w Web Archive.</div>`;
        }
        if (stan === 'blad') {
            if (live === 'ok') return `<div class="kw-src-status kw-src-ok">✓ Serwer strony znów odpowiada (ostatnio: ${reason}${when}).</div>`;
            return `<div class="kw-src-status kw-src-bad">✗ Strona nie odpowiada – ${reason}${when}. Zobacz kopię w Web Archive.</div>`;
        }
        if (live === 'fail') {
            return `<div class="kw-src-status kw-src-warn">⚠ Twoja przeglądarka nie może teraz połączyć się z tą stroną${stan === 'dziala' ? ` (przy sprawdzeniu ${esc(plDate(info.sprawdzono))} działała)` : ''}. Mogła zniknąć – jest też kopia w Web Archive.</div>`;
        }
        if (stan === 'dziala') return `<div class="kw-src-status kw-src-ok">✓ Strona działa${when}</div>`;
        if (stan === 'blokada') return `<div class="kw-src-status kw-src-ok">✓ Serwer strony odpowiada${live === 'ok' ? '' : when} <span class="kw-src-hint">(nie pozwala na automatyczny podgląd)</span></div>`;
        if (live === 'ok') return `<div class="kw-src-status kw-src-ok">✓ Serwer strony odpowiada</div>`;
        if (live === 'slow') return `<div class="kw-src-status kw-src-warn">⚠ Strona odpowiada bardzo wolno albo wcale.</div>`;
        return `<div class="kw-src-status">Tej strony jeszcze nie sprawdzaliśmy.</div>`;
    }

    function sourceTipHtml(a, info, live) {
        const url = a.href;
        const dom = domainOf(url);
        const title = (info && info.tytul) || a.dataset.kwTitle || a.dataset.kwName || a.textContent.replace(/[↗\s]+$/, '').trim() || dom;
        const lang = (a.dataset.kwLang || (info && info.jezyk) || '').toLowerCase().slice(0, 2);
        const target = (info && info.adres_koncowy) || url;
        const dead = info && (info.stan === 'brak' || info.stan === 'blad') && live !== 'ok';
        const archive = `https://web.archive.org/web/2/${url}`;

        let html = `<div class="kw-wiki-head">${esc(title)}</div>`;
        const bits = [`<img class="kw-src-fav" src="https://icons.duckduckgo.com/ip3/${encodeURIComponent(dom)}.ico" alt="" width="16" height="16" loading="lazy" onerror="this.remove()"> ${esc((info && info.serwis) || dom)}`];
        if (lang && lang !== 'pl') bits.push(LANG_PO[lang] ? `oryginał po ${LANG_PO[lang]}` : `język: ${esc(lang.toUpperCase())}`);
        if (a.dataset.kwDate) bits.push(`pobrano ${esc(plDate(a.dataset.kwDate) || a.dataset.kwDate)}`);
        html += `<div class="kw-src-domain">${bits.join(' · ')}</div>`;
        html += statusHtml(info, live);

        const canFrame = info && info.osadzalna && info.stan === 'dziala' && live !== 'fail' && /^https:\/\//i.test(target);
        if (canFrame) {
            html += `<div class="kw-src-frame" aria-label="Podgląd strony">
                <div class="kw-src-frame-load"><span class="kw-wiki-spinner"></span> Ładuję podgląd strony…</div>
                <iframe src="${esc(target)}" title="Podgląd: ${esc(title)}" loading="lazy" tabindex="-1" referrerpolicy="no-referrer"
                    sandbox="allow-scripts allow-same-origin"></iframe>
                <a class="kw-src-frame-cover" href="${esc(target)}" target="_blank" rel="noopener nofollow" aria-label="Otwórz stronę"></a>
            </div>`;
        } else if (info && (info.obraz || info.opis)) {
            html += `<div class="kw-wiki-body kw-src-card${dead ? ' kw-src-dead' : ''}">${info.obraz ? `<img class="kw-wiki-img" src="${esc(info.obraz)}" alt="" loading="lazy" onerror="this.remove()">` : ''}`
                + `${info.opis ? `<p class="kw-wiki-text">${esc(info.opis)}</p>` : ''}</div>`;
            if (dead) html += `<div class="kw-wiki-sub">Tak opisywała się ta strona, gdy jeszcze działała.</div>`;
        }
        const translate = lang && lang !== 'pl' && !dead
            ? `<a class="kw-wiki-more" href="https://translate.google.com/translate?sl=auto&tl=pl&u=${encodeURIComponent(target)}" target="_blank" rel="noopener">Przetłumacz ↗</a>` : '';
        const open = dead
            ? `<a class="kw-wiki-more" href="${esc(archive)}" target="_blank" rel="noopener">Kopia w Web Archive ↗</a><a class="kw-src-dim" href="${esc(url)}" target="_blank" rel="noopener nofollow">spróbuj otworzyć ↗</a>`
            : `<a class="kw-wiki-more" href="${esc(target)}" target="_blank" rel="noopener nofollow">Otwórz stronę ↗</a>${translate}<a class="kw-src-dim" href="${esc(archive)}" target="_blank" rel="noopener">archiwum ↗</a>`;
        html += `<div class="kw-wiki-foot"><span>${open}</span></div>`;
        return html;
    }

    function wireFrame() {
        if (!tip) return;
        const box = tip.querySelector('.kw-src-frame');
        if (!box) return;
        const fr = box.querySelector('iframe');
        const s = (box.clientWidth || 360) / 1100;
        fr.style.transform = `scale(${s})`;
        fr.style.height = `${Math.round((box.clientHeight || 230) / s)}px`;
        fr.addEventListener('load', () => box.classList.add('kw-src-frame-ready'), { once: true });
        onClose = () => { try { fr.src = 'about:blank'; } catch (e) { /* nic */ } };
    }

    async function showSourceTip(a) {
        if (anchor === a && tip && !tip.hidden) { closeTip(); return; }
        const url = a.href;
        openTip(a, sourceTipHtml(a, undefined, 'pending'), 'kw-src-page-tip');
        const map = await loadPodglad();
        if (anchor !== a) return;
        const info = map.get(srcKey(url));
        const liveP = probe(url);
        // znamy wynik ostatniego sprawdzenia – pokazujemy od razu, a sprawdzenie na żywo dopisze się po chwili
        if (info) { setTip(sourceTipHtml(a, info, 'pending-known')); wireFrame(); }
        const live = await liveP;
        if (anchor !== a) return;
        const changed = !info || live === 'fail' || (live === 'ok' && (info.stan === 'blad' || info.stan === 'blokada'));
        if (!changed) return;
        const st = tip.querySelector('.kw-src-status');
        if (tip.querySelector('.kw-src-frame') && live !== 'fail' && st) {
            st.outerHTML = statusHtml(info, live);      // podgląd w ramce zostaje (bez ponownego ładowania)
            position();
        } else { setTip(sourceTipHtml(a, info, live)); wireFrame(); }
    }

    const SRC_SELECTOR = 'a[data-kw-src], a[data-kw-podglad]';
    document.addEventListener('click', e => {
        const btn = e.target.closest && e.target.closest('.kw-mylka-foto');
        if (btn) {
            e.preventDefault();
            e.stopPropagation();
            if (!btn.disabled) showPhotoTip(btn);
            return;
        }
        const a = e.target.closest && e.target.closest(SRC_SELECTOR);
        if (a && !(tip && tip.contains(a))) {
            if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || !/^https?:/i.test(a.href)) return;   // zwykłe otwarcie w nowej karcie
            e.preventDefault();
            e.stopPropagation();   // np. żeby kliknięcie w źródło na karcie nie otwierało grymuaru przepisu
            showSourceTip(a);
            return;
        }
        if (tip && !tip.hidden && !tip.contains(e.target)) closeTip();
    }, true);

    function init() {
        initPhotos(document);
        // źródła w oknie przepisu pojawiają się później – oznaczamy je, żeby było wiadomo, że kliknięcie pokaże dymek
        if (document.querySelector('a[data-kw-src]')) loadPodglad();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();

    window.KwZrodla = { findPhoto, parseName, initPhotos, showSourceTip, loadPodglad };
})();
