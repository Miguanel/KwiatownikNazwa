// ==========================================
// KWIATOWNIK – STRONA GŁÓWNA
// Jedna wyszukiwarka, która łączy dawne funkcje:
//  • wyszukiwarki głównej (karty roślin z gildiami i kalendarzem, pory roku,
//    miesiące, czynności ogrodnicze, przepisy, objawy/działanie, kolory),
//  • wyszukiwarki tagów (Enter = filtr, wszystkie filtry muszą pasować),
//    która filtruje też karuzele Bestiariusza i Księgi Przepisów,
//  • rozpoznawania rośliny ze zdjęcia (magic_lens.js).
// Wszystko działa po stronie przeglądarki, więc także w wersji statycznej (freeze).
// ==========================================
(function () {
    'use strict';

    // ------------------------------------------
    // NARZĘDZIA
    // ------------------------------------------
    const ACCENTS = { 'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z' };

    function safeStr(val) {
        return (val === null || val === undefined) ? '' : String(val);
    }

    function esc(val) {
        return safeStr(val).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    // "Ból Głowy" -> "bol glowy"
    function norm(text) {
        return safeStr(text).toLowerCase().replace(/[ąćęłńóśźż]/g, m => ACCENTS[m]);
    }

    function words(text) {
        return norm(text).split(/[^\p{L}\p{N}]+/u).filter(w => w.length > 0);
    }

    function containsAll(normText, wordList) {
        return wordList.every(w => normText.includes(w));
    }

    function slugify(text) {
        return norm(text).trim().replace(/\s+/g, '_').replace(/[^\w\-]+/g, '');
    }

    // Spłaszcza dowolną strukturę JSON do listy tekstów (do przeszukiwania pełnotekstowego)
    function flatten(value, skipKeys, out, depth) {
        out = out || [];
        depth = depth || 0;
        if (value === null || value === undefined || depth > 7) return out;
        if (typeof value === 'string' || typeof value === 'number') { out.push(String(value)); return out; }
        if (Array.isArray(value)) { value.forEach(v => flatten(v, skipKeys, out, depth + 1)); return out; }
        if (typeof value === 'object') {
            Object.keys(value).forEach(k => {
                if (skipKeys && skipKeys.has(k)) return;
                flatten(value[k], skipKeys, out, depth + 1);
            });
        }
        return out;
    }

    function shorten(text, max) {
        const t = safeStr(text).replace(/\s+/g, ' ').trim();
        return t.length > max ? t.slice(0, max - 1).trimEnd() + '…' : t;
    }

    function prepText(r) {
        const p = r.sposob_przygotowania;
        if (Array.isArray(p)) return p.map(x => typeof x === 'object' ? flatten(x).join(' ') : x).join(' ');
        if (p && typeof p === 'object') return flatten(p).join(' ');
        return safeStr(p);
    }

    function ingredientNames(r) {
        const s = r.skladniki;
        if (Array.isArray(s)) return s.map(x => (x && typeof x === 'object') ? (x.nazwa || x.skladnik || '') : x).filter(Boolean);
        if (s && typeof s === 'object') return Object.keys(s);
        return s ? [safeStr(s)] : [];
    }

    // --- PRZECIĄGANIE (DRAG TO SCROLL) ---
    let isDraggingUI = false;
    function enableDragToScroll(slider) {
        let isDown = false, startX = 0, scrollLeft = 0;
        slider.addEventListener('mousedown', e => {
            isDown = true; isDraggingUI = false;
            startX = e.pageX - slider.offsetLeft;
            scrollLeft = slider.scrollLeft;
        });
        slider.addEventListener('mouseleave', () => { isDown = false; });
        slider.addEventListener('mouseup', () => { isDown = false; setTimeout(() => { isDraggingUI = false; }, 0); });
        slider.addEventListener('mousemove', e => {
            if (!isDown) return;
            const walk = (e.pageX - slider.offsetLeft - startX) * 1.5;
            if (Math.abs(walk) > 5) { isDraggingUI = true; e.preventDefault(); }
            slider.scrollLeft = scrollLeft - walk;
        });
    }

    // ------------------------------------------
    // DANE
    // ------------------------------------------
    const PLANTS = (typeof plantsData !== 'undefined' && Array.isArray(plantsData) ? plantsData : [])
        .filter(p => p && typeof p === 'object');
    PLANTS.forEach(p => {
        p.nazwa_pl = p.nazwa_pl || p.gatunek || 'Nieznana roślina';
        p.id = p.id || p.slug || slugify(p.nazwa_pl);
    });

    const RECIPES = (typeof recipesData !== 'undefined' && Array.isArray(recipesData) ? recipesData : [])
        .filter(r => r && typeof r === 'object' && r.tytul);

    const CAL = (typeof kalendarz !== 'undefined' && kalendarz && typeof kalendarz === 'object') ? kalendarz : {};
    const TAGS = (typeof TAG_DICTIONARY !== 'undefined') ? TAG_DICTIONARY : {};

    const plantByName = new Map(PLANTS.map(p => [norm(p.nazwa_pl), p]));
    function findPlantByName(name) { return plantByName.get(norm(name).trim()) || null; }
    function latinOf(p) { return safeStr(p.nazwa_lat || p.nazwa_lacinska || p.lacina); }

    function getBestImageUrl(plant) {
        if (!plant) return '';
        if (plant.url && typeof plant.url === 'object') return Object.values(plant.url)[0] || '';
        return plant.zdjecie_url || plant.zdjecie || plant.image || (typeof plant.url === 'string' ? plant.url : '') || '';
    }

    function getPlantUrl(plant) { return '/plant/' + encodeURIComponent(plant.id) + '/'; }
    function getRecipeUrl(title) { return '/przepisy/?q=' + encodeURIComponent(title) + '&autoopen=true'; }

    function getWitcherIcon(plant) {
        const rodzina = norm(plant && plant.rodzina);
        const nazwa = norm(plant && (plant.nazwa_pl || plant.nazwa));
        if (rodzina.includes('bukowate') || rodzina.includes('sosnowate') || nazwa.includes('dab')) return 'ra-pine-tree';
        return 'ra-herb';
    }

    function showUnknownPlant(name) {
        const el = document.getElementById('megaAlertPlantName');
        const overlay = document.getElementById('megaAlertOverlay');
        if (el) el.textContent = name;
        if (overlay) overlay.style.display = 'block';
    }

    // --- Indeks roślin (pełnotekstowy) ---
    const plantIndex = PLANTS.map(p => {
        const tagDescs = (Array.isArray(p.tagi) ? p.tagi : []).map(t => {
            const def = TAGS[safeStr(t).toLowerCase().trim()];
            return def ? def.desc : '';
        });
        return {
            plant: p,
            name: norm(`${p.nazwa_pl} ${latinOf(p)}`),
            core: norm([p.nazwa_pl, latinOf(p), p.rodzina, (p.tagi || []).join(' '), tagDescs.join(' ')].join(' ')),
            full: norm(flatten([
                p.nazwa_pl, latinOf(p), p.rodzina, p.opis, p.tagi, tagDescs, p.zastosowanie,
                p.czesci_rosliny, p.ciekawostki, p.identyfikacja, p.profil_energetyczny, p.ostrzezenia, p.wymagania
            ]).join(' '))
        };
    });

    // --- Indeks przepisów ---
    const RECIPE_SKIP = new Set(['id', 'slug', 'zrodla', 'url', 'zdjecie', 'zdjecie_url']);
    const recipeIndex = RECIPES.map(r => ({
        recipe: r,
        title: norm(`${r.tytul} ${r.roslina || ''}`),
        full: norm(flatten(r, RECIPE_SKIP).join(' '))
    }));

    // ------------------------------------------
    // MAPA DZIAŁANIA / OBJAWÓW (dawna "arena")
    // ------------------------------------------
    const symptomMap = {};
    function addSymptom(text, plant) {
        if (!text || !plant) return;
        const content = Array.isArray(text) ? text.join(', ') : (typeof text === 'object' ? flatten(text).join(', ') : String(text));
        content.split(/[,;.:()]/).forEach(part => {
            const tag = safeStr(part).trim().toLowerCase();
            if (tag.length < 3 || tag.length > 60) return;
            if (!symptomMap[tag]) symptomMap[tag] = [];
            if (!symptomMap[tag].includes(plant)) symptomMap[tag].push(plant);
        });
    }
    RECIPES.forEach(r => {
        const plant = r.roslina ? findPlantByName(r.roslina) : null;
        if (!plant) return;
        ['zastosowanie', 'cechy', 'wlasciwosci', 'efekty', 'tagi'].forEach(k => addSymptom(r[k], plant));
    });
    PLANTS.forEach(p => {
        if (p.zastosowanie && p.zastosowanie.medyczne) addSymptom(p.zastosowanie.medyczne, p);
        if (p.czesci_rosliny && typeof p.czesci_rosliny === 'object') {
            Object.values(p.czesci_rosliny).forEach(c => { if (c) addSymptom(c.wlasciwosci || c['wlasciwości'], p); });
        }
    });
    // Kolory kwiatów (dawne colorMap) – dopasowane do roślin z bazy
    [['żółty', 'Mniszek lekarski'], ['czerwony', 'Mak polny'], ['fioletowy', 'Lawenda wąskolistna']].forEach(([color, name]) => {
        const p = findPlantByName(name);
        if (p) { (symptomMap['kwiat ' + color] = symptomMap['kwiat ' + color] || []).push(p); }
    });
    const symptomKeys = Object.keys(symptomMap).map(k => ({ key: k, n: norm(k) }));

    // ------------------------------------------
    // KALENDARZ: PORY ROKU, MIESIĄCE, CZYNNOŚCI
    // ------------------------------------------
    const monthNames = ['', 'styczeń', 'luty', 'marzec', 'kwiecień', 'maj', 'czerwiec', 'lipiec', 'sierpień', 'wrzesień', 'październik', 'listopad', 'grudzień'];
    const seasonMonths = { 'zima': [12, 1, 2], 'wiosna': [3, 4, 5], 'lato': [6, 7, 8], 'jesień': [9, 10, 11] };
    const seasonalMap = {};
    Object.keys(seasonMonths).concat(monthNames.slice(1)).forEach(k => { seasonalMap[k] = []; });

    function taskIconFor(name) {
        const t = norm(name);
        if (t.includes('sadz') || t.includes('siew')) return 'ra-plant-seed';
        if (t.includes('zbior') || t.includes('zbier')) return 'ra-sickle';
        if (t.includes('ciac') || t.includes('cieci') || t.includes('przycina')) return 'ra-sword';
        if (t.includes('podlew') || t.includes('nawadnia')) return 'ra-water-drop';
        return 'ra-sprout';
    }

    PLANTS.forEach(plant => {
        const zadania = plant.kalendarz_ogrodnika && Array.isArray(plant.kalendarz_ogrodnika.zadania) ? plant.kalendarz_ogrodnika.zadania : [];
        zadania.forEach(z => {
            const entry = { tytul: `${plant.nazwa_pl} - ${z.czynnosc}`, desc: z.opis || `Czas na: ${z.czynnosc}`, icon: taskIconFor(z.czynnosc), rosliny: [plant.nazwa_pl] };
            (z.miesiace || []).forEach(m => {
                const mName = monthNames[m];
                if (mName && !seasonalMap[mName].some(t => t.tytul === entry.tytul)) seasonalMap[mName].push(entry);
                Object.entries(seasonMonths).forEach(([season, arr]) => {
                    if (arr.includes(m) && !seasonalMap[season].some(t => t.tytul === entry.tytul)) seasonalMap[season].push(entry);
                });
            });
        });
    });

    // Klucze kalendarza: { 'jesień': {type, label, data:[zadania]} }
    const calendarSearchMap = {};
    // "exact" = słowo będące samym pojęciem czasu/czynności (np. "jesień", "zbiór"),
    // nie zawęża już listy roślin/przepisów – tylko wybiera kalendarz.
    const exactCalendarKeys = new Set();

    function normalizeTasks(list, fallbackName, fallbackIcon) {
        return (Array.isArray(list) ? list : [list]).filter(Boolean).map(t => {
            const plantName = t.roslina || (t.rosliny && t.rosliny[0]) || '';
            return {
                tytul: t.tytul || (plantName ? `${plantName} - ${fallbackName}` : fallbackName),
                desc: t.desc || t.opis || `Czynność: ${fallbackName}`,
                icon: t.icon || fallbackIcon || taskIconFor(fallbackName),
                rosliny: t.rosliny || (t.roslina ? [t.roslina] : [])
            };
        });
    }

    if (CAL.okresy) {
        Object.keys(CAL.okresy).forEach(okres => {
            const key = okres.toLowerCase();
            calendarSearchMap[key] = { type: 'Sezon / Czas', label: okres, data: normalizeTasks(CAL.okresy[okres].zadania, okres) };
            exactCalendarKeys.add(norm(key));
        });
    }

    const actionBuckets = {
        'zbiór': { type: 'Grupa czynności', label: 'Zbiór (wszystkie rodzaje)', keywords: ['zbiór', 'zbieranie', 'żniwa'], match: ['zbior', 'zbier', 'zniwa'], data: [], icon: 'ra-sickle' },
        'sadzenie': { type: 'Grupa czynności', label: 'Sadzenie i rozmnażanie', keywords: ['sadzenie', 'siew', 'rozmnażanie', 'pikowanie'], match: ['sadz', 'siew', 'rozmnaza', 'pikow'], data: [], icon: 'ra-plant-seed' },
        'cięcie': { type: 'Grupa czynności', label: 'Cięcie i pielęgnacja', keywords: ['cięcie', 'przycinanie', 'pielęgnacja'], match: ['ciac', 'cieci', 'przycina', 'formow', 'piel'], data: [], icon: 'ra-sword' },
        'podlewanie': { type: 'Grupa czynności', label: 'Nawadnianie i nawożenie', keywords: ['podlewanie', 'nawożenie', 'nawadnianie'], match: ['podlew', 'nawoz', 'zasila', 'nawadnia'], data: [], icon: 'ra-water-drop' }
    };

    if (CAL.czynnosci) {
        Object.keys(CAL.czynnosci).forEach(czynnosc => {
            const n = norm(czynnosc);
            const bucket = Object.values(actionBuckets).find(b => b.match.some(kw => n.includes(kw)));
            if (bucket) {
                bucket.data = bucket.data.concat(normalizeTasks(CAL.czynnosci[czynnosc], czynnosc, bucket.icon));
            } else {
                calendarSearchMap[czynnosc.toLowerCase()] = { type: 'Czynność', label: czynnosc, data: normalizeTasks(CAL.czynnosci[czynnosc], czynnosc) };
            }
        });
    }
    // Zadania z kart roślin też trafiają do grup czynności
    Object.values(seasonalMap).forEach(list => list.forEach(t => {
        const n = norm(t.tytul);
        const bucket = Object.values(actionBuckets).find(b => b.match.some(kw => n.includes(kw)));
        if (bucket && !bucket.data.some(x => x.tytul === t.tytul)) bucket.data.push(t);
    }));
    Object.values(actionBuckets).forEach(bucket => {
        if (!bucket.data.length) return;
        bucket.keywords.forEach(kw => { calendarSearchMap[kw] = bucket; exactCalendarKeys.add(norm(kw)); });
    });

    Object.keys(seasonalMap).forEach(key => {
        if (!seasonalMap[key].length) return;
        if (calendarSearchMap[key]) {
            const existing = calendarSearchMap[key];
            seasonalMap[key].forEach(t => { if (!existing.data.some(x => x.tytul === t.tytul)) existing.data.push(t); });
        } else {
            const typeLabel = seasonMonths[key] ? 'Pora roku' : 'Miesiąc';
            calendarSearchMap[key] = { type: typeLabel, label: key.charAt(0).toUpperCase() + key.slice(1), data: seasonalMap[key].slice() };
        }
        exactCalendarKeys.add(norm(key));
    });

    function findCalendarAnchor(terms) {
        const keys = Object.keys(calendarSearchMap);
        for (const term of terms) {
            const nt = norm(term).trim();
            if (nt.length < 3) continue;
            const exact = keys.find(k => norm(k) === nt);
            if (exact) return { term, key: exact, entry: calendarSearchMap[exact], exact: exactCalendarKeys.has(nt) };
        }
        for (const term of terms) {
            const nt = norm(term).trim();
            if (nt.length < 4) continue;
            const tw = words(term);
            const partial = keys.find(k => containsAll(norm(k), tw));
            if (partial) return { term, key: partial, entry: calendarSearchMap[partial], exact: false };
        }
        return null;
    }

    // ------------------------------------------
    // KARTA ROŚLINY (wyniki) – z gildiami i kalendarzem miesięcznym
    // ------------------------------------------
    const monthColors = { 1: '#d0e3f0', 2: '#b5d4e9', 3: '#b8d8be', 4: '#95c99d', 5: '#7bbd85', 6: '#e8d87d', 7: '#e6c95c', 8: '#e0a948', 9: '#d9863d', 10: '#b56933', 11: '#8c715c', 12: '#6c8093' };
    const romanMonths = ['', 'I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X', 'XI', 'XII'];

    function renderPlantStatus(plant, month) {
        const tasks = (plant.kalendarz_ogrodnika && plant.kalendarz_ogrodnika.zadania) || [];
        const current = tasks.find(t => t.miesiace && t.miesiace.includes(month));
        const prevM = month - 1 < 1 ? 12 : month - 1;
        const nextM = month + 1 > 12 ? 1 : month + 1;
        const taskText = current ? esc(current.czynnosc) : "<span style='color:#555; font-weight:normal;'>Odpoczynek / brak zadań</span>";
        return `
            <div class="card-status-header">
                <button type="button" class="month-nav" data-m="${prevM}" aria-label="Poprzedni miesiąc"><i class="ra ra-fast-backward"></i> ${romanMonths[prevM]}</button>
                <span>MIESIĄC: <strong>${romanMonths[month]}</strong></span>
                <button type="button" class="month-nav" data-m="${nextM}" aria-label="Następny miesiąc">${romanMonths[nextM]} <i class="ra ra-fast-forward"></i></button>
            </div>
            <div class="card-status-body" style="background-color: ${monthColors[month]};">${taskText}</div>`;
    }

    function simulateHover(targetCard, row) {
        row.querySelectorAll('.guild-mini-card').forEach(c => c.classList.remove('force-hover'));
        targetCard.classList.add('force-hover');
    }

    function buildPlantColumn(plant) {
        const column = document.createElement('div');
        column.className = 'result-column';

        // --- Gildie (towarzysze) nad kartą ---
        const miniRow = document.createElement('div');
        miniRow.className = 'guild-mini-row';
        const compsRaw = (plant.permakultura && plant.permakultura.gildie) || plant.gildie || [];
        const comps = (Array.isArray(compsRaw) ? compsRaw : []).map(g => typeof g === 'string'
            ? { nazwa: g, rola: 'Powiązanie' }
            : { nazwa: g.nazwa || g.name || 'Nieznany gość', rola: g.rola || 'Powiązanie' });

        comps.forEach((comp, index) => {
            const guest = findPlantByName(comp.nazwa);
            const img = guest ? getBestImageUrl(guest) : '';
            const mini = document.createElement('div');
            mini.className = 'guild-mini-card';
            mini.dataset.index = index;
            mini.innerHTML = `
                <div class="guild-mini-img" style="${img ? `background-image:url('${esc(img)}');` : 'background:#5a4f41;'}"></div>
                <div class="guild-mini-title-short">${esc(safeStr(comp.nazwa).split(' ')[0])}</div>
                <div class="guild-mini-expanded">
                    <button type="button" class="guild-nav-btn guild-nav-left" aria-label="Poprzedni"><i class="ra ra-bottom-left"></i></button>
                    <div class="expanded-title">${esc(comp.nazwa)}</div>
                    <div class="expanded-role">${esc(comp.rola)}</div>
                    <button type="button" class="expanded-btn">POKAŻ <i class="ra ra-eye"></i></button>
                    <button type="button" class="guild-nav-btn guild-nav-right" aria-label="Następny"><i class="ra ra-bottom-right"></i></button>
                </div>`;
            const left = mini.querySelector('.guild-nav-left');
            const right = mini.querySelector('.guild-nav-right');
            if (index === 0) left.style.visibility = 'hidden';
            if (index === comps.length - 1) right.style.visibility = 'hidden';
            left.onclick = e => { e.stopPropagation(); const c = miniRow.querySelector(`.guild-mini-card[data-index="${index - 1}"]`); if (c) simulateHover(c, miniRow); };
            right.onclick = e => { e.stopPropagation(); const c = miniRow.querySelector(`.guild-mini-card[data-index="${index + 1}"]`); if (c) simulateHover(c, miniRow); };
            mini.addEventListener('mouseenter', () => simulateHover(mini, miniRow));
            mini.addEventListener('mouseleave', () => mini.classList.remove('force-hover'));
            const go = e => {
                e.stopPropagation();
                if (isDraggingUI) return;
                if (guest) window.location.href = getPlantUrl(guest); else showUnknownPlant(comp.nazwa);
            };
            mini.onclick = go;
            mini.querySelector('.expanded-btn').onclick = go;
            miniRow.appendChild(mini);
        });

        // --- Karta rośliny ---
        const card = document.createElement('div');
        card.className = 'result-card';
        card.tabIndex = 0;
        card.setAttribute('role', 'link');
        card.setAttribute('aria-label', `Otwórz: ${plant.nazwa_pl}`);
        const img = getBestImageUrl(plant);
        const desc = plant.opis || 'Brak szczegółowego opisu zielarskiego.';
        const trivia = Array.isArray(plant.ciekawostki) && plant.ciekawostki.length
            ? plant.ciekawostki[Math.floor(Math.random() * plant.ciekawostki.length)]
            : 'Zioła kryją wiele tajemnic...';
        const triviaText = typeof trivia === 'object' ? flatten(trivia).join(' – ') : trivia;

        let tagsHtml = '';
        (Array.isArray(plant.tagi) ? plant.tagi : []).forEach(raw => {
            const def = TAGS[safeStr(raw).toLowerCase().trim()] || { icon: 'ra-help', desc: raw, color: '#7a6a58' };
            tagsHtml += `<span class="card-emoji" data-bs-toggle="tooltip" title="${esc(def.desc)}" style="border-color:${def.color}; color:${def.color};"><i class="ra ${def.icon}"></i></span>`;
        });

        card.innerHTML = `
            <div class="card-img-container" style="${img ? `background-image:url('${esc(img)}');` : 'background:#d1c7a7;'}">
                <div class="card-tags-row">${tagsHtml}</div>
            </div>
            <h3 class="card-title">${esc(plant.nazwa_pl)}</h3>
            ${latinOf(plant) ? `<div class="card-latin">${esc(latinOf(plant))}</div>` : ''}
            <div class="card-desc-container"><div class="card-desc-scroll">${esc(desc)}<br><br>${esc(desc)}</div></div>
            <div class="card-trivia-container"><div class="card-trivia-scroll">✨ Ciekawostka: ${esc(triviaText)}</div></div>
            <div class="card-status-wrapper"></div>
            <div class="card-btn">ZBADAJ <i class="ra ra-eye"></i></div>`;

        const statusWrapper = card.querySelector('.card-status-wrapper');
        const updateMonthUI = m => {
            statusWrapper.innerHTML = renderPlantStatus(plant, m);
            statusWrapper.querySelectorAll('.month-nav').forEach(btn => {
                btn.onclick = e => { e.stopPropagation(); updateMonthUI(parseInt(btn.getAttribute('data-m'), 10)); };
            });
        };
        updateMonthUI(new Date().getMonth() + 1);

        const open = e => {
            if (e.target.closest('.month-nav') || isDraggingUI) return;
            window.location.href = getPlantUrl(plant);
        };
        card.addEventListener('click', open);
        card.addEventListener('keydown', e => { if (e.key === 'Enter') open(e); });

        if (comps.length) column.appendChild(miniRow);
        column.appendChild(card);
        return column;
    }

    // ------------------------------------------
    // ELEMENTY LIST (zadania, przepisy)
    // ------------------------------------------
    function taskItemHtml(task) {
        const plantName = (task.rosliny && task.rosliny[0]) || '';
        const plant = plantName ? findPlantByName(plantName) : null;
        const href = plant ? getPlantUrl(plant) : '#';
        return `
            <a class="task-card" href="${href}" ${plant ? '' : `data-unknown="${esc(plantName)}"`}>
                <div class="task-card-icon"><i class="ra ${esc(task.icon || 'ra-leaf')}"></i></div>
                <div class="task-card-content">
                    <h4 class="task-card-title">${esc(task.tytul)}</h4>
                    <p class="task-card-desc">${esc(shorten(task.desc, 120))}</p>
                </div>
                <div class="task-card-action">ZBADAJ <i class="ra ra-eye"></i></div>
            </a>`;
    }

    function recipeItemHtml(r) {
        const fromWeb = r._z_sieci || r.siedziba;
        const plantLabel = r.roslina || ingredientNames(r).slice(0, 2).join(', ');
        const desc = r.opis || prepText(r) || 'Brak instrukcji';
        return `
            <a class="task-card task-card-recipe" href="${getRecipeUrl(r.tytul)}">
                <div class="task-card-icon"><i class="ra ra-potion"></i></div>
                <div class="task-card-content">
                    <h4 class="task-card-title">${esc(r.tytul)}${fromWeb ? ' <span class="kw-web-badge" title="Przepis zebrany z sieci przez Siedzibę Kwiatownika">🌐 z sieci</span>' : ''}</h4>
                    ${plantLabel ? `<div class="task-card-meta"><i class="ra ra-leaf"></i> ${esc(shorten(plantLabel, 70))}</div>` : ''}
                    <p class="task-card-desc">${esc(shorten(desc, 120))}</p>
                </div>
                <div class="task-card-action">PRZEPIS <i class="ra ra-scroll-unfurled"></i></div>
            </a>`;
    }

    // ------------------------------------------
    // STAN WYSZUKIWARKI
    // ------------------------------------------
    const input = document.getElementById('universalSearch');
    const tagsBox = document.getElementById('activeTagsContainer');
    const suggBox = document.getElementById('kwSuggestions');
    const resultsBox = document.getElementById('kwResults');
    const quickBox = document.getElementById('kwQuick');
    const clearBtn = document.getElementById('kwClearBtn');
    const searchBar = document.getElementById('kwSearchBar');

    const state = { tags: [], text: '', recipeLimit: 12, plantLimit: 24 };
    let lastResult = null;

    function currentTerms() {
        const terms = state.tags.slice();
        const t = state.text.trim();
        if (t.length >= 2) terms.push(t);
        return terms;
    }

    function computeResults(terms) {
        const anchor = findCalendarAnchor(terms);
        const filterTerms = anchor && anchor.exact ? terms.filter(t => t !== anchor.term) : terms;
        const filterWords = filterTerms.flatMap(words);

        // Rośliny: wszystkie słowa muszą wystąpić; najpierw trafienia w nazwie
        let plants = [];
        if (filterWords.length) {
            plants = plantIndex
                .filter(pi => containsAll(pi.full, filterWords))
                .map(pi => ({ pi, score: filterWords.filter(w => pi.name.includes(w)).length * 10 + filterWords.filter(w => pi.core.includes(w)).length }))
                .sort((a, b) => b.score - a.score || a.pi.plant.nazwa_pl.localeCompare(b.pi.plant.nazwa_pl, 'pl'))
                .map(x => x.pi.plant);
        }
        const plantSet = new Set(plants);
        // Rośliny trafione po nazwie (np. "mniszek") – ich kalendarz pokazujemy nawet bez pory roku
        const namedPlants = plants.filter(p => filterTerms.some(t => containsAll(norm(`${p.nazwa_pl} ${latinOf(p)}`), words(t))));

        // Przepisy
        let recipes = [];
        if (filterWords.length) {
            recipes = recipeIndex
                .filter(ri => containsAll(ri.full, filterWords))
                .map(ri => ({ ri, score: filterWords.filter(w => ri.title.includes(w)).length }))
                .sort((a, b) => b.score - a.score)
                .map(x => x.ri.recipe);
        }

        // Kalendarz / czynności
        let calendar = null;
        if (anchor) {
            let tasks = anchor.entry.data || [];
            if (filterWords.length) {
                tasks = tasks.filter(t => {
                    const p = t.rosliny && t.rosliny[0] ? findPlantByName(t.rosliny[0]) : null;
                    return (p && plantSet.has(p)) || containsAll(norm(`${t.tytul} ${t.desc} ${(t.rosliny || []).join(' ')}`), filterWords);
                });
            }
            calendar = { title: anchor.entry.label || anchor.key, type: anchor.entry.type, icon: anchor.entry.icon, tasks };
        } else if (namedPlants.length && namedPlants.length <= 5) {
            const tasks = [];
            namedPlants.forEach(p => ((p.kalendarz_ogrodnika && p.kalendarz_ogrodnika.zadania) || []).forEach(z => {
                const months = (z.miesiace || []).map(m => romanMonths[m]).filter(Boolean).join(', ');
                tasks.push({ tytul: `${p.nazwa_pl} - ${z.czynnosc}`, desc: (months ? `[${months}] ` : '') + (z.opis || `Czas na: ${z.czynnosc}`), icon: taskIconFor(z.czynnosc), rosliny: [p.nazwa_pl] });
            }));
            if (tasks.length) calendar = { title: 'Kalendarz: ' + namedPlants.map(p => p.nazwa_pl).join(', '), type: 'Kalendarz ogrodnika', tasks };
        }
        if (calendar) {
            const seen = new Set();
            calendar.tasks = calendar.tasks.filter(t => !seen.has(t.tytul) && seen.add(t.tytul));
        }

        // Działanie / objawy
        const effects = [];
        filterTerms.forEach(term => {
            const tw = words(term);
            if (!tw.length || norm(term).trim().length < 3) return;
            symptomKeys.filter(s => containsAll(s.n, tw)).forEach(s => {
                let list = symptomMap[s.key];
                if (filterTerms.length > 1) list = list.filter(p => plantSet.has(p));
                if (list.length && !effects.some(e => e.key === s.key)) effects.push({ key: s.key, plants: list });
            });
        });
        effects.sort((a, b) => b.plants.length - a.plants.length);

        return { terms, anchor, plants, recipes, calendar, effects: effects.slice(0, 8) };
    }

    function sectionTitle(icon, text, count, id) {
        return `<h3 class="kw-sec-title" id="${id}"><i class="ra ${icon}"></i> ${esc(text)} ${count !== null ? `<span class="kw-count">${count}</span>` : ''}</h3>`;
    }

    function renderResults() {
        const terms = currentTerms();
        updateUrl();
        clearBtn.hidden = !(state.tags.length || state.text);

        if (!terms.length) {
            resultsBox.hidden = true;
            resultsBox.innerHTML = '';
            quickBox.hidden = false;
            lastResult = null;
            renderCarousels(PLANTS, defaultRecipeSample());
            return;
        }
        quickBox.hidden = true;

        const res = computeResults(terms);
        lastResult = res;
        const { plants, recipes, calendar, effects } = res;
        const total = plants.length + recipes.length + (calendar ? calendar.tasks.length : 0) + effects.length;

        let html = '';
        const summary = [];
        if (plants.length) summary.push(`<a href="#kwSecPlants">🌿 Rośliny: ${plants.length}</a>`);
        if (effects.length) summary.push(`<a href="#kwSecEffects">⚕ Działanie: ${effects.length}</a>`);
        if (calendar && calendar.tasks.length) summary.push(`<a href="#kwSecCalendar">📅 Kalendarz: ${calendar.tasks.length}</a>`);
        if (recipes.length) summary.push(`<a href="#kwSecRecipes">📜 Przepisy: ${recipes.length}</a>`);
        if (summary.length) html += `<div class="kw-summary" role="navigation" aria-label="Sekcje wyników">${summary.join('')}</div>`;

        if (!total) {
            html += `<div class="kw-empty">
                <i class="ra ra-bleeding-eye"></i>
                <p>Nic nie znaleziono dla: <strong>${esc(terms.join(' + '))}</strong>.</p>
                <p class="kw-empty-hint">${state.tags.length > 1 || (state.tags.length && state.text) ? 'Spróbuj usunąć któryś z filtrów – wszystkie muszą pasować jednocześnie.' : 'Sprawdź pisownię albo spróbuj innego słowa (np. nazwy rośliny, objawu lub miesiąca).'}</p>
            </div>`;
        }

        if (plants.length) {
            html += `<section class="kw-sec">${sectionTitle('ra-leaf', 'Rośliny', plants.length, 'kwSecPlants')}
                <div class="kw-plant-row" id="horizontalResults"></div>
                ${plants.length > state.plantLimit ? `<div class="kw-more"><button type="button" class="kw-more-btn" data-more="plants">Pokaż więcej roślin (${plants.length - state.plantLimit})</button></div>` : ''}
            </section>`;
        }

        if (effects.length) {
            html += `<section class="kw-sec">${sectionTitle('ra-health', 'Rośliny według działania', null, 'kwSecEffects')}<div class="kw-effects">`;
            effects.forEach(e => {
                html += `<div class="kw-effect"><div class="kw-effect-name">${esc(e.key)}</div><div class="kw-effect-plants">` +
                    e.plants.slice(0, 10).map(p => `<a class="kw-plant-chip" href="${getPlantUrl(p)}"><i class="ra ${getWitcherIcon(p)}"></i> ${esc(p.nazwa_pl)}</a>`).join('') +
                    (e.plants.length > 10 ? `<span class="kw-chip-more">+${e.plants.length - 10}</span>` : '') +
                    `</div></div>`;
            });
            html += `</div></section>`;
        }

        if (calendar && calendar.tasks.length) {
            html += `<section class="kw-sec">${sectionTitle(calendar.icon || 'ra-sun', calendar.title, calendar.tasks.length, 'kwSecCalendar')}
                <div class="kw-sec-sub">${esc(calendar.type || '')}</div>
                <div class="kw-list">${calendar.tasks.slice(0, 40).map(taskItemHtml).join('')}</div>
                ${calendar.tasks.length > 40 ? `<p class="kw-sec-sub">…oraz ${calendar.tasks.length - 40} kolejnych. Dodaj filtr (np. nazwę rośliny), aby zawęzić listę.</p>` : ''}
            </section>`;
        }

        if (recipes.length) {
            const przepisyQuery = res.terms.filter(t => !(res.anchor && res.anchor.exact && t === res.anchor.term)).join(' ');
            html += `<section class="kw-sec">${sectionTitle('ra-potion', 'Przepisy', recipes.length, 'kwSecRecipes')}
                <div class="kw-list">${recipes.slice(0, state.recipeLimit).map(recipeItemHtml).join('')}</div>
                <div class="kw-more">
                    ${recipes.length > state.recipeLimit ? `<button type="button" class="kw-more-btn" data-more="recipes">Pokaż więcej przepisów (${recipes.length - state.recipeLimit})</button>` : ''}
                    <a class="kw-more-link" href="/przepisy/?q=${encodeURIComponent(przepisyQuery)}">Otwórz w Przepiśniku <i class="ra ra-cauldron"></i></a>
                </div>
            </section>`;
        }

        resultsBox.innerHTML = html;
        resultsBox.hidden = false;

        const row = document.getElementById('horizontalResults');
        if (row) {
            plants.slice(0, state.plantLimit).forEach(p => row.appendChild(buildPlantColumn(p)));
            enableDragToScroll(row);
        }
        if (window.bootstrap && bootstrap.Tooltip) {
            resultsBox.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => bootstrap.Tooltip.getOrCreateInstance(el));
        }

        renderCarousels(plants, recipes);
    }

    // Kliknięcia w wynikach (delegacja)
    resultsBox.addEventListener('click', e => {
        const more = e.target.closest('.kw-more-btn');
        if (more) {
            if (more.dataset.more === 'recipes') state.recipeLimit += 24;
            if (more.dataset.more === 'plants') state.plantLimit += 24;
            const y = window.scrollY;
            renderResults();
            window.scrollTo({ top: y, behavior: 'instant' });
            return;
        }
        const unknown = e.target.closest('[data-unknown]');
        if (unknown) {
            e.preventDefault();
            if (unknown.dataset.unknown) showUnknownPlant(unknown.dataset.unknown);
            return;
        }
        const jump = e.target.closest('.kw-summary a');
        if (jump) {
            e.preventDefault();
            const target = document.querySelector(jump.getAttribute('href'));
            if (target) window.scrollTo({ top: target.getBoundingClientRect().top + window.scrollY - 130, behavior: 'smooth' });
        }
    });

    // ------------------------------------------
    // FILTRY (TAGI)
    // ------------------------------------------
    function renderTags() {
        tagsBox.innerHTML = '';
        state.tags.forEach((tag, i) => {
            const el = document.createElement('button');
            el.type = 'button';
            el.className = 'search-tag';
            el.title = 'Usuń filtr';
            el.innerHTML = `${esc(tag)} <i class="bi bi-x"></i>`;
            el.onclick = () => { removeTag(i); input.focus(); };
            tagsBox.appendChild(el);
        });
        input.placeholder = state.tags.length ? 'Dodaj kolejne słowo, aby zawęzić…' : 'Np. mniszek, kaszel, jesień, zbiór, syrop…';
    }

    function addTag(text) {
        const t = safeStr(text).trim();
        if (!t) return;
        if (!state.tags.some(x => norm(x) === norm(t))) state.tags.push(t);
        state.text = '';
        input.value = '';
        state.recipeLimit = 12; state.plantLimit = 24;
        renderTags();
        hideSuggestions();
        renderResults();
    }

    function removeTag(index) {
        state.tags.splice(index, 1);
        renderTags();
        renderResults();
    }

    function setTags(list) {
        state.tags = [];
        list.forEach(t => { if (t && !state.tags.some(x => norm(x) === norm(t))) state.tags.push(t.trim()); });
        state.text = '';
        input.value = '';
        renderTags();
        hideSuggestions();
        renderResults();
    }

    function clearAll() {
        state.tags = []; state.text = ''; input.value = '';
        renderTags(); hideSuggestions(); renderResults();
        input.focus();
    }
    clearBtn.addEventListener('click', clearAll);

    function updateUrl() {
        try {
            const params = new URLSearchParams();
            state.tags.forEach(t => params.append('q', t));
            const qs = params.toString();
            history.replaceState(null, '', window.location.pathname + (qs ? '?' + qs : '') + window.location.hash);
        } catch (e) { /* brak History API – bez znaczenia */ }
    }

    // ------------------------------------------
    // PODPOWIEDZI (AUTOUZUPEŁNIANIE)
    // ------------------------------------------
    const suggestionPool = [];
    PLANTS.forEach(p => suggestionPool.push({ label: p.nazwa_pl, sub: latinOf(p), value: p.nazwa_pl, cat: 'Roślina', icon: getWitcherIcon(p), n: norm(`${p.nazwa_pl} ${latinOf(p)}`) }));
    const seenCal = new Set();
    Object.keys(calendarSearchMap).forEach(k => {
        const entry = calendarSearchMap[k];
        if (seenCal.has(entry)) return;
        seenCal.add(entry);
        const n = norm(k + ' ' + (entry.keywords ? entry.keywords.join(' ') : '') + ' ' + (entry.label || ''));
        suggestionPool.push({ label: entry.label || k, sub: `${entry.type} · ${entry.data.length} zadań`, value: k, cat: 'Czas', icon: entry.icon || 'ra-sun', n });
    });
    symptomKeys
        .filter(s => s.key.length <= 40)
        .sort((a, b) => symptomMap[b.key].length - symptomMap[a.key].length)
        .forEach(s => suggestionPool.push({ label: s.key, sub: `${symptomMap[s.key].length} roślin`, value: s.key, cat: 'Działanie', icon: 'ra-health', n: s.n }));
    RECIPES.forEach(r => suggestionPool.push({ label: r.tytul, sub: r.roslina || '', href: getRecipeUrl(r.tytul), cat: 'Przepis', icon: 'ra-potion', n: norm(r.tytul) }));

    const CAT_LIMITS = { 'Roślina': 4, 'Czas': 3, 'Działanie': 3, 'Przepis': 3 };
    const CAT_LABELS = { 'Roślina': 'Roślina', 'Czas': 'Czas / czynność', 'Działanie': 'Działanie / objaw', 'Przepis': 'Przepis – otwórz' };
    let suggestions = [];
    let activeSugg = -1;

    function getSuggestions(text) {
        const q = norm(text).trim();
        if (q.length < 2) return [];
        const used = new Set(state.tags.map(norm));
        const scored = [];
        suggestionPool.forEach(s => {
            if (used.has(norm(s.value || ''))) return;
            const i = s.n.indexOf(q);
            if (i < 0) return;
            const score = i === 0 ? 0 : (/[^a-z0-9]/.test(s.n[i - 1]) ? 1 : 2);
            scored.push({ s, score });
        });
        scored.sort((a, b) => a.score - b.score || a.s.label.length - b.s.label.length);
        const counts = {};
        const out = [];
        scored.forEach(({ s }) => {
            counts[s.cat] = (counts[s.cat] || 0) + 1;
            if (counts[s.cat] <= CAT_LIMITS[s.cat]) out.push(s);
        });
        const order = ['Roślina', 'Czas', 'Działanie', 'Przepis'];
        return out.sort((a, b) => order.indexOf(a.cat) - order.indexOf(b.cat));
    }

    function renderSuggestions() {
        suggestions = getSuggestions(state.text);
        activeSugg = -1;
        if (!suggestions.length) { hideSuggestions(); return; }
        let html = '';
        let lastCat = '';
        suggestions.forEach((s, i) => {
            if (s.cat !== lastCat) { html += `<div class="kw-sugg-cat">${esc(CAT_LABELS[s.cat])}</div>`; lastCat = s.cat; }
            html += `<div class="kw-sugg-item" role="option" id="kwSugg${i}" data-i="${i}">
                <i class="ra ${esc(s.icon)}"></i>
                <span class="kw-sugg-label">${esc(s.label)}</span>
                ${s.sub ? `<span class="kw-sugg-sub">${esc(shorten(s.sub, 40))}</span>` : ''}
            </div>`;
        });
        suggBox.innerHTML = html;
        suggBox.hidden = false;
        input.setAttribute('aria-expanded', 'true');
    }

    function hideSuggestions() {
        suggBox.hidden = true;
        suggBox.innerHTML = '';
        suggestions = [];
        activeSugg = -1;
        input.setAttribute('aria-expanded', 'false');
        input.removeAttribute('aria-activedescendant');
    }

    function highlightSuggestion(i) {
        const items = suggBox.querySelectorAll('.kw-sugg-item');
        items.forEach(el => el.classList.remove('active'));
        activeSugg = i;
        if (i >= 0 && items[i]) {
            items[i].classList.add('active');
            items[i].scrollIntoView({ block: 'nearest' });
            input.setAttribute('aria-activedescendant', items[i].id);
        }
    }

    function pickSuggestion(i) {
        const s = suggestions[i];
        if (!s) return;
        if (s.href) { window.location.href = s.href; return; }
        addTag(s.value || s.label);
    }

    suggBox.addEventListener('mousedown', e => e.preventDefault()); // nie trać fokusu inputa
    suggBox.addEventListener('click', e => {
        const item = e.target.closest('.kw-sugg-item');
        if (item) pickSuggestion(parseInt(item.dataset.i, 10));
    });

    // ------------------------------------------
    // OBSŁUGA POLA WYSZUKIWANIA
    // ------------------------------------------
    let debounceId = null;
    input.addEventListener('input', () => {
        state.text = input.value;
        state.recipeLimit = 12; state.plantLimit = 24;
        renderSuggestions();
        clearTimeout(debounceId);
        debounceId = setTimeout(() => {
            const y = window.scrollY; // bez skakania ekranu
            renderResults();
            window.scrollTo({ top: y, behavior: 'instant' });
        }, 120);
    });

    input.addEventListener('keydown', e => {
        if (e.key === 'ArrowDown' && suggestions.length) {
            e.preventDefault();
            highlightSuggestion((activeSugg + 1) % suggestions.length);
        } else if (e.key === 'ArrowUp' && suggestions.length) {
            e.preventDefault();
            highlightSuggestion(activeSugg <= 0 ? suggestions.length - 1 : activeSugg - 1);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (activeSugg >= 0) pickSuggestion(activeSugg);
            else if (input.value.trim()) addTag(input.value);
        } else if (e.key === 'Escape') {
            hideSuggestions();
        } else if (e.key === 'Backspace' && !input.value && state.tags.length) {
            removeTag(state.tags.length - 1);
        }
    });

    input.addEventListener('blur', () => setTimeout(hideSuggestions, 150));
    input.addEventListener('focus', () => { if (state.text.trim().length >= 2) renderSuggestions(); });
    searchBar.addEventListener('click', e => { if (e.target === searchBar || e.target === tagsBox) input.focus(); });

    // ------------------------------------------
    // SZYBKIE PODPOWIEDZI (gdy pole jest puste)
    // ------------------------------------------
    function renderQuick() {
        const m = new Date().getMonth() + 1;
        const season = Object.keys(seasonMonths).find(s => seasonMonths[s].includes(m));
        const chips = [];
        const mName = monthNames[m];
        if (calendarSearchMap[mName]) chips.push({ label: `Ten miesiąc: ${mName}`, value: mName, icon: 'ra-hourglass' });
        if (calendarSearchMap[season]) chips.push({ label: `Pora roku: ${season}`, value: season, icon: 'ra-sun' });
        ['zbiór', 'sadzenie'].forEach(k => { if (calendarSearchMap[k]) chips.push({ label: k, value: k, icon: calendarSearchMap[k].icon }); });
        ['przeziębienie', 'kaszel', 'odporność', 'rany', 'syrop'].forEach(k => chips.push({ label: k, value: k, icon: 'ra-health' }));
        quickBox.innerHTML = '<span class="kw-quick-label">Spróbuj:</span>' + chips.map(c =>
            `<button type="button" class="kw-quick-chip" data-value="${esc(c.value)}"><i class="ra ${esc(c.icon)}"></i> ${esc(c.label)}</button>`).join('') +
            `<button type="button" class="kw-quick-chip kw-quick-lens"><i class="bi bi-camera"></i> rozpoznaj ze zdjęcia</button>`;
    }
    quickBox.addEventListener('click', e => {
        const chip = e.target.closest('.kw-quick-chip');
        if (!chip) return;
        if (chip.classList.contains('kw-quick-lens')) {
            const btn = document.getElementById('magicLensBtn');
            if (btn) btn.click();
            return;
        }
        addTag(chip.dataset.value);
    });

    // ------------------------------------------
    // ROZPOZNAWANIE ZE ZDJĘCIA – integracja z magic_lens.js
    // ------------------------------------------
    // magic_lens.js woła tę funkcję po rozpoznaniu; zwracamy nazwę, którą ma pokazać modal
    window.onPlantRecognized = function (result) {
        const latin = safeStr(result && result.latin);
        const polish = safeStr(result && result.polish);
        const latinKey = norm(latin).split(/\s+/).slice(0, 2).join(' ');
        const genus = latinKey.split(' ')[0];

        let plant = null;
        let how = '';
        if (latinKey) plant = PLANTS.find(p => latinOf(p) && norm(latinOf(p)).startsWith(latinKey));
        if (plant) how = 'exact';
        if (!plant && polish) { plant = findPlantByName(polish); if (plant) how = 'exact'; }
        if (!plant && genus.length > 2) {
            plant = PLANTS.find(p => latinOf(p) && norm(latinOf(p)).split(/\s+/)[0] === genus);
            if (plant) how = 'genus';
        }

        const name = plant && how === 'exact' ? plant.nazwa_pl : (polish || latin);
        // przy dopasowaniu tylko do rodzaju szukamy spokrewnionej rośliny z Bestiariusza
        setTags([plant ? plant.nazwa_pl : name]);

        const latinEl = document.getElementById('recognizedLatin');
        const infoEl = document.getElementById('recognizedInfo');
        const linkEl = document.getElementById('recognizedOpenLink');
        if (latinEl) latinEl.textContent = latin && norm(latin) !== norm(name) ? latin : '';
        if (infoEl) {
            if (how === 'exact') infoEl.textContent = 'Ta roślina jest w Bestiariuszu – wyniki poniżej.';
            else if (how === 'genus') infoEl.textContent = `Tego gatunku nie ma jeszcze w Bestiariuszu. Najbliżej spokrewniona roślina z tego samego rodzaju: ${plant.nazwa_pl}.`;
            else infoEl.textContent = 'Tej rośliny nie ma jeszcze w Bestiariuszu – szukam jej w przepisach i opisach.';
        }
        if (linkEl) {
            if (plant) { linkEl.href = getPlantUrl(plant); linkEl.hidden = false; }
            else linkEl.hidden = true;
        }
        return name;
    };

    // Wklejanie (Ctrl+V) i upuszczanie zdjęcia na wyszukiwarkę
    function firstImage(items) {
        for (const it of items || []) {
            const f = it.kind === 'file' ? it.getAsFile() : (it instanceof File ? it : null);
            if (f && f.type && f.type.startsWith('image/')) return f;
        }
        return null;
    }
    input.addEventListener('paste', e => {
        const img = firstImage(e.clipboardData && e.clipboardData.items);
        if (img && typeof window.kwRecognizeFile === 'function') { e.preventDefault(); window.kwRecognizeFile(img); }
    });
    const dropHint = document.getElementById('kwDropHint');
    searchBar.addEventListener('dragover', e => {
        if (e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files')) {
            e.preventDefault(); searchBar.classList.add('kw-drag'); if (dropHint) dropHint.hidden = false;
        }
    });
    searchBar.addEventListener('dragleave', () => { searchBar.classList.remove('kw-drag'); if (dropHint) dropHint.hidden = true; });
    searchBar.addEventListener('drop', e => {
        searchBar.classList.remove('kw-drag'); if (dropHint) dropHint.hidden = true;
        const img = firstImage(e.dataTransfer && e.dataTransfer.files);
        if (img && typeof window.kwRecognizeFile === 'function') { e.preventDefault(); window.kwRecognizeFile(img); }
    });

    // ------------------------------------------
    // KARUZELE (Bestiariusz / Księga Przepisów) – te same wyniki co wyszukiwarka
    // ------------------------------------------
    const plantsCarousel = document.getElementById('plantsCarousel');
    const recipesCarousel = document.getElementById('recipesCarousel');

    function defaultRecipeSample() {
        const copy = RECIPES.slice();
        for (let i = copy.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [copy[i], copy[j]] = [copy[j], copy[i]]; }
        return copy.slice(0, 40);
    }
    const RECIPE_SAMPLE = defaultRecipeSample();

    function miniCardHtml(item, type, hidden) {
        const extra = hidden ? ' aria-hidden="true" tabindex="-1"' : '';
        if (type === 'plant') {
            const img = getBestImageUrl(item);
            return `<a class="mini-card" href="${getPlantUrl(item)}"${extra}>
                <div class="mini-card-img" style="${img ? `background-image:url('${esc(img)}');` : 'background:#d1c7a7;'}"></div>
                <h4>${esc(item.nazwa_pl)}</h4>
            </a>`;
        }
        return `<a class="mini-card" href="${getRecipeUrl(item.tytul)}"${extra}>
            <i class="ra ra-potion mini-card-icon"></i>
            <h4>${esc(shorten(item.tytul, 60))}</h4>
            ${item.roslina ? `<span class="mini-card-sub">${esc(item.roslina)}</span>` : ''}
        </a>`;
    }

    function drawCarousel(container, items, type, countEl, totalCount) {
        if (!container) return;
        if (countEl) countEl.textContent = currentTerms().length ? `(${totalCount})` : '';
        if (!items.length) {
            container.innerHTML = '<span class="kw-carousel-empty">Brak wyników w tej kategorii.</span>';
        } else {
            const list = items.slice(0, 60);
            const once = list.map(i => miniCardHtml(i, type, false)).join('');
            // podwójna zawartość = płynna, nieskończona pętla (tylko gdy jest co przewijać)
            container.innerHTML = list.length >= 6 ? once + list.map(i => miniCardHtml(i, type, true)).join('') : once;
            container.dataset.loop = list.length >= 6 ? '1' : '0';
        }
        const wrapper = container.parentElement;
        if (wrapper) wrapper.scrollLeft = 0;
    }

    function renderCarousels(plants, recipes) {
        drawCarousel(plantsCarousel, plants, 'plant', document.getElementById('plantsCarouselCount'), plants.length);
        const recipeItems = currentTerms().length ? recipes : RECIPE_SAMPLE;
        drawCarousel(recipesCarousel, recipeItems, 'recipe', document.getElementById('recipesCarouselCount'), recipes.length);
    }

    function autoScroll(wrapperId) {
        const wrapper = document.getElementById(wrapperId);
        if (!wrapper) return;
        const content = wrapper.querySelector('.auto-scroll-content');
        let animationId = null, isPaused = false, isVisible = false, pos = 0;
        const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (reduceMotion) return;

        const observer = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                isVisible = entry.isIntersecting;
                if (isVisible && !animationId) start();
            });
        }, { threshold: 0.1 });
        observer.observe(wrapper);

        const pause = () => { isPaused = true; };
        const resume = () => { isPaused = false; pos = wrapper.scrollLeft; };
        wrapper.addEventListener('mouseenter', pause);
        wrapper.addEventListener('mouseleave', resume);
        wrapper.addEventListener('focusin', pause);
        wrapper.addEventListener('focusout', resume);
        wrapper.addEventListener('touchstart', pause, { passive: true });
        wrapper.addEventListener('touchend', () => setTimeout(resume, 1500), { passive: true });

        function start() {
            if (animationId) return;
            pos = wrapper.scrollLeft;
            const step = () => {
                if (!isVisible) { animationId = null; return; }
                if (!isPaused && content.dataset.loop === '1') {
                    pos += 0.6;
                    const half = wrapper.scrollWidth / 2;
                    if (pos >= half) pos -= half;
                    wrapper.scrollLeft = pos;
                }
                animationId = requestAnimationFrame(step);
            };
            animationId = requestAnimationFrame(step);
        }
    }

    // ------------------------------------------
    // BESTIARIUSZ – cała karta jest linkiem, napis "Zbadaj" zostaje
    // ------------------------------------------
    function renderBestiary() {
        const grid = document.getElementById('bestiaryGrid');
        if (!grid) return;
        grid.innerHTML = PLANTS
            .slice()
            .sort((a, b) => a.nazwa_pl.localeCompare(b.nazwa_pl, 'pl'))
            .map(plant => {
                const img = getBestImageUrl(plant);
                return `<a class="witcher-card" href="${getPlantUrl(plant)}" aria-label="Zbadaj: ${esc(plant.nazwa_pl)}">
                    <div class="witcher-card-img" style="${img ? `background-image:url('${esc(img)}');` : 'background:#3a2b21;'}"></div>
                    <div class="witcher-card-content">
                        <h3 class="witcher-card-title">${esc(plant.nazwa_pl)}</h3>
                        ${latinOf(plant) ? `<p class="witcher-card-latin">${esc(latinOf(plant))}</p>` : ''}
                        <p class="witcher-card-desc">${esc(plant.rodzina || '')}</p>
                    </div>
                    <span class="witcher-btn">Zbadaj <i class="ra ra-eye"></i></span>
                </a>`;
            }).join('');
    }

    // ------------------------------------------
    // START
    // ------------------------------------------
    renderBestiary();
    renderQuick();
    renderTags();

    let initialTags = [];
    try { initialTags = new URLSearchParams(window.location.search).getAll('q').map(s => s.trim()).filter(Boolean); } catch (e) { /* ignore */ }

    function init() {
        if (initialTags.length) setTags(initialTags);
        else renderResults();
        autoScroll('plantsWrapper');
        autoScroll('recipesWrapper');
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
