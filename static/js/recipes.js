// ==========================================
// 1. SŁOWNIKI POJĘĆ DLA TOOLTIPÓW
// ==========================================
const dict = {
    "Matryca Wu Xing": "Tradycyjna Medycyna Chińska. Dzieli choroby i zioła na 5 żywiołów (Drzewo, Ogień, Ziemia, Metal, Woda). Leczenie polega na równoważeniu tych żywiołów.",
    "Triada Kampo": "Japońska koncepcja medyczna dzieląca zdrowie na 3 strumienie: KI (Energia życiowa/nerwy), KETSU (Krew/krążenie) oraz SUI (Płyny ustrojowe/limfa).",
    "Alchemia Spageryczna": "Starożytna sztuka rozdzielania zioła na olejek (Duszę), alkohol (Ducha) i popiół (Ciało mineralne), by połączyć je w spotęgowany eliksir.",
    "Doktryna Sygnatur": "Dawne wierzenie, według którego wygląd, kolor lub środowisko życia rośliny zdradza, jaki organ ludzki ona leczy.",
    "Humory Galena": "Grecko-rzymska medycyna czterech humorów (krew, flegma, żółć żółta, żółć czarna). Zioła mają jakości: ciepłe/zimne i suche/wilgotne w stopniach od I do IV.",
    "Skalowanie Toksykologiczne": "Określa stopień niebezpieczeństwa i siłę działania receptury, od ziół łagodnych (normalizujących) po heroiczne (ekstremalnie silne, potencjalnie toksyczne)."
};

// Bez filarow, smakow ajurwedy i tropizmu - nie wyswietlamy tych pol (nie maja zrodel dla ziol europejskich).

const kampoDict = {
    "ki": "Ki (Energia): Siła życiowa, impulsy nerwowe i napęd organizmu. Jej zastój powoduje nagły ból, napięcie, drgawki i skurcze.",
    "ketsu": "Ketsu (Krew): Fizyczne krążenie i odżywienie tkanek. Jej zablokowanie powoduje ciemne krwiaki, stwardnienia i kłujący ból.",
    "sui": "Sui (Płyny): Limfa, pot, śluz i woda. Zapewnia nawilżenie. Jej nadmiar to obrzęki i wysięki, a brak to suchość i pękanie skóry.",
    "tokuso": "Tokuso (Toksyny): Szkodliwe zastoje ropne, martwica, zakażenia lub obce jady w organizmie, które należy kategorycznie wydalić."
};

// ==========================================
// 2. FUNKCJE POMOCNICZE
// ==========================================
// Tresci z internetu (Siedziba Kwiatownika) wstawiamy przez innerHTML - zawsze je escapujemy.
// Pary [etykieta, wartosc] -> "<strong>etykieta:</strong> wartosc" tylko dla niepustych wartosci.
function labeledRows(pairs, sep = '<br><br>') {
    return pairs.filter(p => p[1]).map(p => (p[0] ? `<strong>${p[0]}:</strong> ` : '') + esc(p[1])).join(sep);
}
function subDetails(summary, content) {
    return content ? `
                    <details class="grimoire-subdetails">
                        <summary>${summary}</summary>
                        <div class="subdetails-content">${content}</div>
                    </details>` : '';
}
function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"']/g, ch => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[ch]));
}

function safeUrl(url) {
    return (typeof url === 'string' && /^https?:\/\//i.test(url)) ? url : null;
}

// Zrodla przepisu: stare przepisy maja liste napisow, przepisy z Siedziby - liste obiektow {nazwa, url, ...}
function normalizeSources(recipe) {
    let list = [];
    if (Array.isArray(recipe.zrodla)) list = recipe.zrodla;
    else if (recipe.zrodla) list = [recipe.zrodla];
    if (recipe.zrodlo) list = list.concat([recipe.zrodlo]);
    return list.filter(Boolean).map(z => {
        if (typeof z === 'object') {
            return {name: z.nazwa || z.url || 'Źródło', url: safeUrl(z.url), title: z.tytul_oryginalny || '',
                    lang: z.jezyk || '', date: z.data_pobrania || ''};
        }
        const url = safeUrl(z.trim());
        return {name: url ? url.replace(/^https?:\/\/(www\.)?/i, '').split('/')[0] : z, url: url, title: '', lang: '', date: ''};
    });
}
function getContextTooltip(title, text) {
    if(!text) return '';
    return `<span class="info-tooltip">?<span class="tooltip-text"><strong>${title}</strong><br>${text}</span></span>`;
}

function extractContext(fullText) {
    let match = fullText.match(/^(.*?)\s*\((.*?)\)$/);
    if (match) {
        return { name: match[1], desc: match[2] };
    }
    return { name: fullText, desc: '' };
}

function getDictContext(value, dictObj) {
    if(!value) return { name: '', desc: '' };
    let cleanName = value.replace(/_/g, ' ');
    let desc = '';
    for (let key in dictObj) {
        if (value.toLowerCase().includes(key)) {
            desc += dictObj[key] + " ";
        }
    }
    if (cleanName.includes('_')) cleanName = cleanName.split('_')[1];
    return { name: cleanName, desc: desc.trim() };
}

// ==========================================
// 3. GŁÓWNA FUNKCJA MODALA GRYMUARU
// ==========================================
// Pełny przepis nie siedzi już w karcie (strona ważyła 10 MB) – pobieramy go przy otwarciu grymuaru
// z /api/przepis/<nr>.json (data-src przycisku). Stary format (data-recipe w przycisku) nadal działa.
const recipeCache = new Map();
window.openRecipeModal = function(buttonElement) {
    const raw = buttonElement.getAttribute('data-recipe');
    if (raw) {
        try { showRecipeModal(JSON.parse(raw)); } catch (e) { console.error("Błąd przetwarzania przepisu:", e); }
        return Promise.resolve();
    }
    const url = buttonElement.getAttribute('data-src');
    if (!url) return Promise.resolve();
    if (recipeCache.has(url)) { showRecipeModal(recipeCache.get(url)); return Promise.resolve(); }
    if (buttonElement.classList.contains('is-loading')) return Promise.resolve();
    const label = buttonElement.innerHTML;
    buttonElement.classList.add('is-loading');
    buttonElement.innerHTML = 'Otwieram grymuar…';
    return fetch(url)
        .then(r => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status))))
        .then(recipe => { recipeCache.set(url, recipe); showRecipeModal(recipe); })
        .catch(e => {
            console.error("Nie udało się pobrać przepisu:", e);
            buttonElement.innerHTML = 'Nie udało się otworzyć – spróbuj ponownie';
            setTimeout(() => { buttonElement.innerHTML = label; }, 2500);
            buttonElement.classList.remove('is-loading');
            return;
        })
        .finally(() => {
            if (buttonElement.innerHTML === 'Otwieram grymuar…') buttonElement.innerHTML = label;
            buttonElement.classList.remove('is-loading');
        });
};

function showRecipeModal(recipe) {
    try {
        // --- OBSŁUGA ULUBIONYCH (ZAPIS W LOCALSTORAGE) ---
        const recipeTitle = recipe.tytul || "Nieznana Receptura";
        const btnToggleFav = document.getElementById('btnToggleRecipeFav');
        const favIcon = document.getElementById('recipeFavIcon');

        if (btnToggleFav && favIcon) {
            let currentFavs = JSON.parse(localStorage.getItem("recipeFavorites")) || [];

            // Sprawdź stan początkowy
            if (currentFavs.includes(recipeTitle)) {
                favIcon.classList.replace('bi-heart', 'bi-heart-fill');
                btnToggleFav.innerHTML = `<i class="bi bi-heart-fill" id="recipeFavIcon"></i> Zapisano`;
            } else {
                favIcon.classList.replace('bi-heart-fill', 'bi-heart');
                btnToggleFav.innerHTML = `<i class="bi bi-heart" id="recipeFavIcon"></i> Dodaj`;
            }

            // Odświeżanie event listenera (usuwamy stary, dodajemy nowy)
            const newBtn = btnToggleFav.cloneNode(true);
            btnToggleFav.parentNode.replaceChild(newBtn, btnToggleFav);

            newBtn.addEventListener('click', function() {
                let favs = JSON.parse(localStorage.getItem("recipeFavorites")) || [];
                if (favs.includes(recipeTitle)) {
                    favs = favs.filter(r => r !== recipeTitle);
                    this.innerHTML = `<i class="bi bi-heart" id="recipeFavIcon"></i> Dodaj`;
                } else {
                    favs.push(recipeTitle);
                    this.innerHTML = `<i class="bi bi-heart-fill" id="recipeFavIcon"></i> Zapisano`;
                }
                localStorage.setItem("recipeFavorites", JSON.stringify(favs));
                if(typeof renderFavoritesDropdown === 'function') renderFavoritesDropdown();
                sortResultsByFavorites(); // Odśwież widok listy
            });
        }
        // --- TYTUŁ I POCHODZENIE ---
        document.getElementById('modalRecipeTitle').innerText = recipe.tytul || "Nieznana Receptura";
        if (window.KwStats) KwStats.track('recipe_open', recipe.id || recipe.tytul || '');

        // Źródło (pierwsze z adresem) widoczne od razu pod tytułem; pełna lista w "📚 Źródła" niżej
        const sourceLine = document.getElementById('modalSourceLine');
        if (sourceLine) {
            const all = normalizeSources(recipe).filter(z => z.url || (z.name && String(z.name).length > 3 && !/^\d+$/.test(z.name)));
            const withUrl = all.filter(z => z.url);
            if (withUrl.length) {
                const first = withUrl[0];
                const domain = first.url.replace(/^https?:\/\/(www\.)?/i, '').split('/')[0];
                sourceLine.innerHTML = `<i class="bi bi-link-45deg" aria-hidden="true"></i> Źródło: `
                    + `<a href="${esc(first.url)}" target="_blank" rel="noopener nofollow" data-kw-src="${esc(domain)}">${esc(first.name || domain)} ↗</a>`
                    + (all.length > 1 ? ` <span class="recipe-source-more">+${all.length - 1}</span>` : '');
            } else if (all.length) {
                sourceLine.innerHTML = `<i class="bi bi-book" aria-hidden="true"></i> Źródło: ${esc(String(all[0].name).slice(0, 90))}`
                    + (all.length > 1 ? ` <span class="recipe-source-more">+${all.length - 1}</span>` : '');
            } else {
                sourceLine.innerHTML = `<i class="bi bi-book" aria-hidden="true"></i> Źródło: księga Kwiatownika`;
            }
            sourceLine.hidden = false;
        }

        const originTags = document.getElementById('modalOriginTags');
        const tooltipText = document.getElementById('modalOriginTooltipText');

        let tagsHtml = "";
        let plainTextTags = "";

        if(recipe.pochodzenie) {
            let origins = Array.isArray(recipe.pochodzenie) ? recipe.pochodzenie : [recipe.pochodzenie];
            origins.forEach(p => {
                let clean = esc(String(p).replace('[', '').replace(']', ''));
                tagsHtml += `<span class="alchemical-tag">${clean}</span>`;
                plainTextTags += `${clean}<br>`;
            });
        }
        if(recipe._z_sieci) {
            tagsHtml += `<span class="alchemical-tag web-tag" title="Przepis zebrany z internetu i przetłumaczony przez Siedzibę Kwiatownika">🌐 Z sieci</span>`;
            plainTextTags += `Z sieci (przetłumaczony)<br>`;
        }
        if(recipe.mechanizm_tworzenia) {
            let mechanisms = (Array.isArray(recipe.mechanizm_tworzenia) ? recipe.mechanizm_tworzenia : [recipe.mechanizm_tworzenia])
                .filter(m => !/filar/i.test(String(m)));   // "Wzorzec 5 filarów" nie jest wyswietlany
            mechanisms.forEach(m => {
                tagsHtml += `<span class="alchemical-tag" style="background:#f4f1ea; border-color:#d1c7a7; color:#b8860b;">${esc(m)}</span>`;
                plainTextTags += `${esc(m)}<br>`;
            });
        }

        originTags.innerHTML = tagsHtml;
        tooltipText.innerHTML = `<strong>Pochodzenie i System:</strong><br>${plainTextTags}`;

        // --- O PRZEPISIE (opis, metoda, porcje, czas, roślina, tagi) ---
        const infoContainer = document.getElementById('modalInfoContainer');
        if (infoContainer) {
            let facts = [];
            if (recipe.roslina) {
                const plantLink = recipe.slug ? `<a href="/plant/${encodeURIComponent(recipe.slug)}/">${esc(recipe.roslina)}</a>` : esc(recipe.roslina);
                facts.push(`<span><strong>Roślina:</strong> ${plantLink}</span>`);
            }
            if (recipe.metoda) facts.push(`<span><strong>Metoda:</strong> ${esc(recipe.metoda)}</span>`);
            if (recipe.porcje) facts.push(`<span><strong>Porcje:</strong> ${esc(recipe.porcje)}</span>`);
            if (recipe.czas_przygotowania) facts.push(`<span><strong>Czas:</strong> ${esc(recipe.czas_przygotowania)}</span>`);
            const tags = Array.isArray(recipe.tagi) ? recipe.tagi.filter(t => typeof t === 'string' && t) : [];
            let infoHtml = '';
            if (recipe.opis) infoHtml += `<p class="recipe-description">${esc(recipe.opis)}</p>`;
            if (facts.length) infoHtml += `<div class="recipe-facts">${facts.join('')}</div>`;
            if (tags.length) infoHtml += `<div class="recipe-tags">${tags.map(t => `<span class="alchemical-tag">#${esc(t)}</span>`).join('')}</div>`;
            infoContainer.innerHTML = infoHtml;
        }

        // --- ZASTOSOWANIE I DAWKOWANIE ---
        const dosageContainer = document.getElementById('modalDosageContainer');
        if(recipe.stosowanie_i_dawkowanie) {
            const sd = recipe.stosowanie_i_dawkowanie;
            const rows = [["Kiedy stosować", sd.okolicznosci_stosowania], ["Jak dawkować", sd.dawkowanie_standardowe],
                          ["Dla pacjenta", sd.skalowanie_pacjenta]].filter(r => r[1]);   // bez "undefined" dla brakujacych pol
            dosageContainer.innerHTML = rows.length ? `
                <details class="grimoire-details" open>
                    <summary>🩺 Zastosowanie i Dawkowanie</summary>
                    <div class="details-content details-highlight">
                        ${rows.map((r, i) => `<p style="margin-bottom:${i === rows.length - 1 ? 0 : 10}px;"><strong>${r[0]}:</strong> ${esc(r[1])}</p>`).join('')}
                    </div>
                </details>` : '';
        } else if (recipe.dawkowanie) {
            dosageContainer.innerHTML = `
                <details class="grimoire-details" open>
                    <summary>🩺 Dawkowanie</summary>
                    <div class="details-content details-highlight">${esc(recipe.dawkowanie)}</div>
                </details>`;
        } else {
            dosageContainer.innerHTML = '';
        }

        // --- WŁAŚCIWOŚCI FIZYCZNE ---
        const propsContainer = document.getElementById('modalPropertiesContainer');
        if(recipe.wlasciwosci_fizyczne) {
            const wf = recipe.wlasciwosci_fizyczne;
            propsContainer.innerHTML = `
                <details class="grimoire-details">
                    <summary>👁️ Właściwości fizyczne i ślady</summary>
                    <div class="details-content" style="padding: 10px 20px;">
                        ${subDetails('Konsystencja i zapach', esc(wf.konsystencja_i_slady || ''))}
                        ${subDetails('Ślady na skórze', esc(wf.barwienie_skory || ''))}
                        ${subDetails('Ślady na odzieży', esc(wf.barwienie_ubran || ''))}
                    </div>
                </details>`;
        } else {
            propsContainer.innerHTML = '';
        }

        // --- BEZPIECZEŃSTWO I SZAMANIZM ---
        const warnContainer = document.getElementById('modalWarningsContainer');
        let warnHtml = "";
        if(recipe.bezpieczenstwo_i_interakcje || recipe.wymogi_szamanskie_i_czasowe || recipe.uwagi) {
            warnHtml += `<details class="grimoire-details">
                            <summary style="color: #c62828;">⚠️ Bezpieczeństwo i Wymogi</summary>
                            <div class="details-content details-warning" style="padding: 10px 20px;">`;

            if(recipe.bezpieczenstwo_i_interakcje) {
                warnHtml += `
                    <details class="grimoire-subdetails">
                        <summary>Ostrzeżenia i Interakcje</summary>
                        <div class="subdetails-content">
                            ${labeledRows([["Ostrzeżenia", recipe.bezpieczenstwo_i_interakcje.ostrzezenia],
                                           ["Interakcje", recipe.bezpieczenstwo_i_interakcje.interakcje_z_lekami]])}
                        </div>
                    </details>`;
            }
            if(recipe.wymogi_szamanskie_i_czasowe) {
                warnHtml += `
                    <details class="grimoire-subdetails">
                        <summary>Wymogi Czasowe i Zakazy</summary>
                        <div class="subdetails-content">
                            ${labeledRows([["Aplikacja", recipe.wymogi_szamanskie_i_czasowe.chronoterapia],
                                           ["Czas zbioru", recipe.wymogi_szamanskie_i_czasowe.astrologia_zbioru],
                                           ["Zakazy", recipe.wymogi_szamanskie_i_czasowe.dieta_i_zakazy]])}
                        </div>
                    </details>`;
            }
            if(recipe.uwagi) {
                warnHtml += `
                    <details class="grimoire-subdetails">
                        <summary>Uwagi ogólne</summary>
                        <div class="subdetails-content">${esc(recipe.uwagi)}</div>
                    </details>`;
            }
            warnHtml += `</div></details>`;
            warnContainer.innerHTML = warnHtml;
        } else {
            warnContainer.innerHTML = '';
        }

        // --- ALCHEMIA ---
        const alchemicalContainer = document.getElementById('modalAlchemicalContainer');
        if(recipe.klasyfikacja_dzialania) {
            const kd = recipe.klasyfikacja_dzialania;
            let html = `<details class="grimoire-details">
                            <summary>⚕️ Matryce Alchemiczne i Działanie</summary>
                            <div class="details-content" style="padding: 10px 20px;">`;

            if (kd.skalowanie_toksykologiczne) {
                html += `
                    <details class="grimoire-subdetails">
                        <summary>Moc i Skalowanie ${getContextTooltip("Skalowanie Toksykologiczne", dict["Skalowanie Toksykologiczne"])}</summary>
                        <div class="subdetails-content">${esc(kd.skalowanie_toksykologiczne)}</div>
                    </details>`;
            }
            if(kd.matryca_wu_xing) {
                html += `
                    <details class="grimoire-subdetails">
                        <summary>Matryca Wu Xing ${getContextTooltip("Matryca Wu Xing", dict["Matryca Wu Xing"])}</summary>
                        <div class="subdetails-content">
                            ${labeledRows([["Leczy żywioł", kd.matryca_wu_xing.zywiol_leczony],
                                           ["Wsparcie", kd.matryca_wu_xing.narzad_matczyny_do_wsparcia]], '<br>')}
                            ${kd.matryca_wu_xing.porada_matrycy ? `<br><br><small style="color:#666;">📝 ${esc(kd.matryca_wu_xing.porada_matrycy)}</small>` : ''}
                        </div>
                    </details>`;
            }
            if(kd.triada_kampo) {
                // Rozpoznawanie konkretnego terminu (Sui, Ketsu, Ki, Tokuso) i dodawanie dymka do wartości "Cel główny"
                let kampoCtx = extractContext(kd.triada_kampo.cel_glowny || '');
                let kampoTooltipDef = "";
                for (let key in kampoDict) {
                    if (kampoCtx.name.toLowerCase().includes(key)) {
                        kampoTooltipDef = kampoDict[key];
                        break;
                    }
                }
                let kampoValueTooltip = kampoTooltipDef ? getContextTooltip(kampoCtx.name, kampoTooltipDef) : '';

                html += `
                    <details class="grimoire-subdetails">
                        <summary>Triada Kampo ${getContextTooltip("Triada Kampo", dict["Triada Kampo"])}</summary>
                        <div class="subdetails-content">
                            <strong>Cel główny:</strong> <em>${esc(kd.triada_kampo.cel_glowny || '')}</em> ${kampoValueTooltip}
                            ${kd.triada_kampo.wyjasnienie ? `<br><br><small style="color:#666;">📝 ${esc(kd.triada_kampo.wyjasnienie)}</small>` : ''}
                        </div>
                    </details>`;
            }
            // Pola opracowania z Siedziby Kwiatownika (inne tradycje)
            if (kd.doktryna_sygnatur) {
                html += subDetails(`Doktryna Sygnatur ${getContextTooltip("Doktryna Sygnatur", dict["Doktryna Sygnatur"])}`,
                    labeledRows([["Sygnatura", kd.doktryna_sygnatur.sygnatura], ["Interpretacja", kd.doktryna_sygnatur.interpretacja]]));
            }
            if (kd.humory_galena) {
                html += subDetails(`Humory Galena ${getContextTooltip("Humory Galena", dict["Humory Galena"])}`,
                    labeledRows([["Jakość", kd.humory_galena.jakosc], ["Stopień", kd.humory_galena.stopien],
                                 ["", kd.humory_galena.wyjasnienie]]));
            }
            if (kd.alchemia_spageryczna) {
                html += subDetails(`Alchemia Spageryczna ${getContextTooltip("Alchemia Spageryczna", dict["Alchemia Spageryczna"])}`,
                    labeledRows([["Zasada", kd.alchemia_spageryczna.zasada], ["", kd.alchemia_spageryczna.wyjasnienie]]));
            }
            if (Array.isArray(recipe.wskazowki_tradycyjne) && recipe.wskazowki_tradycyjne.length) {
                html += subDetails('Wskazówki tradycyjne',
                    `<ul style="margin:0; padding-left:18px;">${recipe.wskazowki_tradycyjne.map(t => `<li>${esc(t)}</li>`).join('')}</ul>`);
            }
            if (recipe.opracowanie && recipe.opracowanie.uwaga) {
                html += `<p class="enrich-note">ℹ️ ${esc(recipe.opracowanie.uwaga)}</p>`;
            }
            html += `</div></details>`;
            alchemicalContainer.innerHTML = html;
        } else {
            alchemicalContainer.innerHTML = '';
        }

        // --- SKŁADNIKI W JEDNEJ LINII ---
        const ingList = document.getElementById('modalRecipeIngredients');
        let ingHtml = "";
        if (Array.isArray(recipe.skladniki)) {
            recipe.skladniki.forEach(s => {
                if(typeof s === 'object') {
                    const ingName = s.link_id
                        ? `<a href="/plant/${encodeURIComponent(s.link_id)}/" class="ingredient-plant-link" title="Zobacz roślinę">${esc(s.nazwa)}</a>`
                        : `<span data-wiki-term="${esc(s.nazwa)}">${esc(s.nazwa)}</span>`;
                    ingHtml += `<li class="ingredient-li">
                        <strong style="color:#2d5a27; font-size:1.15rem;">${s.ilosc ? esc(s.ilosc) + ' - ' : ''}${ingName}</strong>
                        ${s.czesc_rosliny ? `<small class="text-muted"> (${esc(s.czesc_rosliny)})</small>` : ''}
                    </li>`;
                } else {
                    ingHtml += `<li class="ingredient-li"><strong style="color:#2d5a27; font-size:1.1rem;"><span data-wiki-term="${esc(s)}">${esc(s)}</span></strong></li>`;
                }
            });
        } else {
            ingHtml = `<li class="ingredient-li">${esc(recipe.skladniki) || 'Brak danych'}</li>`;
        }
        ingList.innerHTML = ingHtml;

        // --- RYTUAŁ PRZYGOTOWANIA ---
        const prep = document.getElementById('modalRecipePreparation');
        if(Array.isArray(recipe.sposob_przygotowania)) {
            let prepsHtml = "";
            recipe.sposob_przygotowania.forEach((step, index) => {
                let cleanStep = esc(step).replace(/^Faza \d+ \((.*?)\):/, '<strong>$1:</strong>').replace(/^Krok \d+:\s*/, '');
                prepsHtml += `
                    <div class="ritual-step">
                        <div class="ritual-number">${index + 1}</div>
                        <div class="ritual-text">${cleanStep}</div>
                    </div>
                `;
            });
            prep.innerHTML = prepsHtml;
        } else {
            prep.innerHTML = `<div class="ritual-step"><div class="ritual-text">${esc(recipe.sposob_przygotowania) || 'Brak instrukcji'}</div></div>`;
        }

        // --- ŹRÓDŁA ---
        const srcContainer = document.getElementById('modalSourcesContainer');
        if (srcContainer) {
            const sources = normalizeSources(recipe);
            if (sources.length) {
                const items = sources.map(z => {
                    const dom = z.url ? z.url.replace(/^https?:\/\/(www\.)?/i, '').split('/')[0] : '';
                    const name = z.url ? `<a href="${esc(z.url)}" target="_blank" rel="noopener nofollow" data-kw-src="${esc(dom)}">${esc(z.name)}</a>` : esc(z.name);
                    const meta = [z.title ? `„${esc(z.title)}”` : '', z.lang ? esc(z.lang.toUpperCase()) : '',
                                  z.date ? `pobrano ${esc(z.date)}` : ''].filter(Boolean).join(' · ');
                    return `<li>${name}${meta ? ` <small class="text-muted">— ${meta}</small>` : ''}</li>`;
                }).join('');
                const note = recipe._z_sieci
                    ? `<p class="text-muted" style="font-size:.9rem;margin-bottom:6px;">Przepis przetłumaczony z oryginału${sources.length > 1 ? ` — występuje na ${sources.length} stronach` : ''}.</p>` : '';
                srcContainer.innerHTML = `
                    <details class="grimoire-details" ${recipe._z_sieci ? 'open' : ''}>
                        <summary>📚 Źródła (${sources.length})</summary>
                        <div class="details-content">${note}<ul class="recipe-sources">${items}</ul></div>
                    </details>`;
            } else {
                srcContainer.innerHTML = '';
            }
        }

        // Pokaż Modal
        if (typeof bootstrap !== 'undefined') {
            bootstrap.Modal.getOrCreateInstance(document.getElementById('dynamicRecipeModal')).show();
        } else if (window.jQuery) {
            $('#dynamicRecipeModal').modal('show');
        }

    } catch (e) {
        console.error("Błąd przetwarzania przepisu:", e);
    }
}

// ==========================================
// 4. ANIMACJA SCROLLA W MODALU
// ==========================================
document.addEventListener("DOMContentLoaded", function() {
    const modalElement = document.getElementById('dynamicRecipeModal');
    if (!modalElement) return;

    // POPRAWKA: Używamy prawidłowej nazwy zmiennej 'modalElement'
    modalElement.addEventListener('hidden.bs.modal', () => {
        document.body.focus();
    });

    modalElement.addEventListener('shown.bs.modal', function () {
        const modalBody = document.getElementById('modalBodyObj');
        const modalHeader = document.getElementById('modalHeaderObj');
        const tagsContainer = document.getElementById('modalOriginTags');
        const tooltipIcon = document.getElementById('modalOriginTooltipIcon');

        modalBody.scrollTop = 0;
        modalHeader.classList.remove('scrolled');
        tagsContainer.style.display = 'block';
        tooltipIcon.style.display = 'none';

        modalBody.addEventListener('scroll', function() {
            if (modalBody.scrollTop > 50) {
                modalHeader.classList.add('scrolled');
                tagsContainer.style.display = 'none';
                tooltipIcon.style.display = 'block';
            } else {
                modalHeader.classList.remove('scrolled');
                tagsContainer.style.display = 'block';
                tooltipIcon.style.display = 'none';
            }
        });
    });
});

// ==========================================
// 5. WYSZUKIWARKA (ZAAWANSOWANA)
// ==========================================
const searchForm = document.getElementById('recipeSearchForm');
const searchInput = document.getElementById('recipeSearch');
const suggestionsList = document.getElementById('suggestionsList');
const recipeWrappers = document.querySelectorAll('.recipe-wrapper');
const noResultsMessage = document.getElementById('noResultsMessage');
let keywords = new Set();
const stopWords = ['w', 'z', 'i', 'o', 'a', 'do', 'na', 'po', 'ze', 'za', 'się', 'lub', 'jak', 'ml', 'g', 'kg', 'dag', 'lyz', 'łyż', 'łyżka', 'łyżeczka', 'szklanki', 'szklanka', 'proporcja', 'ok', 'szt', 'sztuk', 'litr', 'gram', 'często', 'bardzo', 'jest'];

// 1. SILNIK NORMALIZACJI - usuwa polskie znaki diakrytyczne do wyszukiwania
function normalizeText(text) {
    if (!text) return "";
    const accents = {'ą':'a','ć':'c','ę':'e','ł':'l','ń':'n','ó':'o','ś':'s','ź':'z','ż':'z'};
    return text.toLowerCase().replace(/[ąćęłńóśźż]/g, match => accents[match]);
}

// 2. SILNIK DOPASOWANIA - rozdziela zapytanie ("ból głowy" na "bol", "glowy") i szuka każdego z osobna
function advancedSearchMatch(targetText, query) {
    if (!targetText || !query) return false;
    const normTarget = targetText;           // tekst kart jest znormalizowany raz, przy wczytaniu
    const normQuery = normalizeText(query);

    const queryWords = normQuery.split(/\s+/).filter(w => w.length > 0);
    return queryWords.every(word => normTarget.includes(word));
}

// 3. DANE DO WYSZUKIWANIA
// Na start szukamy w tym, co widać na karcie (tytuł, roślina, opis). Pełny tekst przepisów
// (składniki, działanie, dawkowanie…) przychodzi z /api/przepisnik.json, gdy ktoś zacznie szukać
// (albo w tle chwilę po wczytaniu strony) – wtedy wyniki i podpowiedzi uzupełniają się same.
recipeWrappers.forEach(wrapper => {
    const card = wrapper.querySelector('.recipe-card');
    wrapper._kwText = normalizeText(card ? card.textContent.replace(/\s+/g, ' ') : '');
});
let keywordsArray = [];
let searchTextsLoaded = null;

function loadSearchTexts() {
    if (searchTextsLoaded) return searchTextsLoaded;
    const grid = document.getElementById('recipesGrid');
    const src = grid && grid.dataset.searchSrc;
    if (!src) return Promise.resolve(false);
    searchTextsLoaded = fetch(src)
        .then(r => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status))))
        .then(data => {
            const texts = data && Array.isArray(data.teksty) ? data.teksty : [];
            const kw = new Set();
            recipeWrappers.forEach(wrapper => {
                const t = texts[Number(wrapper.dataset.nr)];
                if (typeof t !== 'string') return;
                wrapper._kwText += ' ' + normalizeText(t);
                t.split(' ').forEach(w => {
                    // tylko same litery (bez 100g, 50ml), dłuższe niż 2 znaki
                    if (w.length > 2 && /^[a-zżźćńółęąś]+$/.test(w) && !stopWords.includes(w)) kw.add(w);
                });
            });
            keywordsArray = Array.from(kw).sort();
            if (searchInput && searchInput.value.trim()) filterRecipes(searchInput.value.trim());
            return true;
        })
        .catch(() => { searchTextsLoaded = null; return false; });
    return searchTextsLoaded;
}
if (searchInput) {
    ['focus', 'pointerdown'].forEach(ev => searchInput.addEventListener(ev, () => loadSearchTexts(), { once: true, passive: true }));
}
window.addEventListener('load', () => {
    if (navigator.connection && navigator.connection.saveData) return;
    if (window.requestIdleCallback) requestIdleCallback(() => loadSearchTexts(), { timeout: 5000 });
    else setTimeout(loadSearchTexts, 2500);
}, { once: true });



// 4. LOGIKA FILTROWANIA KART
let currentOrigin = 'all';   // 'all' | 'book' (z ksiąg) | 'web' (z sieci)

window.setOriginFilter = function(origin, btn) {
    currentOrigin = origin;
    document.querySelectorAll('.origin-filter .btn').forEach(b => b.classList.toggle('active', b === btn));
    filterRecipes(searchInput ? searchInput.value.trim() : '');
};

function filterRecipes(query) {
    let visibleCount = 0;
    const cleanQuery = query.trim();

    recipeWrappers.forEach(wrapper => {
        // tekst karty + (gdy już przyszedł) pełny tekst przepisu – oba znormalizowane
        const dataText = wrapper._kwText || "";

        if (currentOrigin !== 'all' && wrapper.dataset.origin !== currentOrigin) {
            wrapper.classList.add('d-none');
        } else if (cleanQuery === "") {
            wrapper.classList.remove('d-none');
            visibleCount++;
        } else {
            // Sprawdzamy algorytmem advancedSearchMatch
            if (advancedSearchMatch(dataText, cleanQuery)) {
                wrapper.classList.remove('d-none');
                visibleCount++;
            } else {
                wrapper.classList.add('d-none');
            }
        }
    });

    if (typeof sortResultsByFavorites === 'function') {
        sortResultsByFavorites();
    }

    if (noResultsMessage) {
        noResultsMessage.style.display = visibleCount === 0 ? 'block' : 'none';
    }
}

// 5. NASŁUCHIWANIE ZDARZEŃ FORMULARZA
if (searchInput) {
    searchInput.addEventListener('input', function() {
        const val = this.value.trim();
        suggestionsList.innerHTML = '';
        suggestionsList.style.display = 'none';

        filterRecipes(val);
        loadSearchTexts();

        if (val.length < 2) return;

        const normVal = normalizeText(val);
        const filtered = keywordsArray.filter(k => normalizeText(k).includes(normVal)).slice(0, 6);

        if (filtered.length > 0) {
            suggestionsList.style.display = 'block';
            filtered.forEach(word => {
                const btn = document.createElement('button');
                btn.className = 'list-group-item list-group-item-action text-start';
                btn.style.borderRadius = '0';
                btn.style.fontFamily = "'Crimson Text', serif";
                // Podświetlamy słowo na zielono
                btn.innerHTML = `<strong style="color: #2d5a27;">${word}</strong>`;
                btn.type = 'button';
                btn.onclick = () => {
                    searchInput.value = word;
                    suggestionsList.style.display = 'none';
                    filterRecipes(word);
                };
                suggestionsList.appendChild(btn);
            });
        }
    });
}

if (searchForm) {
    searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        filterRecipes(searchInput.value.trim());
        if(suggestionsList) suggestionsList.style.display = 'none';
    });
}

document.addEventListener('click', e => {
    if (searchInput && e.target !== searchInput && suggestionsList) {
        suggestionsList.style.display = 'none';
    }
});

window.clearSearch = function() {
    if (searchInput) {
        searchInput.value = '';
        filterRecipes('');
    }
};
// ==========================================
// 6. OBSŁUGA ULUBIONYCH I PARAMETRÓW URL
// ==========================================
function sortResultsByFavorites() {
    const grid = document.getElementById('recipesGrid');
    if (!grid) return;

    let favRecipes = [];
    try { favRecipes = JSON.parse(localStorage.getItem("recipeFavorites")) || []; } catch (e) { favRecipes = []; }
    // bez ulubionych nie przestawiamy ~1300 kart (to kosztowne na telefonie)
    if (!favRecipes.length && !grid.querySelector('.recipe-title .bi-heart-fill')) return;
    const items = Array.from(grid.querySelectorAll('.recipe-wrapper'));

    // 1. KESZOWANIE: Pobieramy dane raz i przechowujemy w tablicy obiektów
    // Dzięki temu unikamy wielokrotnego odczytu z DOM (Forced Reflow)
    const itemsWithData = items.map(item => {
        const titleEl = item.querySelector('.recipe-title');
        // Czyścimy tytuł z serduszka do porównania
        const title = titleEl.innerText.replace('❤️ ', '').trim();
        return {
            element: item,
            title: title,
            isFav: favRecipes.includes(title)
        };
    });

    // 2. SORTOWANIE: Operujemy na czystej tablicy JavaScript (błyskawiczne)
    itemsWithData.sort((a, b) => {
        if (a.isFav && !b.isFav) return -1;
        if (!a.isFav && b.isFav) return 1;
        return 0;
    });

    // 3. BUDOWANIE: Tworzymy fragment i aktualizujemy ikony
    const fragment = document.createDocumentFragment();

    itemsWithData.forEach(obj => {
        const titleEl = obj.element.querySelector('.recipe-title');
        const existingIcon = titleEl.querySelector('.bi-heart-fill');

        if (obj.isFav) {
            if (!existingIcon) {
                titleEl.insertAdjacentHTML('afterbegin', `<i class="bi bi-heart-fill" style="color: #9b4b4b; font-size: 0.9rem; margin-right: 8px;"></i> `);
            }
        } else if (existingIcon) {
            existingIcon.remove();
        }

        fragment.appendChild(obj.element);
    });

    // 4. JEDNORAZOWA PODMIANA (Tylko 1 przerysowanie strony)
    grid.innerHTML = "";
    grid.appendChild(fragment);
}

// Obsługa parametrów przy starcie strony
document.addEventListener("DOMContentLoaded", () => {
    const urlParams = new URLSearchParams(window.location.search);
    const query = urlParams.get('q');
    const autoOpen = urlParams.get('autoopen');

    if (query && searchInput) {
        searchInput.value = query;
        filterRecipes(query.toLowerCase());
        loadSearchTexts();          // pełny tekst dołoży wyniki, gdy przyjdzie
    } else {
        sortResultsByFavorites();
    }

    // --- NOWOŚĆ: AUTOMATYCZNE OTWIERANIE PRZEPISU ---
    if (autoOpen === 'true') {
        setTimeout(() => {
            // Szukamy pierwszego widocznego przepisu na liście po przefiltrowaniu
            const visibleWrappers = document.querySelectorAll('.recipe-wrapper:not(.d-none)');
            if (visibleWrappers.length > 0) {
                const btn = visibleWrappers[0].querySelector('.btn-details');
                if (btn) btn.click(); // Automatyczne kliknięcie!
            }
        }, 150); // Krótkie opóźnienie, by filtry i animacje zdążyły zadziałać
    }
});