// ==========================================
// 1. SŁOWNIKI POJĘĆ DLA TOOLTIPÓW
// ==========================================
const dict = {
    "Tropizm Organowy": "Wskazuje, do jakiego narządu lub układu w ciele pacjenta dana roślina kieruje swoje główne działanie lecznicze.",
    "Smak Ajurwedyjski": "Według medycyny wschodniej, smak zioła (np. gorzki, ostry, słodki) determinuje jego termikę – to, czy ochładza, rozgrzewa, wysusza czy nawilża tkanki.",
    "Matryca Wu Xing": "Tradycyjna Medycyna Chińska. Dzieli choroby i zioła na 5 żywiołów (Drzewo, Ogień, Ziemia, Metal, Woda). Leczenie polega na równoważeniu tych żywiołów.",
    "Triada Kampo": "Japońska koncepcja medyczna dzieląca zdrowie na 3 strumienie: KI (Energia życiowa/nerwy), KETSU (Krew/krążenie) oraz SUI (Płyny ustrojowe/limfa).",
    "Filar": "W starożytnych recepturach składniki dzieliły się na role: Bazowy (główny lek), Wzmocnienie (pomocnik), Minister (kierunkowskaz), Posłaniec (nośnik) i Korektor (łagodzący skutki uboczne).",
    "Alchemia Spageryczna": "Starożytna sztuka rozdzielania zioła na olejek (Duszę), alkohol (Ducha) i popiół (Ciało mineralne), by połączyć je w spotęgowany eliksir.",
    "Doktryna Sygnatur": "Dawne wierzenie, według którego wygląd, kolor lub środowisko życia rośliny zdradza, jaki organ ludzki ona leczy.",
    "Humory Galena": "Grecko-rzymska medycyna czterech humorów (krew, flegma, żółć żółta, żółć czarna). Zioła mają jakości: ciepłe/zimne i suche/wilgotne w stopniach od I do IV.",
    "Ajurweda": "Indyjska medycyna, w której zioła równoważą trzy dosze: Vata (ruch, powietrze), Pitta (ogień, przemiana) i Kapha (struktura, woda).",
    "Skalowanie Toksykologiczne": "Określa stopień niebezpieczeństwa i siłę działania receptury, od ziół łagodnych (normalizujących) po heroiczne (ekstremalnie silne, potencjalnie toksyczne)."
};

const flavorDict = {
    "kwaśny": "Smak kwaśny ściąga tkanki i zatrzymuje płyny.",
    "gorzki": "Smak gorzki chłodzi zapalenia i obniża gorączkę.",
    "słodki": "Smak słodki nawilża, odżywia i łagodzi ból.",
    "ostry": "Smak ostry rozgrzewa i otwiera pory skóry.",
    "słony": "Smak słony rozmiękcza guzy.",
    "cierpki": "Smak cierpki tamuje krwotoki."
};

const pillarDict = {
    "1_bazowy": "Baza: Główny lek uderzający bezpośrednio w przyczynę choroby.",
    "2_wzmocnienie": "Wzmocnienie: Pomaga i potęguje działanie leku bazowego.",
    "3_minister": "Minister: Usuwa poboczne objawy lub kieruje lek do konkretnego miejsca.",
    "4_poslaniec": "Posłaniec: Nośnik ułatwiający wchłanianie (np. alkohol, tłuszcz).",
    "5_korektor": "Korektor: Łagodzi drażniące skutki uboczne silnych ziół."
};

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
window.openRecipeModal = function(buttonElement) {
    try {
        const recipe = JSON.parse(buttonElement.getAttribute('data-recipe'));
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
            let mechanisms = Array.isArray(recipe.mechanizm_tworzenia) ? recipe.mechanizm_tworzenia : [recipe.mechanizm_tworzenia];
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
            if (kd.ajurweda) {
                html += subDetails(`Ajurweda ${getContextTooltip("Ajurweda", dict["Ajurweda"])}`,
                    labeledRows([["Dosze", kd.ajurweda.dosze], ["", kd.ajurweda.wyjasnienie]]));
            }
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
                    let filarCtx = getDictContext(s.filar ? esc(s.filar) : '', pillarDict);
                    let tropizmCtx = extractContext(esc(s.tropizm_organowy || ''));
                    let smakCtx = getDictContext(s.smak_ajurweda ? esc(s.smak_ajurweda) : '', flavorDict);
                    if (smakCtx.name && s.smak_ajurweda) smakCtx.name = esc(s.smak_ajurweda).replace(/_/g, ' ');

                    let rolaHtml = filarCtx.name ? `
                        <span class="ingredient-role">
                            <strong>Rola:</strong>
                            <em>${filarCtx.name}</em> ${getContextTooltip("Rola: " + filarCtx.name.toUpperCase(), filarCtx.desc)}
                        </span>` : '';

                    let dzialanieHtml = tropizmCtx.name ? `
                        <span class="ingredient-action">
                            <strong>Działanie:</strong>
                            <em>${tropizmCtx.name}</em> ${getContextTooltip("Mechanizm działania", tropizmCtx.desc)}
                        </span>` : '';

                    let smakHtml = smakCtx.name ? `
                        <span class="ingredient-action">
                            <strong>Smak:</strong>
                            <em>${smakCtx.name}</em> ${getContextTooltip("Smak ajurwedyjski", smakCtx.desc || dict["Smak Ajurwedyjski"])}
                        </span>` : '';

                    const ingName = s.link_id
                        ? `<a href="/plant/${encodeURIComponent(s.link_id)}/" class="ingredient-plant-link" title="Zobacz roślinę">${esc(s.nazwa)}</a>`
                        : `<span data-wiki-term="${esc(s.nazwa)}">${esc(s.nazwa)}</span>`;
                    ingHtml += `<li class="ingredient-li">
                        <strong style="color:#2d5a27; font-size:1.15rem;">${s.ilosc ? esc(s.ilosc) + ' - ' : ''}${ingName}</strong>
                        ${s.czesc_rosliny && !s.filar ? `<small class="text-muted"> (${esc(s.czesc_rosliny)})</small>` : ''}
                        <div class="ingredient-details-row">
                            ${rolaHtml}
                            ${dzialanieHtml}
                            ${smakHtml}
                        </div>
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
                    const name = z.url ? `<a href="${esc(z.url)}" target="_blank" rel="noopener nofollow">${esc(z.name)}</a>` : esc(z.name);
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
};

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
    const normTarget = normalizeText(targetText);
    const normQuery = normalizeText(query);

    const queryWords = normQuery.split(/\s+/).filter(w => w.length > 0);
    return queryWords.every(word => normTarget.includes(word));
}

// 3. GENEROWANIE CZYSTYCH DANYCH I PODPOWIEDZI W LOCIE
recipeWrappers.forEach(wrapper => {
    const btn = wrapper.querySelector('.btn-details');
    if (!btn) return;

    // Pobieramy bezpieczny, poprawnie zakodowany JSON (omijamy błędy Pythona z polskimi znakami)
    let recipeData;
    try {
        recipeData = JSON.parse(btn.getAttribute('data-recipe'));
    } catch (e) {
        recipeData = {};
    }

    // Zmieniamy cały słownik w jeden tekst (bez źródeł i metadanych Siedziby - to nie treść przepisu)
    const {zrodla, zrodlo, siedziba, _z_sieci, ...searchable} = recipeData || {};
    let rawText = JSON.stringify(searchable);

    // USUWANIE LINKÓW: Wycina wszystkie adresy URL zaczynające się od http/https
    rawText = rawText.replace(/https?:\/\/[^\s"']+/g, ' ');

    // Zapisujemy ten idealnie oczyszczony tekst w pamięci diva dla szybkiego filtrowania
    wrapper.dataset.searchContent = rawText;

    // ZAMIANA INTERPUNKCJI NA SPACJE: Zamiast sklejać słowa, oddzielamy je
    const cleanTextForKeywords = rawText.replace(/[^\w\sęóąśłżźćńĘÓĄŚŁŻŹĆŃ]/g, ' ');

    // Tworzenie słów kluczowych do dropdownu
    const words = cleanTextForKeywords.split(/\s+/);
    words.forEach(word => {
        const w = word.toLowerCase();
        // Przepuszczamy tylko same litery (wywalamy 100g, 50ml), dłuższe niż 2 znaki
        if (w.length > 2 && w.match(/^[a-zżźćńółęąś]+$/) && !stopWords.includes(w)) {
            keywords.add(w);
        }
    });
});

const keywordsArray = Array.from(keywords).sort();

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
        // Czytamy nasz zoptymalizowany tekst
        const dataText = wrapper.dataset.searchContent || "";

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

    const favRecipes = JSON.parse(localStorage.getItem("recipeFavorites")) || [];
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