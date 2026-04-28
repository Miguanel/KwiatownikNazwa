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
                let clean = p.replace('[', '').replace(']', '');
                tagsHtml += `<span class="alchemical-tag">${clean}</span>`;
                plainTextTags += `${clean}<br>`;
            });
        }
        if(recipe.mechanizm_tworzenia) {
            let mechanisms = Array.isArray(recipe.mechanizm_tworzenia) ? recipe.mechanizm_tworzenia : [recipe.mechanizm_tworzenia];
            mechanisms.forEach(m => {
                tagsHtml += `<span class="alchemical-tag" style="background:#f4f1ea; border-color:#d1c7a7; color:#b8860b;">${m}</span>`;
                plainTextTags += `${m}<br>`;
            });
        }

        originTags.innerHTML = tagsHtml;
        tooltipText.innerHTML = `<strong>Pochodzenie i System:</strong><br>${plainTextTags}`;

        // --- ZASTOSOWANIE I DAWKOWANIE ---
        const dosageContainer = document.getElementById('modalDosageContainer');
        if(recipe.stosowanie_i_dawkowanie) {
            dosageContainer.innerHTML = `
                <details class="grimoire-details" open>
                    <summary>🩺 Zastosowanie i Dawkowanie</summary>
                    <div class="details-content details-highlight">
                        <p style="margin-bottom:10px;"><strong>Kiedy stosować:</strong> ${recipe.stosowanie_i_dawkowanie.okolicznosci_stosowania}</p>
                        <p style="margin-bottom:10px;"><strong>Jak dawkować:</strong> ${recipe.stosowanie_i_dawkowanie.dawkowanie_standardowe}</p>
                        <p style="margin-bottom:0;"><strong>Dla pacjenta:</strong> ${recipe.stosowanie_i_dawkowanie.skalowanie_pacjenta}</p>
                    </div>
                </details>`;
        } else if (recipe.dawkowanie) {
            dosageContainer.innerHTML = `
                <details class="grimoire-details" open>
                    <summary>🩺 Dawkowanie</summary>
                    <div class="details-content details-highlight">${recipe.dawkowanie}</div>
                </details>`;
        } else {
            dosageContainer.innerHTML = '';
        }

        // --- WŁAŚCIWOŚCI FIZYCZNE ---
        const propsContainer = document.getElementById('modalPropertiesContainer');
        if(recipe.wlasciwosci_fizyczne) {
            propsContainer.innerHTML = `
                <details class="grimoire-details">
                    <summary>👁️ Właściwości fizyczne i ślady</summary>
                    <div class="details-content" style="padding: 10px 20px;">
                        <details class="grimoire-subdetails">
                            <summary>Konsystencja i zapach</summary>
                            <div class="subdetails-content">${recipe.wlasciwosci_fizyczne.konsystencja_i_slady}</div>
                        </details>
                        <details class="grimoire-subdetails">
                            <summary>Ślady na skórze</summary>
                            <div class="subdetails-content">${recipe.wlasciwosci_fizyczne.barwienie_skory}</div>
                        </details>
                        <details class="grimoire-subdetails">
                            <summary>Ślady na odzieży</summary>
                            <div class="subdetails-content">${recipe.wlasciwosci_fizyczne.barwienie_ubran}</div>
                        </details>
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
                            <strong>Ostrzeżenia:</strong> ${recipe.bezpieczenstwo_i_interakcje.ostrzezenia}<br><br>
                            <strong>Interakcje:</strong> ${recipe.bezpieczenstwo_i_interakcje.interakcje_z_lekami}
                        </div>
                    </details>`;
            }
            if(recipe.wymogi_szamanskie_i_czasowe) {
                warnHtml += `
                    <details class="grimoire-subdetails">
                        <summary>Wymogi Czasowe i Zakazy</summary>
                        <div class="subdetails-content">
                            <strong>Aplikacja:</strong> ${recipe.wymogi_szamanskie_i_czasowe.chronoterapia}<br><br>
                            <strong>Czas zbioru:</strong> ${recipe.wymogi_szamanskie_i_czasowe.astrologia_zbioru}<br><br>
                            <strong>Zakazy:</strong> ${recipe.wymogi_szamanskie_i_czasowe.dieta_i_zakazy}
                        </div>
                    </details>`;
            }
            if(recipe.uwagi) {
                warnHtml += `
                    <details class="grimoire-subdetails">
                        <summary>Uwagi ogólne</summary>
                        <div class="subdetails-content">${recipe.uwagi}</div>
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
                        <div class="subdetails-content">${kd.skalowanie_toksykologiczne}</div>
                    </details>`;
            }
            if(kd.matryca_wu_xing) {
                html += `
                    <details class="grimoire-subdetails">
                        <summary>Matryca Wu Xing ${getContextTooltip("Matryca Wu Xing", dict["Matryca Wu Xing"])}</summary>
                        <div class="subdetails-content">
                            <strong>Leczy żywioł:</strong> <em>${kd.matryca_wu_xing.zywiol_leczony}</em><br>
                            <strong>Wsparcie:</strong> <em>${kd.matryca_wu_xing.narzad_matczyny_do_wsparcia}</em><br><br>
                            <small style="color:#666;">📝 ${kd.matryca_wu_xing.porada_matrycy}</small>
                        </div>
                    </details>`;
            }
            if(kd.triada_kampo) {
                // Rozpoznawanie konkretnego terminu (Sui, Ketsu, Ki, Tokuso) i dodawanie dymka do wartości "Cel główny"
                let kampoCtx = extractContext(kd.triada_kampo.cel_glowny);
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
                            <strong>Cel główny:</strong> <em>${kd.triada_kampo.cel_glowny}</em> ${kampoValueTooltip}<br><br>
                            <small style="color:#666;">📝 ${kd.triada_kampo.wyjasnienie}</small>
                        </div>
                    </details>`;
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
                    let filarCtx = getDictContext(s.filar, pillarDict);
                    let tropizmCtx = extractContext(s.tropizm_organowy || '');

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

                    ingHtml += `<li class="ingredient-li">
                        <strong style="color:#2d5a27; font-size:1.15rem;">${s.ilosc || ''} - ${s.nazwa}</strong>
                        <div class="ingredient-details-row">
                            ${rolaHtml}
                            ${dzialanieHtml}
                        </div>
                    </li>`;
                } else {
                    ingHtml += `<li class="ingredient-li"><strong style="color:#2d5a27; font-size:1.1rem;">${s}</strong></li>`;
                }
            });
        } else {
            ingHtml = `<li class="ingredient-li">${recipe.skladniki || 'Brak danych'}</li>`;
        }
        ingList.innerHTML = ingHtml;

        // --- RYTUAŁ PRZYGOTOWANIA ---
        const prep = document.getElementById('modalRecipePreparation');
        if(Array.isArray(recipe.sposob_przygotowania)) {
            let prepsHtml = "";
            recipe.sposob_przygotowania.forEach((step, index) => {
                let cleanStep = step.replace(/^Faza \d+ \((.*?)\):|^Krok \d+:/, '<strong>$1:</strong>');
                prepsHtml += `
                    <div class="ritual-step">
                        <div class="ritual-number">${index + 1}</div>
                        <div class="ritual-text">${cleanStep}</div>
                    </div>
                `;
            });
            prep.innerHTML = prepsHtml;
        } else {
            prep.innerHTML = `<div class="ritual-step"><div class="ritual-text">${recipe.sposob_przygotowania || 'Brak instrukcji'}</div></div>`;
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
    else {
        modalEl.addEventListener('hidden.bs.modal', () => {
            document.body.focus(); // Przenieś fokus na stronę, by nie blokować czytników ekranu
        });
    }
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
// 5. WYSZUKIWARKA
// ==========================================
const searchForm = document.getElementById('recipeSearchForm');
const searchInput = document.getElementById('recipeSearch');
const suggestionsList = document.getElementById('suggestionsList');
const recipeWrappers = document.querySelectorAll('.recipe-wrapper');
const noResultsMessage = document.getElementById('noResultsMessage');
let keywords = new Set();
const stopWords = ['w', 'z', 'i', 'o', 'a', 'do', 'na', 'po', 'ze', 'za', 'się', 'lub', 'jak', 'ml', 'g', 'kg', 'dag', 'lyz', 'łyż', 'łyżka', 'łyżeczka', 'szklanki', 'szklanka', 'proporcja', 'ok', 'szt', 'sztuk', 'litr', 'gram', 'często', 'bardzo', 'jest'];

recipeWrappers.forEach(wrapper => {
    const rawText = wrapper.querySelector('.search-data').textContent;
    const words = rawText.replace(/[^\w\sęóąśłżźćń]/gi, '').split(/\s+/);
    words.forEach(word => {
        if (word.length > 2 && !!word.match(/^[a-z]+$/i) && !stopWords.includes(word)) {
            keywords.add(word);
        }
    });
});

const keywordsArray = Array.from(keywords).sort();

function filterRecipes(query) {
    let visibleCount = 0;
    recipeWrappers.forEach(wrapper => {
        const dataText = wrapper.querySelector('.search-data').textContent;
        if (dataText.includes(query)) {
            wrapper.classList.remove('d-none');
            visibleCount++;
        } else {
            wrapper.classList.add('d-none');
        }
    });

    sortResultsByFavorites();

    if (noResultsMessage) {
        noResultsMessage.style.display = visibleCount === 0 ? 'block' : 'none';
    }
}

if (searchInput) {
    searchInput.addEventListener('input', function() {
        const val = this.value.toLowerCase().trim();
        suggestionsList.innerHTML = '';
        suggestionsList.style.display = 'none';
        filterRecipes(val);
        if (val.length < 2) return;
        const filtered = keywordsArray.filter(k => k.includes(val)).slice(0, 6);
        if (filtered.length > 0) {
            suggestionsList.style.display = 'block';
            filtered.forEach(word => {
                const btn = document.createElement('button');
                btn.className = 'list-group-item list-group-item-action text-start';
                btn.style.borderRadius = '0';
                btn.style.fontFamily = "'Crimson Text', serif";
                const regex = new RegExp(`(${val})`, 'gi');
                btn.innerHTML = word.replace(regex, '<strong style="color: #2d5a27;">$1</strong>');
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
        filterRecipes(searchInput.value.toLowerCase().trim());
        suggestionsList.style.display = 'none';
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