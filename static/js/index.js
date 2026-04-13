//const BASE_URL = window.location.origin;

// --- NOWOŚĆ: SYSTEM PRZECIĄGANIA (DRAG TO SCROLL) ---
let isDraggingUI = false; // Flaga blokująca kliknięcia w trakcie przeciągania

function enableDragToScroll(slider) {
    let isDown = false; let startX; let scrollLeft;

    slider.addEventListener('mousedown', (e) => {
        isDown = true; isDraggingUI = false;
        slider.classList.add('active');
        startX = e.pageX - slider.offsetLeft;
        scrollLeft = slider.scrollLeft;
    });
    slider.addEventListener('mouseleave', () => { isDown = false; slider.classList.remove('active'); });
    slider.addEventListener('mouseup', () => { isDown = false; slider.classList.remove('active'); });
    slider.addEventListener('mousemove', (e) => {
        if (!isDown) return;
        e.preventDefault();
        const x = e.pageX - slider.offsetLeft;
        const walk = (x - startX) * 1.5; // Prędkość przeciągania
        if (Math.abs(walk) > 5) isDraggingUI = true; // Jeśli ruszyliśmy myszką o >5px, oznaczamy to jako PRZECIĄGANIE, a nie KLIKNIĘCIE!
        slider.scrollLeft = scrollLeft - walk;
    });
}
// --- NOWOŚĆ: INTELIGENTNE POBIERANIE ZDJĘCIA Z OBIEKTU URL ---
function getBestImageUrl(plant) {
    // Jeśli url jest obiektem (tak jak u Ciebie w bez_czarny.json)
    if (plant.url && typeof plant.url === 'object') {
        return Object.values(plant.url)[0] || ''; // Pobiera pierwszy link z obiektu
    }
    // Kompatybilność wsteczna dla starych roślin
    return plant.zdjecie_url || plant.zdjecie || plant.image || plant.url || '';
}

function getPlantUrl(id) { return BASE_URL + "/plant/" + id + "/"; }

function getWitcherIcon(plant, isRecipe = false) {
    if (isRecipe) return 'ra-scroll';
    const rodzina = (plant.rodzina || "").toLowerCase();
    const nazwa = (plant.nazwa_pl || "").toLowerCase();
    if (rodzina.includes('bukowate') || rodzina.includes('sosnowate') || nazwa.includes('dąb')) return 'ra-pine-tree';
    return 'ra-herb';
}

function getPlantWitcherClass(plant) {
    let fam = (plant.rodzina || "").toLowerCase();
    let desc = (plant.opis || "").toLowerCase();
    let name = (plant.nazwa_pl || "").toLowerCase();

    if (fam.includes("sosnowate") || fam.includes("cyprysowate")) return "ra-pine-tree";
    if (fam.includes("różowate") && (desc.includes("drzewo") || name.includes("jabłoń") || name.includes("śliw"))) return "ra-apple";
    if (desc.includes("drzewo") || fam.includes("bukowate") || fam.includes("brzozowate")) return "ra-wood-stick";
    if (desc.includes("krzew")) return "ra-sprout";
    if (desc.includes("cebul") || desc.includes("korzeń") || desc.includes("bulwa")) return "ra-acorn";
    if (fam.includes("astrowate") || fam.includes("jasnotowate") || desc.includes("kwiat")) return "ra-flower";
    if (desc.includes("egzotycz") || fam.includes("imbirowate")) return "ra-sun";
    return "ra-leaf";
}

const monthColors = {
    1: "#d0e3f0", 2: "#b5d4e9", 3: "#b8d8be", 4: "#95c99d", 5: "#7bbd85", 6: "#e8d87d",
    7: "#e6c95c", 8: "#e0a948", 9: "#d9863d", 10: "#b56933", 11: "#8c715c", 12: "#6c8093"
};
const romanMonths = ["", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"];

function renderPlantStatus(plant, month) {
    let tasks = plant.kalendarz_ogrodnika?.zadania || [];
    let currentTask = tasks.find(t => t.miesiace && t.miesiace.includes(month));
    let bgColor = monthColors[month];

    let prevM = month - 1 < 1 ? 12 : month - 1;
    let nextM = month + 1 > 12 ? 1 : month + 1;

    let taskText = currentTask ? currentTask.czynnosc : "<span style='color:#777; font-weight:normal;'>Odpoczynek / Brak zadań</span>";

    return `
        <div class="card-status-header">
            <span class="month-nav" data-m="${prevM}"><i class="ra ra-fast-backward"></i> ${romanMonths[prevM]}</span>
            <span>MIESIĄC: <strong>${romanMonths[month]}</strong></span>
            <span class="month-nav" data-m="${nextM}">${romanMonths[nextM]} <i class="ra ra-fast-forward"></i></span>
        </div>
        <div class="card-status-body" style="background-color: ${bgColor};">
            ${taskText}
        </div>
    `;
}

const colorMap = {
    'żółty': [{ id: null, nazwa: 'Mniszek Lekarski', rola: 'Kwiat żółty' }],
    'czerwony': [{ id: null, nazwa: 'Mak Polny', rola: 'Kwiat czerwony' }],
    'fioletowy': [{ id: null, nazwa: 'Lawenda', rola: 'Kwiat fioletowy' }]
};

const symptomMap = {};
function addSymptom(text, roslinaName, plantId) {
    if (!text || text.length < 3) return;
    const content = Array.isArray(text) ? text.join(', ') : String(text);
    content.split(/[,;.]/).forEach(part => {
        const cleanTag = part.trim().toLowerCase();
        if (cleanTag.length < 3) return;
        if (!symptomMap[cleanTag]) symptomMap[cleanTag] = [];
        if (!symptomMap[cleanTag].find(item => item.nazwa === roslinaName)) {
            symptomMap[cleanTag].push({ id: plantId, nazwa: roslinaName, rola: `Działanie: ${cleanTag}` });
        }
    });
}

recipesData.forEach(recipe => {
    const plant = plantsData.find(p => p.nazwa_pl.toLowerCase() === (recipe.roslina || "").toLowerCase());
    if (!plant) return;
    const plantId = plant.id, rName = plant.nazwa_pl;
    addSymptom(recipe.zastosowanie, rName, plantId);
    addSymptom(recipe.cechy, rName, plantId);
    addSymptom(recipe.tytul, rName, plantId);
    addSymptom(recipe.wlasciwosci, rName, plantId);
    if (recipe.efekty) addSymptom(recipe.efekty, rName, plantId);
    if (recipe.tagi) addSymptom(recipe.tagi, rName, plantId);
    if (recipe.skladniki) addSymptom(recipe.skladniki, rName, plantId);
});

plantsData.forEach(plant => {
    const pName = plant.nazwa_pl;
    if (plant.zastosowanie && plant.zastosowanie.medyczne) addSymptom(plant.zastosowanie.medyczne, pName, plant.id);
    if (plant.czesci_rosliny) {
        Object.values(plant.czesci_rosliny).forEach(czesc => {
            addSymptom(czesc.wlasciwosci || czesc.wlasciwości, pName, plant.id);
        });
    }
});

// ==========================================
// NOWOŚĆ: ALGORYTM AGREGACJI SEZONÓW I MIESIĘCY
// ==========================================
const monthNames = ["", "styczeń", "luty", "marzec", "kwiecień", "maj", "czerwiec", "lipiec", "sierpień", "wrzesień", "październik", "listopad", "grudzień"];
const seasonMonths = {
    "zima": [12, 1, 2], "wiosna": [3, 4, 5], "lato": [6, 7, 8], "jesień": [9, 10, 11]
};

// Koszyki na nasz automatyczny raport
const seasonalMap = {
    "wiosna": [], "lato": [], "jesień": [], "zima": [],
    "styczeń": [], "luty": [], "marzec": [], "kwiecień": [], "maj": [], "czerwiec": [],
    "lipiec": [], "sierpień": [], "wrzesień": [], "październik": [], "listopad": [], "grudzień": []
};

// Algorytm skanujący każdą roślinę z JSON-a
plantsData.forEach(plant => {
    if (plant.kalendarz_ogrodnika && plant.kalendarz_ogrodnika.zadania) {
        plant.kalendarz_ogrodnika.zadania.forEach(zadanie => {
            // Automatyczne dobieranie fajnej ikonki na podstawie nazwy czynności
            let taskIcon = "ra-sprout";
            let taskNameLower = zadanie.czynnosc.toLowerCase();
            if (taskNameLower.includes('sadz')) taskIcon = "ra-plant-seed";
            if (taskNameLower.includes('zbiór') || taskNameLower.includes('zbier')) taskIcon = "ra-sickle";
            if (taskNameLower.includes('ciąc') || taskNameLower.includes('cięci')) taskIcon = "ra-sword";
            if (taskNameLower.includes('podlew')) taskIcon = "ra-water-drop";

            // Formatujemy obiekt zadania idealnie pod naszą karuzelę (spawnSeasonNode)
            let taskEntry = {
                tytul: `${plant.nazwa_pl} - ${zadanie.czynnosc}`,
                desc: zadanie.opis || `Czas na: ${zadanie.czynnosc}`,
                icon: taskIcon,
                rosliny: [plant.nazwa_pl]
            };

            // Rozkładamy to zadanie do odpowiednich miesięcy i pór roku
            if (zadanie.miesiace) {
                zadanie.miesiace.forEach(m => {
                    let mName = monthNames[m];
                    if (mName) seasonalMap[mName].push(taskEntry);

                    // Sprawdzamy do jakiej pory roku należy ten miesiąc
                    for (const [season, mArray] of Object.entries(seasonMonths)) {
                        if (mArray.includes(m)) {
                            // Unikamy duplikatów (np. jeśli kwitnie przez całe lato, wsadzamy do lata tylko raz)
                            if (!seasonalMap[season].some(t => t.tytul === taskEntry.tytul)) {
                                seasonalMap[season].push(taskEntry);
                            }
                        }
                    }
                });
            }
        });
    }
});

// Zbudowanie finalnej mapy dla wyszukiwarki
const calendarSearchMap = {};

// 1. Zaciągamy dane ze starego, globalnego kalendarza (jeśli jest)
if (kalendarz.okresy) Object.keys(kalendarz.okresy).forEach(okres => calendarSearchMap[okres.toLowerCase()] = { type: 'Sezon / Czas', data: kalendarz.okresy[okres].zadania, label: okres });
if (kalendarz.czynnosci) Object.keys(kalendarz.czynnosci).forEach(czynnosc => calendarSearchMap[czynnosc.toLowerCase()] = { type: 'Czynność', data: [kalendarz.czynnosci[czynnosc]], label: czynnosc });

// 2. Wtłaczamy nasz dynamicznie wygenerowany z roślin raport kalendarzowy!
Object.keys(seasonalMap).forEach(key => {
    if (seasonalMap[key].length > 0) {
        if (calendarSearchMap[key]) {
            // Łączymy zadania globalne z zadaniami z roślin
            calendarSearchMap[key].data = calendarSearchMap[key].data.concat(seasonalMap[key]);
        } else {
            // Tworzymy nową zakładkę
            let typeLabel = Object.keys(seasonMonths).includes(key) ? 'Pora Roku' : 'Miesiąc';
            calendarSearchMap[key] = {
                type: typeLabel,
                data: seasonalMap[key],
                label: key.charAt(0).toUpperCase() + key.slice(1)
            };
        }
    }
});
let globalRotation = 0, currentRotationSpeed = 0, dotsPhase = 0;
let activeSatellites = [], mouseX = -1000, mouseY = -1000, animationFrameId, dockedSat = null;

const universalSearch = document.getElementById('universalSearch');
const symptomBox = document.getElementById('symptomBox');
const colorBox = document.getElementById('colorBox');
const actionBox = document.getElementById('actionBox');
const horizontalResults = document.getElementById('horizontalResults');
enableDragToScroll(horizontalResults);
const networkContainer = document.getElementById('guildNetwork');
const carousel = document.getElementById('recipeCarousel');
const searchNode = document.getElementById('mainSearchNode');
const svgLines = document.getElementById('arenaLines');
const taskResults = document.getElementById('taskResults');

document.addEventListener('mousemove', e => { mouseX = e.clientX; mouseY = e.clientY; });

function hideAllBoxes() {
    actionBox.style.display = 'none'; symptomBox.style.display = 'none'; colorBox.style.display = 'none';
}

universalSearch.addEventListener('input', function() {
    const query = this.value.toLowerCase().trim();

    actionBox.innerHTML = ''; symptomBox.innerHTML = ''; colorBox.innerHTML = ''; horizontalResults.innerHTML = '';
    if (taskResults) taskResults.style.display = 'none'; // <--- DODAJ TĘ LINIJKĘ ZABEZPIECZAJĄCĄ
    const architecturalSuggestions = document.getElementById('architecturalSuggestions');

    // ZABEZPIECZENIE: Upewniamy się, że element istnieje zanim zmienimy jego styl
    if (architecturalSuggestions) {
        architecturalSuggestions.style.display = 'none';
    }

    hideAllBoxes(); clearSatellites(); carousel.classList.remove('active');

    if (query.length < 2) {
        horizontalResults.style.display = 'none';
        searchNode.classList.remove('active-arena');
        return;
    }

    let hasSuggestions = false;

    const filteredSymptoms = Object.keys(symptomMap).filter(s => s.includes(query)).slice(0, 15);
    if (filteredSymptoms.length > 0) {
        hasSuggestions = true; symptomBox.style.display = 'block';
        filteredSymptoms.forEach(sym => {
            const div = document.createElement('div'); div.className = 'suggestion-item';
            div.innerHTML = `<span class="suggestion-category symptom-category"><i class="ra ra-droplet"></i> Objawy / Użycie</span><strong>${sym}</strong>`;
            div.onclick = () => {
                universalSearch.value = sym;
                if (architecturalSuggestions) architecturalSuggestions.style.display = 'none';
                spawnEntities(symptomMap[sym]);
                horizontalResults.style.display = 'none';
            };
            symptomBox.appendChild(div);
        });
    }

    const matchedCalendar = Object.keys(calendarSearchMap).filter(k => k.includes(query));
    if (matchedCalendar.length > 0) {
        hasSuggestions = true; actionBox.style.display = 'block';
        matchedCalendar.forEach(k => {
            const item = calendarSearchMap[k];
            const div = document.createElement('div'); div.className = 'suggestion-item';
            div.innerHTML = `<span class="suggestion-category" style="color:#e6a817"><i class="ra ra-sun"></i> ${item.type}</span><strong>${item.label}</strong>`;
            div.onclick = () => {
                universalSearch.value = item.label;
                if (architecturalSuggestions) architecturalSuggestions.style.display = 'none';
                spawnSeasonNode(item.label, item.data);
                horizontalResults.style.display = 'none';
            };
            actionBox.appendChild(div);
        });
    }

    const filteredColors = Object.keys(colorMap).filter(c => c.includes(query));
    if (filteredColors.length > 0) {
        hasSuggestions = true; colorBox.style.display = 'block';
        filteredColors.forEach(color => {
            const div = document.createElement('div'); div.className = 'suggestion-item';
            div.innerHTML = `<span class="suggestion-category color-category"><i class="ra ra-kaleidoscope"></i> Kolor</span><strong>${color}</strong>`;
            div.onclick = () => {
                universalSearch.value = color;
                if (architecturalSuggestions) architecturalSuggestions.style.display = 'none';
                spawnEntities(colorMap[color]);
                horizontalResults.style.display = 'none';
            };
            colorBox.appendChild(div);
        });
    }

    if (hasSuggestions && architecturalSuggestions) architecturalSuggestions.style.display = 'grid';

    // --- NOWE ELEMENTY: ROŚLINY (KARTY POZIOME + LOKALNE MINI KARTY) ---
    const filteredPlants = plantsData.filter(p => p.nazwa_pl.toLowerCase().includes(query) || (p.rodzina && p.rodzina.toLowerCase().includes(query)));

    if (filteredPlants.length > 0) {
        horizontalResults.style.display = 'flex';

        filteredPlants.forEach(plant => {
            // TWORZYMY GŁÓWNĄ KOLUMNĘ (Karta Główna + Jej własna Gildia)
            const resultColumn = document.createElement('div');
            resultColumn.className = 'result-column';

            // 1. ZBIERAMY I BUDUJEMY LOKALNĄ GILDIĘ DLA TEJ KONKRETNEJ ROŚLINY
            const miniRow = document.createElement('div');
            miniRow.className = 'guild-mini-row';
            enableDragToScroll(miniRow);

            let compsRaw = plant.permakultura?.gildie || plant.gildie || [];
            let comps = compsRaw.map(g => {
                if (typeof g === 'string') return { nazwa: g, rola: "Powiązanie" };
                return { nazwa: g.nazwa || g.name || "Nieznany gość", rola: g.rola || "Powiązanie" };
            });

            if (comps.length > 0) {
                comps.forEach(comp => {
                    const guestPlant = plantsData.find(p => p.nazwa_pl.toLowerCase() === comp.nazwa.toLowerCase());
                    let imageUrl = guestPlant ? getBestImageUrl(guestPlant) : '';
                    let shortName = comp.nazwa.split(' ')[0]; // Pobiera tylko pierwsze słowo
                    let role = comp.rola || "Powiązanie gildyjne";

                    const miniCard = document.createElement('div');
                    miniCard.className = 'guild-mini-card';
                    // --- NOWOŚĆ: AUTOMATYCZNE CENTROWANIE PRZY NAJECHANIU ---
                    miniCard.addEventListener('mouseenter', () => {
                        const row = miniCard.parentElement;
                        // Liczymy idealny środek dla tego kółka względem paska
                        const scrollTarget = miniCard.offsetLeft - (row.clientWidth / 2) + (miniCard.clientWidth / 2);
                        // Płynnie przewijamy pasek do tego punktu
                        row.scrollTo({ left: scrollTarget, behavior: 'smooth' });
                    });
                    // PRZYWRÓCONE ROZSZERZONE MENU HTML BEZPOŚREDNIO W KARCIE
                    miniCard.innerHTML = `
                        <div class="guild-mini-img" style="${imageUrl ? `background-image: url('${imageUrl}');` : 'background: #5a4f41;'}"></div>
                        <div class="guild-mini-title-short">${shortName}</div>

                        <div class="guild-mini-expanded">
                            <div class="expanded-title">${comp.nazwa}</div>
                            <div class="expanded-role">${role}</div>
                            <button class="expanded-btn">POKAŻ <i class="ra ra-eye"></i></button>
                        </div>
                    `;

                    // --- NOWOŚĆ: BEZPOŚREDNI TELEPORT PO KLIKNIĘCIU W TOWARZYSZA ---
                    const navigateToCompanion = (e) => {
                        e.stopPropagation();
                        if (isDraggingUI) return;

                        if(guestPlant) {
                            // Przenosi od razu na podstronę rośliny (zamiast otwierać starą arenę)
                            window.location.href = getPlantUrl(guestPlant.id || guestPlant.slug);
                        } else {
                            document.getElementById('megaAlertPlantName').innerText = comp.nazwa;
                            document.getElementById('megaAlertOverlay').style.display = 'block';
                        }
                    };

                    // Podpinamy tę samą funkcję pod całe kółko ORAZ pod przycisk
                    miniCard.onclick = navigateToCompanion;
                    miniCard.querySelector('.expanded-btn').onclick = navigateToCompanion;

                    miniRow.appendChild(miniCard);
                });
            }

            // 2. BUDUJEMY GŁÓWNĄ KARTĘ ROŚLINY Z NOWYMI TAGAMI
            // 2. BUDUJEMY GŁÓWNĄ KARTĘ ROŚLINY Z POZIOMYMI TAGAMI
            const card = document.createElement('div');
            card.className = 'result-card';
            card.style.cursor = 'pointer';

            let imageUrl = getBestImageUrl(plant);
            let bgStyle = imageUrl ? `background-image: url('${imageUrl}');` : `background: #d1c7a7;`;
            let desc = plant.opis || "Brak szczegółowego opisu zielarskiego.";
            let trivia = plant.ciekawostki && plant.ciekawostki.length > 0 ? plant.ciekawostki[Math.floor(Math.random() * plant.ciekawostki.length)] : "Zioła kryją wiele tajemnic...";

            // KULOODPORNE WYCIĄGANIE TAGÓW Z JSON
            let tagsHtml = '';
            if (plant.tagi && Array.isArray(plant.tagi) && plant.tagi.length > 0) {
                plant.tagi.forEach(tagKeyRaw => {
                    // Normalizujemy wpis (małe litery, usuwamy puste znaki na końcach)
                    let tagKey = tagKeyRaw.toLowerCase().trim();

                    // Szukamy w słowniku, jeśli nie ma - robimy awaryjny szary tag
                    const tagDef = (typeof TAG_DICTIONARY !== 'undefined' && TAG_DICTIONARY[tagKey])
                        ? TAG_DICTIONARY[tagKey]
                        : { icon: "ra-help", desc: `Nieznany tag: ${tagKeyRaw}`, color: "#7a6a58" };

                    tagsHtml += `
                        <div class="card-emoji" data-bs-toggle="tooltip" data-bs-placement="bottom" title="${tagDef.desc}" style="border-color: ${tagDef.color}; color: ${tagDef.color};">
                            <i class="ra ${tagDef.icon}"></i>
                        </div>`;
                });
            } else {
                // FALLBACK DLA ROŚLIN BEZ ZDEFINIOWANYCH TAGÓW W JSON
                let wIcon = getPlantWitcherClass(plant);
                let iconDescription = "Zioło Zielarskie";
                switch(wIcon) {
                    case 'ra-pine-tree': iconDescription = "Drzewo Iglaste / Wiecznie Zielone"; break;
                    case 'ra-apple': iconDescription = "Drzewo Liściaste Owocowe"; break;
                    case 'ra-wood-stick': iconDescription = "Drzewo lub duży krzew"; break;
                    case 'ra-sprout': iconDescription = "Krzew / Krzewinka"; break;
                    case 'ra-acorn': iconDescription = "Roślina Bulwiasta / Cebulowa / Kłączowa"; break;
                    case 'ra-flower': iconDescription = "Roślina Kwiatowa / Ozdobna"; break;
                    case 'ra-sun': iconDescription = "Roślina Egzotyczna / Ciepłolubna"; break;
                    case 'ra-leaf': iconDescription = "Roślina Zielna / Zielona"; break;
                }
                tagsHtml = `<div class="card-emoji" data-bs-toggle="tooltip" data-bs-placement="bottom" title="${iconDescription}"><i class="ra ${wIcon}"></i></div>`;
            }

            // BUDOWANIE STRUKTURY KARTY Z NOWYM RZĘDEM POZIOMYM (card-tags-row)
            card.innerHTML = `
                <div class="card-img-container" style="${bgStyle}">
                    <div class="card-tags-row">
                        ${tagsHtml}
                    </div>
                </div>
                <h3 class="card-title">${plant.nazwa_pl}</h3>
                <div class="card-desc-container">
                    <div class="card-desc-scroll">${desc}<br><br>${desc}</div>
                </div>
                <div class="card-trivia-container">
                    <div class="card-trivia-scroll">✨ Ciekawostka: ${trivia}</div>
                </div>
                <div class="card-status-wrapper"></div>
                <div class="card-btn">ROZWIŃ</div>
            `;

            let currentM = new Date().getMonth() + 1;
            const statusWrapper = card.querySelector('.card-status-wrapper');
            function updateMonthUI(m) {
                statusWrapper.innerHTML = renderPlantStatus(plant, m);
                statusWrapper.querySelectorAll('.month-nav').forEach(btn => {
                    btn.onclick = (e) => { e.stopPropagation(); updateMonthUI(parseInt(btn.getAttribute('data-m'))); }
                });
            }
            updateMonthUI(currentM);

            card.onclick = (e) => {
                // Ignorujemy kliknięcia w miesiące i tagi, by móc je swobodnie obsługiwać
                if(e.target.closest('.month-nav')) return;
                if(e.target.closest('.card-emoji')) return;
                if (isDraggingUI) return;

                // Bezpośredni teleport na podstronę rośliny!
                window.location.href = getPlantUrl(plant.id || plant.slug);
            };

            // --- NOWOŚĆ: KLIKNIĘCIE "ROZWIŃ" PRZENOSI OD RAZU DO STRONY ROŚLINY ---
            card.querySelector('.card-btn').onclick = (e) => {
                e.stopPropagation(); // Blokuje otwarcie areny
                if (isDraggingUI) return;
                window.location.href = getPlantUrl(plant.id || plant.slug);
            };

            resultColumn.appendChild(miniRow);
            resultColumn.appendChild(card);
            horizontalResults.appendChild(resultColumn);
        });

        // AKTYWACJA DYMKÓW
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    } else {
        horizontalResults.style.display = 'none';
    }
});

function spawnSeasonNode(seasonName, tasks) {
    document.querySelector('.central-node').classList.add('active-arena');
    clearSatellites(); // Zabijamy kółka
    carousel.classList.remove('active'); // Zabijamy karuzele
    if (horizontalResults) horizontalResults.style.display = 'none';
    if (architecturalSuggestions) architecturalSuggestions.style.display = 'none';

    if (!taskResults) return;

    // Dobieramy ikonę do tytułu kalendarza
    let iconStr = "ra-sun";
    let sName = seasonName.toLowerCase();
    if(sName === "zima" || sName === "styczeń" || sName === "luty") iconStr = "ra-snowflake";
    if(sName === "jesień" || sName === "październik" || sName === "listopad") iconStr = "ra-maple-leaf";
    if(sName === "wiosna" || sName === "marzec" || sName === "kwiecień") iconStr = "ra-sprout";

    let html = `<div class="task-season-title"><i class="ra ${iconStr}"></i> ${seasonName}</div>`;

    // --- NOWOŚĆ: POLE FILTRUJĄCE ---
    html += `<input type="text" id="taskFilterInput" class="task-filter-input" placeholder="🔍 Filtruj listę (np. dąb, zbiór...)" autocomplete="off">`;
    html += `<div id="taskListWrapper">`;

    if (tasks && tasks.length > 0) {
        tasks.forEach(task => {
            // Bezpieczne pobranie nazwy rośliny, do której należy to zadanie
            let plantName = task.rosliny && task.rosliny.length > 0 ? task.rosliny[0] : '';

            // Atrybut data-search łączy tytuł i opis małymi literami, by ułatwić wyszukiwanie
            let searchContent = `${task.tytul} ${task.desc} ${plantName}`.toLowerCase();

            html += `
                <div class="task-card" data-search="${searchContent}" onclick="goToPlantPageByName('${plantName}')">
                    <div class="task-card-icon"><i class="ra ${task.icon || 'ra-leaf'}"></i></div>
                    <div class="task-card-content">
                        <h4 class="task-card-title">${task.tytul}</h4>
                        <p class="task-card-desc">${task.desc}</p>
                    </div>
                    <div class="task-card-action">BADAM <i class="ra ra-eye"></i></div>
                </div>
            `;
        });
    } else {
        html += `<p style="text-align:center; color:#7a6a58; font-style:italic; font-size:16px;">Brak prac w tym okresie. Natura odpoczywa.</p>`;
    }

    html += `</div>`; // Koniec wrappera
    taskResults.innerHTML = html;
    taskResults.style.display = 'block';

    // --- NOWOŚĆ: LOGIKA BŁYSKAWICZNEGO FILTROWANIA KART ---
    const filterInput = document.getElementById('taskFilterInput');
    if (filterInput) {
        filterInput.addEventListener('input', function() {
            const query = this.value.toLowerCase().trim();
            const cards = taskResults.querySelectorAll('.task-card');

            cards.forEach(card => {
                const searchData = card.getAttribute('data-search');
                // Jeżeli wpisany tekst znajduje się w ukrytym atrybucie karty -> pokazujemy. W przeciwnym razie ukrywamy.
                if (searchData.includes(query)) {
                    card.style.display = 'flex';
                } else {
                    card.style.display = 'none';
                }
            });
        });
    }
}

// Funkcja pomocnicza: przesuwa prosto na stronę konkretnej rośliny po kliknięciu
function goToPlantPageByName(plantName) {
    if(!plantName) return;
    const plant = plantsData.find(p => p.nazwa_pl.toLowerCase() === plantName.toLowerCase());
    if(plant) {
        window.location.href = getPlantUrl(plant.id || plant.slug);
    } else {
        document.getElementById('megaAlertPlantName').innerText = plantName;
        document.getElementById('megaAlertOverlay').style.display = 'block';
    }
}

function spawnPlantNetwork(plant) {
    clearSatellites();
    searchNode.classList.add('active-arena');
    carousel.classList.remove('active');

    const rect = networkContainer.getBoundingClientRect();
    const centerX = rect.width / 2, centerY = rect.height / 2 + 120;

    const coreEl = document.createElement('div');
    coreEl.className = 'guild-satellite active docked-mode';
    coreEl.style.zIndex = "200";
    coreEl.innerHTML = `<i class="guild-icon ra ${getWitcherIcon(plant)}"></i><div class="guild-title">${plant.nazwa_pl}</div><div class="expand-hint">POKAŻ STRONĘ</div>`;
    coreEl.onclick = (e) => { e.stopPropagation(); window.location.href = getPlantUrl(plant.id || plant.slug); };
    networkContainer.appendChild(coreEl);

    const coreSat = { element: coreEl, baseAngle: 0, x: centerX, y: centerY, vx: 0, vy: 0, magneticX: 0, magneticY: 0 };
    activeSatellites.push(coreSat); dockedSat = coreSat;

    let recipes = recipesData.filter(r => r.roslina && r.roslina.toLowerCase() === plant.nazwa_pl.toLowerCase());
    populateCarousel(recipes, "recipe", plant.id);

    // --- NAPRAWA 1: Obsługa kluczy name/nazwa w samej Arenie ---
    let compsRaw = plant.permakultura?.gildie || plant.gildie || [];
    let companions = compsRaw.map(g => {
        if (typeof g === 'string') return { nazwa: g, rola: "Powiązanie" };
        return { nazwa: g.nazwa || g.name || "Nieznany gość", rola: g.rola || "Powiązanie" };
    });

    companions.forEach((comp, index) => {
        const angleStep = (2 * Math.PI) / (companions.length || 1);
        const el = document.createElement('div'); el.className = 'guild-satellite';
        const guestPlant = plantsData.find(p => p.nazwa_pl.toLowerCase() === comp.nazwa.toLowerCase());

        el.innerHTML = `<i class="guild-icon ra ${getWitcherIcon(guestPlant || comp)}"></i><div class="guild-title">${comp.nazwa}</div><div class="guild-desc" style="color:#d1b880;">${comp.rola}</div><div class="expand-hint" style="display:block;">ROZWIŃ</div>`;

        el.addEventListener('mousemove', (e) => {
            const r = el.getBoundingClientRect(); const sat = activeSatellites.find(s => s.element === el);
            if(sat) { sat.magneticX = (e.clientX - r.left - r.width/2) * 0.4; sat.magneticY = (e.clientY - r.top - r.height/2) * 0.4; }
        });
        el.addEventListener('mouseleave', () => { const sat = activeSatellites.find(s => s.element === el); if(sat) { sat.magneticX = 0; sat.magneticY = 0; } });

        el.onclick = (e) => {
            e.stopPropagation();
            if (guestPlant) { universalSearch.value = guestPlant.nazwa_pl; spawnPlantNetwork(guestPlant); }
            else {
                document.getElementById('megaAlertPlantName').innerText = comp.nazwa;
                document.getElementById('megaAlertOverlay').style.display = 'block';
            }
        };
        networkContainer.appendChild(el);
        activeSatellites.push({ element: el, baseAngle: index * angleStep, x: rect.width/2, y: rect.height/2 + 120, vx: 0, vy: 0 });
    });
    if (!animationFrameId) animateSatellites();
}

function spawnEntities(entities) {
    searchNode.classList.add('active-arena');
    clearSatellites(); dockedSat = null; carousel.classList.remove('active');
    const rect = networkContainer.getBoundingClientRect();

    entities.forEach((entity, index) => {
        const angleStep = (2 * Math.PI) / (entities.length || 1);
        const el = document.createElement('div'); el.className = 'guild-satellite';
        el.innerHTML = `<i class="guild-icon ra ${getWitcherIcon(entity)}"></i><div class="guild-title">${entity.nazwa}</div><div class="guild-desc">${entity.rola}</div><div class="expand-hint">➤ ROZWIŃ</div>`;

        el.onclick = (e) => {
            e.stopPropagation();
            if (isDown) return;
            const plant = plantsData.find(p => p.nazwa_pl === entity.nazwa || p.id === entity.id);
            if (dockedSat && activeSatellites.find(s => s.element === el) === dockedSat) {
                if (plant) window.location.href = getPlantUrl(plant.id);
                return;
            }
            dockedSat = activeSatellites.find(s => s.element === el);
            if (plant) { let recipes = recipesData.filter(r => r.roslina && r.roslina.toLowerCase() === plant.nazwa_pl.toLowerCase()); populateCarousel(recipes, "recipe", plant.id); }
            else { carousel.classList.remove('active'); }
        };
        networkContainer.appendChild(el);
        activeSatellites.push({ element: el, baseAngle: index * angleStep, x: rect.width/2, y: rect.height/2, vx: 0, vy: 0 });
    });
    if (!animationFrameId) animateSatellites();
}

function animateSatellites() {
    const rect = networkContainer.getBoundingClientRect();
    const centerX = rect.width / 2, centerY = rect.height / 2 + 120;

    globalRotation += 0.0015; dotsPhase += 0.015;
    const isDesktop = window.innerWidth > 768;
    const mainRadiusX = isDesktop ? 340 : 160, mainRadiusY = isDesktop ? 180 : 100;

    let svgContent = '';

    activeSatellites.forEach(sat => {
        let orbitX, orbitY, scale, zIndex, opacity;

        if (sat === dockedSat) {
            orbitX = centerX; orbitY = centerY - 10; scale = 1.0; opacity = 1; zIndex = 200;
        } else {
            let currentAngle = sat.baseAngle + globalRotation;
            orbitX = centerX + Math.cos(currentAngle) * mainRadiusX;
            orbitY = centerY + Math.sin(currentAngle) * mainRadiusY;

            const depth = -Math.sin(currentAngle);
            // --- NAPRAWA 4: Lepsza widoczność kul na orbicie ---
            scale = 0.9 + (depth * 0.2);     // Waha się między 0.7 a 1.1 (wyraźniejsze kule)
            opacity = 0.85 + (depth * 0.15); // Waha się między 0.7 a 1.0 (nie bledną tak mocno)
            zIndex = Math.floor(100 + depth * 50);

            sat.magneticX *= 0.85; sat.magneticY *= 0.85;
            orbitX += sat.magneticX; orbitY += sat.magneticY;

            if (dockedSat) {
                const startX = dockedSat.x, startY = dockedSat.y, endX = sat.x, endY = sat.y;
                svgContent += `<line x1="${startX}" y1="${startY}" x2="${endX}" y2="${endY}" class="energy-line" />`;
                for(let i=0; i<3; i++) {
                    let p = (dotsPhase + i*0.33) % 1;
                    let dotX = startX + (endX - startX) * p, dotY = startY + (endY - startY) * p;
                    let dotSize = 2 + (i%2)*1.5;
                    svgContent += `<circle cx="${dotX}" cy="${dotY}" r="${dotSize}" class="energy-dot" opacity="${Math.sin(p*Math.PI)}" />`;
                }
            }
        }

        sat.x += (orbitX - sat.x) * 0.15; sat.y += (orbitY - sat.y) * 0.15;
        sat.element.style.opacity = opacity.toFixed(2); sat.element.style.zIndex = zIndex;
        sat.element.style.transform = `translate(calc(-50% + ${sat.x - centerX}px), calc(-50% + ${sat.y - centerY}px)) scale(${scale.toFixed(2)})`;
    });

    svgLines.innerHTML = svgContent;
    if (activeSatellites.length > 0) animationFrameId = requestAnimationFrame(animateSatellites);
}

function clearSatellites() {
    activeSatellites.forEach(s => s.element.remove());
    activeSatellites = []; svgLines.innerHTML = '';
    if (animationFrameId) { cancelAnimationFrame(animationFrameId); animationFrameId = null; }
}

let isDown = false, startX, scrollLeft;
carousel.addEventListener('mousedown', (e) => { isDown = true; startX = e.pageX - carousel.offsetLeft; scrollLeft = carousel.scrollLeft; });
carousel.addEventListener('mouseleave', () => isDown = false);
carousel.addEventListener('mouseup', () => isDown = false);
carousel.addEventListener('mousemove', (e) => { if (!isDown) return; e.preventDefault(); carousel.scrollLeft = scrollLeft - (e.pageX - carousel.offsetLeft - startX) * 1.5; });

carousel.addEventListener('scroll', () => {
    const items = carousel.querySelectorAll('.carousel-item'), center = carousel.getBoundingClientRect().left + carousel.offsetWidth / 2;
    items.forEach(item => {
        const dist = Math.abs(center - (item.getBoundingClientRect().left + item.offsetWidth / 2));
        item.style.transform = `scale(${Math.max(1 - (dist / (carousel.offsetWidth / 2)) * 0.4, 0.6)})`;
        item.style.opacity = Math.max(1 - (dist / (carousel.offsetWidth / 2)) * 0.8, 0);
    });
});

function populateCarousel(items, type, parentId = null) {
    carousel.innerHTML = '';
    if (items.length === 0) { carousel.classList.remove('active'); return; }
    items.forEach(item => {
        const el = document.createElement('div'); el.className = 'carousel-item';
        if (type === "recipe") {
            let ingsHtml = Array.isArray(item.skladniki) ? item.skladniki.slice(0, 3).map(s => `<li>${s}</li>`).join('') + (item.skladniki.length > 3 ? '<li>...</li>' : '') : `<li>${item.skladniki || 'Brak danych'}</li>`;
            let prepText = Array.isArray(item.sposob_przygotowania) ? item.sposob_przygotowania.join(' ') : (item.sposob_przygotowania || 'Brak instrukcji');
            el.innerHTML = `<i class="carousel-icon ra ra-scroll"></i><div class="carousel-title">${item.tytul}</div><div class="recipe-unroll"><div class="unroll-title">Składniki</div><ul class="unroll-list">${ingsHtml}</ul><div class="unroll-title">Czynności</div><p class="unroll-text">${prepText}</p></div>`;
            el.addEventListener('click', (e) => { e.stopPropagation(); if(!isDown) openRecipeModal(item, parentId); });
        } else {
            let meta = (item.faza || item.pora || item.pogoda) ? `<div class="task-meta">${item.faza ? `<div>🌙 Faza: <span>${item.faza}</span></div>`:''}${item.pora ? `<div>⏳ Pora: <span>${item.pora}</span></div>`:''}${item.pogoda ? `<div>⛅ Warunki: <span>${item.pogoda}</span></div>`:''}</div>` : '';
            let plants = (item.rosliny || []).map(p => `<div class="task-plant-item" onclick="if(!isDown){ event.stopPropagation(); goToPlantPage('${p}'); }">${p}</div>`).join('');
            el.innerHTML = `<i class="carousel-icon ra ${item.icon || 'ra-leaf'}"></i><div class="carousel-title">${item.tytul}</div><div class="carousel-desc">${item.desc}</div><div class="task-plants-list" style="z-index:100; pointer-events:auto;">${meta}${plants}</div>`;
        }
        carousel.appendChild(el);
    });
    carousel.classList.add('active'); setTimeout(() => { carousel.scrollLeft = 0; carousel.dispatchEvent(new Event('scroll')); }, 50);
}

function openRecipeModal(recipe, plantId) {
    try {
        document.getElementById('modalRecipeTitle').innerText = recipe.tytul || "Przepis"; document.getElementById('modalRecipePlantName').innerText = recipe.roslina || "Zioło";
        document.getElementById('modalRecipeIngredients').innerHTML = Array.isArray(recipe.skladniki) ? recipe.skladniki.map(s => `<li>${s}</li>`).join('') : `<li>${recipe.skladniki || 'Brak'}</li>`;
        document.getElementById('modalRecipePreparation').innerHTML = Array.isArray(recipe.sposob_przygotowania) ? `<ol style="padding-left: 20px;">${recipe.sposob_przygotowania.map(k => `<li style="margin-bottom:10px;">${k}</li>`).join('')}</ol>` : `<p style="white-space: pre-line;">${recipe.sposob_przygotowania || 'Brak'}</p>`;

        const dosage = document.getElementById('modalRecipeDosage'); dosage.innerHTML = recipe.dawkowanie ? `<strong>💊 Dawkowanie:</strong> ${recipe.dawkowanie}` : ''; dosage.style.display = recipe.dawkowanie ? 'block' : 'none';
        const notes = document.getElementById('modalRecipeNotes'); let notesContent = "";
        if (recipe.uwagi) notesContent += `<strong>⚠️ Uwagi:</strong> ${recipe.uwagi}<br>`;
        let zrodlaDanych = recipe.zrodla || recipe.zrodlo; if (zrodlaDanych) notesContent += `<strong style="margin-top: 5px; display:inline-block;">📚 Źródła:</strong> ${Array.isArray(zrodlaDanych) ? zrodlaDanych.join(', ') : zrodlaDanych}`;
        notes.innerHTML = notesContent; notes.style.display = notesContent ? 'block' : 'none';
        bootstrap.Modal.getOrCreateInstance(document.getElementById('dynamicRecipeModal')).show();
    } catch (e) { console.error("Błąd otwierania modala:", e); }
}

function renderBestiary() {
    const grid = document.getElementById('bestiaryGrid');
    if (!grid) return;

    // --- NAPRAWA 2: Użycie nowej funkcji również w Bestiariuszu ---
    grid.innerHTML = plantsData.map(plant => `
        <div class="witcher-card"><div class="witcher-card-img" style="background-image: url('${getBestImageUrl(plant)}')"></div><div class="witcher-card-content"><h3 class="witcher-card-title">${plant.nazwa_pl}</h3><p class="witcher-card-desc">${plant.rodzina || ''}</p><a href="${getPlantUrl(plant.id)}" class="witcher-btn">Zbadaj</a></div></div>
    `).join('');
}
renderBestiary();