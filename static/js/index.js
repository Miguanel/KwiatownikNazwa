// ==========================================
// SŁOWNIKI ALCHEMICZNE I POMOCNICZE
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

function getContextTooltip(title, text) {
    if(!text) return '';
    return `<span class="info-tooltip">?<span class="tooltip-text"><strong>${title}</strong><br>${text}</span></span>`;
}

function extractContext(fullText) {
    let match = fullText.match(/^(.*?)\s*\((.*?)\)$/);
    if (match) return { name: match[1], desc: match[2] };
    return { name: fullText, desc: '' };
}

function getDictContext(value, dictObj) {
    if(!value) return { name: '', desc: '' };
    let cleanName = value.replace(/_/g, ' ');
    let desc = '';
    for (let key in dictObj) {
        if (value.toLowerCase().includes(key)) desc += dictObj[key] + " ";
    }
    if (cleanName.includes('_')) cleanName = cleanName.split('_')[1];
    return { name: cleanName, desc: desc.trim() };
}


// --- NOWOŚĆ: SYSTEM PRZECIĄGANIA (DRAG TO SCROLL) ---
let isDraggingUI = false;

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
        const walk = (x - startX) * 1.5;
        if (Math.abs(walk) > 5) isDraggingUI = true;
        slider.scrollLeft = scrollLeft - walk;
    });
}

function getBestImageUrl(plant) {
    if (plant.url && typeof plant.url === 'object') return Object.values(plant.url)[0] || '';
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
    addSymptom(recipe.wlasciwosci, rName, plantId);
    if (recipe.efekty) addSymptom(recipe.efekty, rName, plantId);
    if (recipe.tagi) addSymptom(recipe.tagi, rName, plantId);
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

const monthNames = ["", "styczeń", "luty", "marzec", "kwiecień", "maj", "czerwiec", "lipiec", "sierpień", "wrzesień", "październik", "listopad", "grudzień"];
const seasonMonths = { "zima": [12, 1, 2], "wiosna": [3, 4, 5], "lato": [6, 7, 8], "jesień": [9, 10, 11] };
const seasonalMap = { "wiosna": [], "lato": [], "jesień": [], "zima": [], "styczeń": [], "luty": [], "marzec": [], "kwiecień": [], "maj": [], "czerwiec": [], "lipiec": [], "sierpień": [], "wrzesień": [], "październik": [], "listopad": [], "grudzień": [] };

plantsData.forEach(plant => {
    if (plant.kalendarz_ogrodnika && plant.kalendarz_ogrodnika.zadania) {
        plant.kalendarz_ogrodnika.zadania.forEach(zadanie => {
            let taskIcon = "ra-sprout";
            let taskNameLower = zadanie.czynnosc.toLowerCase();
            if (taskNameLower.includes('sadz')) taskIcon = "ra-plant-seed";
            if (taskNameLower.includes('zbiór') || taskNameLower.includes('zbier')) taskIcon = "ra-sickle";
            if (taskNameLower.includes('ciąc') || taskNameLower.includes('cięci')) taskIcon = "ra-sword";
            if (taskNameLower.includes('podlew')) taskIcon = "ra-water-drop";

            let taskEntry = { tytul: `${plant.nazwa_pl} - ${zadanie.czynnosc}`, desc: zadanie.opis || `Czas na: ${zadanie.czynnosc}`, icon: taskIcon, rosliny: [plant.nazwa_pl] };

            if (zadanie.miesiace) {
                zadanie.miesiace.forEach(m => {
                    let mName = monthNames[m];
                    if (mName) seasonalMap[mName].push(taskEntry);
                    for (const [season, mArray] of Object.entries(seasonMonths)) {
                        if (mArray.includes(m)) {
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

const calendarSearchMap = {};

if (kalendarz.okresy) {
    Object.keys(kalendarz.okresy).forEach(okres => {
        calendarSearchMap[okres.toLowerCase()] = { type: 'Sezon / Czas', data: kalendarz.okresy[okres].zadania, label: okres };
    });
}

const actionBuckets = {
    "zbiór": { type: "Grupa Czynności", label: "Zbiór (Wszystkie rodzaje)", keywords: ["zbiór", "zbier", "żniwa"], data: [], icon: "ra-sickle" },
    "sadzenie": { type: "Grupa Czynności", label: "Sadzenie i Rozmnażanie", keywords: ["sadz", "siew", "rozmnaża", "pikow"], data: [], icon: "ra-plant-seed" },
    "cięcie": { type: "Grupa Czynności", label: "Cięcie i Pielęgnacja", keywords: ["ciąc", "cięci", "przycina", "formow", "piel"], data: [], icon: "ra-sword" },
    "podlewanie": { type: "Grupa Czynności", label: "Nawadnianie i Nawożenie", keywords: ["podlew", "nawoż", "zasila", "nawadnia"], data: [], icon: "ra-water-drop" }
};

if (kalendarz.czynnosci) {
    Object.keys(kalendarz.czynnosci).forEach(czynnosc => {
        const czynnoscLower = czynnosc.toLowerCase();
        let taskDataList = Array.isArray(kalendarz.czynnosci[czynnosc]) ? kalendarz.czynnosci[czynnosc] : [kalendarz.czynnosci[czynnosc]];
        let matchedToGroup = false;

        for (let bucketKey in actionBuckets) {
            let bucket = actionBuckets[bucketKey];
            if (bucket.keywords.some(kw => czynnoscLower.includes(kw))) {
                let formattedTasks = taskDataList.map(t => {
                    let plantName = t.roslina || (t.rosliny && t.rosliny[0]) || "";
                    return { tytul: t.tytul || (plantName ? `${plantName} - ${czynnosc}` : czynnosc), desc: t.desc || t.opis || `Czynność: ${czynnosc}`, icon: t.icon || bucket.icon, rosliny: t.rosliny || (t.roslina ? [t.roslina] : []) };
                });
                bucket.data = bucket.data.concat(formattedTasks);
                matchedToGroup = true;
                break;
            }
        }

        if (!matchedToGroup) {
            let formattedTasks = taskDataList.map(t => {
                let plantName = t.roslina || (t.rosliny && t.rosliny[0]) || "";
                return { tytul: t.tytul || (plantName ? `${plantName} - ${czynnosc}` : czynnosc), desc: t.desc || t.opis || `Czynność: ${czynnosc}`, icon: t.icon || "ra-sprout", rosliny: t.rosliny || (t.roslina ? [t.roslina] : []) };
            });
            calendarSearchMap[czynnoscLower] = { type: 'Czynność', data: formattedTasks, label: czynnosc };
        }
    });

    Object.keys(actionBuckets).forEach(bucketKey => {
        let bucket = actionBuckets[bucketKey];
        if (bucket.data.length > 0) {
            bucket.keywords.forEach(kw => { calendarSearchMap[kw] = bucket; });
        }
    });
}

Object.keys(seasonalMap).forEach(key => {
    if (seasonalMap[key].length > 0) {
        if (calendarSearchMap[key]) {
            calendarSearchMap[key].data = calendarSearchMap[key].data.concat(seasonalMap[key]);
        } else {
            let typeLabel = Object.keys(seasonMonths).includes(key) ? 'Pora Roku' : 'Miesiąc';
            calendarSearchMap[key] = { type: typeLabel, data: seasonalMap[key], label: key.charAt(0).toUpperCase() + key.slice(1) };
        }
    }
});


// ==========================================
// ZMIENNE ARENY
// ==========================================
let globalRotation = 0, currentRotationSpeed = 0, dotsPhase = 0;
let activeSatellites = [], mouseX = -1000, mouseY = -1000, animationFrameId, dockedSat = null;

const universalSearch = document.getElementById('universalSearch');
const horizontalResults = document.getElementById('horizontalResults');
enableDragToScroll(horizontalResults);
const networkContainer = document.getElementById('guildNetwork');
const carousel = document.getElementById('recipeCarousel');
const searchNode = document.getElementById('mainSearchNode');
const svgLines = document.getElementById('arenaLines');
const taskResults = document.getElementById('taskResults');

document.addEventListener('mousemove', e => { mouseX = e.clientX; mouseY = e.clientY; });


// ==========================================
// WYSZUKIWARKA GŁÓWNA
// ==========================================
universalSearch.addEventListener('input', function() {
    const query = this.value.toLowerCase().trim();

    horizontalResults.innerHTML = '';
    if (taskResults) taskResults.style.display = 'none';
    clearSatellites();
    carousel.classList.remove('active');

    if (query.length < 2) {
        horizontalResults.style.display = 'none';
        searchNode.classList.remove('active-arena');
        return;
    }

    let autoRenderCalendarNode = null;

    const filteredPlants = plantsData.filter(p => p.nazwa_pl.toLowerCase().includes(query) || (p.rodzina && p.rodzina.toLowerCase().includes(query)));

    if (filteredPlants.length > 0) {
        horizontalResults.style.display = 'flex';

        filteredPlants.forEach(plant => {
            const resultColumn = document.createElement('div');
            resultColumn.className = 'result-column';

            const miniRow = document.createElement('div');
            miniRow.className = 'guild-mini-row';
            enableDragToScroll(miniRow);

            let compsRaw = plant.permakultura?.gildie || plant.gildie || [];
            let comps = compsRaw.map(g => {
                if (typeof g === 'string') return { nazwa: g, rola: "Powiązanie" };
                return { nazwa: g.nazwa || g.name || "Nieznany gość", rola: g.rola || "Powiązanie" };
            });

            if (comps.length > 0) {
                comps.forEach((comp, index) => {
                    const guestPlant = plantsData.find(p => p.nazwa_pl.toLowerCase() === comp.nazwa.toLowerCase());
                    let imageUrl = guestPlant ? getBestImageUrl(guestPlant) : '';
                    let shortName = comp.nazwa.split(' ')[0];

                    const miniCard = document.createElement('div');
                    miniCard.className = 'guild-mini-card';
                    miniCard.dataset.index = index;

                    miniCard.innerHTML = `
                        <div class="guild-mini-img" style="${imageUrl ? `background-image: url('${imageUrl}');` : 'background: #5a4f41;'}"></div>
                        <div class="guild-mini-title-short">${shortName}</div>
                        <div class="guild-mini-expanded">
                            <button class="guild-nav-btn guild-nav-left"><i class="ra ra-bottom-left"></i></button>
                            <div class="expanded-title">${comp.nazwa}</div>
                            <div class="expanded-role">${comp.rola || "Powiązanie gildyjne"}</div>
                            <button class="expanded-btn">POKAŻ <i class="ra ra-eye"></i></button>
                            <button class="guild-nav-btn guild-nav-right"><i class="ra ra-bottom-right"></i></button>
                        </div>
                    `;

                    const navLeftBtn = miniCard.querySelector('.guild-nav-left');
                    const navRightBtn = miniCard.querySelector('.guild-nav-right');
                    if (index === 0) navLeftBtn.style.visibility = 'hidden';
                    if (index === comps.length - 1) navRightBtn.style.visibility = 'hidden';

                    navLeftBtn.onclick = (e) => {
                        e.stopPropagation();
                        const prevCard = miniRow.querySelector(`.guild-mini-card[data-index="${index - 1}"]`);
                        if (prevCard) simulateHover(prevCard, miniRow);
                    };

                    navRightBtn.onclick = (e) => {
                        e.stopPropagation();
                        const nextCard = miniRow.querySelector(`.guild-mini-card[data-index="${index + 1}"]`);
                        if (nextCard) simulateHover(nextCard, miniRow);
                    };

                    miniCard.addEventListener('mouseenter', () => { simulateHover(miniCard, miniRow); });

                    const navigateToCompanion = (e) => {
                        e.stopPropagation();
                        if (isDraggingUI) return;
                        if(guestPlant) window.location.href = getPlantUrl(guestPlant.id || guestPlant.slug);
                        else {
                            document.getElementById('megaAlertPlantName').innerText = comp.nazwa;
                            document.getElementById('megaAlertOverlay').style.display = 'block';
                        }
                    };

                    miniCard.onclick = navigateToCompanion;
                    miniCard.querySelector('.expanded-btn').onclick = navigateToCompanion;
                    miniRow.appendChild(miniCard);
                });
            }

            const card = document.createElement('div');
            card.className = 'result-card';
            card.style.cursor = 'pointer';

            let imageUrl = getBestImageUrl(plant);
            let bgStyle = imageUrl ? `background-image: url('${imageUrl}');` : `background: #d1c7a7;`;
            let desc = plant.opis || "Brak szczegółowego opisu zielarskiego.";
            let trivia = plant.ciekawostki && plant.ciekawostki.length > 0 ? plant.ciekawostki[Math.floor(Math.random() * plant.ciekawostki.length)] : "Zioła kryją wiele tajemnic...";

            let tagsHtml = '';
            if (plant.tagi && Array.isArray(plant.tagi) && plant.tagi.length > 0) {
                plant.tagi.forEach(tagKeyRaw => {
                    let tagKey = tagKeyRaw.toLowerCase().trim();
                    const tagDef = (typeof TAG_DICTIONARY !== 'undefined' && TAG_DICTIONARY[tagKey]) ? TAG_DICTIONARY[tagKey] : { icon: "ra-help", desc: tagKeyRaw, color: "#7a6a58" };
                    tagsHtml += `<div class="card-emoji" data-bs-toggle="tooltip" title="${tagDef.desc}" style="border-color: ${tagDef.color}; color: ${tagDef.color};"><i class="ra ${tagDef.icon}"></i></div>`;
                });
            }

            card.innerHTML = `
                <div class="card-img-container" style="${bgStyle}">
                    <div class="card-tags-row">${tagsHtml}</div>
                </div>
                <h3 class="card-title">${plant.nazwa_pl}</h3>
                <div class="card-desc-container"><div class="card-desc-scroll">${desc}<br><br>${desc}</div></div>
                <div class="card-trivia-container"><div class="card-trivia-scroll">✨ Ciekawostka: ${trivia}</div></div>
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
                if(e.target.closest('.month-nav') || e.target.closest('.card-emoji') || isDraggingUI) return;
                window.location.href = getPlantUrl(plant.id || plant.slug);
            };

            card.querySelector('.card-btn').onclick = (e) => {
                e.stopPropagation();
                if (isDraggingUI) return;
                window.location.href = getPlantUrl(plant.id || plant.slug);
            };

            resultColumn.appendChild(miniRow);
            resultColumn.appendChild(card);
            horizontalResults.appendChild(resultColumn);
        });

        let combinedItems = [];
        filteredPlants.forEach(plant => {
            if (plant.kalendarz_ogrodnika && plant.kalendarz_ogrodnika.zadania) {
                plant.kalendarz_ogrodnika.zadania.forEach(z => {
                    combinedItems.push({
                        tytul: `${plant.nazwa_pl} - ${z.czynnosc}`,
                        desc: z.opis || `Czas na: ${z.czynnosc}`,
                        icon: "ra-sickle",
                        rosliny: [plant.nazwa_pl],
                        isRecipe: false
                    });
                });
            }
            let relatedRecipes = recipesData.filter(r => r.roslina && r.roslina.toLowerCase() === plant.nazwa_pl.toLowerCase());
            relatedRecipes.forEach(r => {
                let prepText = Array.isArray(r.sposob_przygotowania) ? r.sposob_przygotowania.join(' ') : (r.sposob_przygotowania || 'Brak instrukcji');
                combinedItems.push({
                    tytul: r.tytul,
                    desc: prepText,
                    icon: "ra-potion",
                    rosliny: [plant.nazwa_pl],
                    isRecipe: true,
                    rawData: r
                });
            });
        });

        if (combinedItems.length > 0) {
            spawnSeasonNode(`Wiedza i Prace: ${filteredPlants[0].nazwa_pl}`, combinedItems, true);
        }

        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

        return;
    }

    horizontalResults.style.display = 'none';

    const matchedCalendar = Object.keys(calendarSearchMap).filter(k => k.includes(query));
    if (matchedCalendar.length > 0) {
        const exactMatch = matchedCalendar.find(k => k === query);
        autoRenderCalendarNode = exactMatch ? calendarSearchMap[exactMatch] : calendarSearchMap[matchedCalendar[0]];
        if (autoRenderCalendarNode) {
            spawnSeasonNode(autoRenderCalendarNode.label, autoRenderCalendarNode.data, true);
            return;
        }
    }

    const matchedRecipes = recipesData.filter(r => r.tytul && r.tytul.toLowerCase().includes(query));
    if (matchedRecipes.length > 0) {
        let recipeItems = matchedRecipes.map(r => {
            let prepText = Array.isArray(r.sposob_przygotowania) ? r.sposob_przygotowania.join(' ') : (r.sposob_przygotowania || 'Brak instrukcji');
            return {
                tytul: r.tytul,
                desc: prepText,
                icon: "ra-potion",
                rosliny: [r.roslina || "Zioło"],
                isRecipe: true,
                rawData: r
            };
        });
        const queryTitle = query.charAt(0).toUpperCase() + query.slice(1);
        spawnSeasonNode(`Przepisy: ${queryTitle}`, recipeItems, true);
        return;
    }

    const filteredSymptoms = Object.keys(symptomMap).filter(s => s.includes(query));
    if (filteredSymptoms.length > 0) {
        const exactMatch = filteredSymptoms.find(k => k === query);
        const sym = exactMatch ? exactMatch : filteredSymptoms[0];
        spawnEntities(symptomMap[sym]);
        return;
    }

    const filteredColors = Object.keys(colorMap).filter(c => c.includes(query));
    if (filteredColors.length > 0) {
        const exactMatch = filteredColors.find(k => k === query);
        const color = exactMatch ? exactMatch : filteredColors[0];
        spawnEntities(colorMap[color]);
        return;
    }
});


// ==========================================
// FUNKCJE POMOCNICZE WYSZUKIWANIA
// ==========================================
function simulateHover(targetCard, row) {
    row.querySelectorAll('.guild-mini-card').forEach(c => c.classList.remove('force-hover'));
    targetCard.classList.add('force-hover');
    const scrollTarget = targetCard.offsetLeft - (row.clientWidth / 2) + (targetCard.clientWidth / 2);
    row.scrollTo({ left: scrollTarget, behavior: 'smooth' });
}

function spawnSeasonNode(seasonName, tasks, isAutoRender = false) {
    document.querySelector('.central-node').classList.add('active-arena');

    if (!isAutoRender) {
        clearSatellites();
        carousel.classList.remove('active');
        if (horizontalResults) horizontalResults.style.display = 'none';
    }

    if (!taskResults) return;

    let iconStr = "ra-sun";
    let sName = seasonName.toLowerCase();
    if(sName === "zima" || sName === "styczeń" || sName === "luty") iconStr = "ra-snowflake";
    if(sName === "jesień" || sName === "październik" || sName === "listopad") iconStr = "ra-maple-leaf";
    if(sName === "wiosna" || sName === "marzec" || sName === "kwiecień") iconStr = "ra-sprout";
    if(sName.includes("zbiór")) iconStr = "ra-sickle";
    if(sName.includes("sadzenie")) iconStr = "ra-plant-seed";
    if(sName.includes("cięcie")) iconStr = "ra-sword";
    if(sName.includes("nawadnianie")) iconStr = "ra-water-drop";
    if(sName.includes("wiedza i prace")) iconStr = "ra-parchment";
    if(sName.includes("przepis")) iconStr = "ra-flask";

    let html = `<div class="task-season-title"><i class="ra ${iconStr}"></i> ${seasonName}</div>`;
    html += `<input type="text" id="taskFilterInput" class="task-filter-input" placeholder="🔍 Filtruj tę listę (np. syrop, kora...)" autocomplete="off">`;
    html += `<div id="taskListWrapper">`;

    if (tasks && tasks.length > 0) {
        tasks.forEach(task => {
            let plantName = task.rosliny && task.rosliny.length > 0 ? task.rosliny[0] : '';
            let searchContent = `${task.tytul} ${task.desc} ${plantName}`.toLowerCase();

            let clickAction = "";
            let actionLabel = "";

            if (task.isRecipe) {
                clickAction = `window.redirectToRecipe('${task.tytul.replace(/'/g, "\\'")}', event)`;
                actionLabel = `PRZEPIS <i class="ra ra-scroll-unfurled"></i>`;
            } else {
                clickAction = `goToPlantPageByName('${plantName}')`;
                actionLabel = `BADAM <i class="ra ra-eye"></i>`;
            }

            html += `
                <div class="task-card" data-search="${searchContent}" onclick="${clickAction}">
                    <div class="task-card-icon"><i class="ra ${task.icon || 'ra-leaf'}"></i></div>
                    <div class="task-card-content">
                        <h4 class="task-card-title">${task.tytul}</h4>
                        <p class="task-card-desc">${task.desc.substring(0, 85)}...</p>
                    </div>
                    <div class="task-card-action" style="${task.isRecipe ? 'background:#8a7a58;color:#fff;' : ''}">${actionLabel}</div>
                </div>
            `;
        });
    } else {
        html += `<p style="text-align:center; color:#7a6a58; font-style:italic; font-size:16px;">Brak wpisów.</p>`;
    }

    html += `</div>`;
    taskResults.innerHTML = html;
    taskResults.style.display = 'block';

    const filterInput = document.getElementById('taskFilterInput');
    if (filterInput) {
        filterInput.addEventListener('input', function() {
            const query = this.value.toLowerCase().trim();
            const cards = taskResults.querySelectorAll('.task-card');
            cards.forEach(card => {
                const searchData = card.getAttribute('data-search');
                card.style.display = searchData.includes(query) ? 'flex' : 'none';
            });
        });
    }
}

// Błyskawiczny teleport do Przepiśnika
window.redirectToRecipe = function(title, event) {
    if(event) event.stopPropagation();
    if(isDraggingUI) return;
    window.location.href = '/przepisy/?q=' + encodeURIComponent(title) + '&autoopen=true';
};

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


// ==========================================
// FUNKCJE ARENY I SFER (Zwrócone na miejsce!)
// ==========================================
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
            scale = 0.9 + (depth * 0.2);
            opacity = 0.85 + (depth * 0.15);
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


// ==========================================
// KARUZELA
// ==========================================
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
            let basicIngs = Array.isArray(item.skladniki) ? item.skladniki.map(s => typeof s === 'object' ? s.nazwa : s) : [item.skladniki];
            let ingsHtml = basicIngs.slice(0, 3).map(s => `<li>${s}</li>`).join('') + (basicIngs.length > 3 ? '<li>...</li>' : '');
            let prepText = Array.isArray(item.sposob_przygotowania) ? item.sposob_przygotowania.join(' ') : (item.sposob_przygotowania || 'Brak instrukcji');

            el.innerHTML = `<i class="carousel-icon ra ra-scroll"></i><div class="carousel-title">${item.tytul}</div><div class="recipe-unroll"><div class="unroll-title">Składniki</div><ul class="unroll-list">${ingsHtml}</ul><div class="unroll-title">Czynności</div><p class="unroll-text">${prepText}</p></div>`;
            el.addEventListener('click', (e) => {
                e.stopPropagation();
                if(!isDown) {
                    window.location.href = '/przepisy/?q=' + encodeURIComponent(item.tytul) + '&autoopen=true';
                }
            });
        } else {
            let meta = (item.faza || item.pora || item.pogoda) ? `<div class="task-meta">${item.faza ? `<div>🌙 Faza: <span>${item.faza}</span></div>`:''}${item.pora ? `<div>⏳ Pora: <span>${item.pora}</span></div>`:''}${item.pogoda ? `<div>⛅ Warunki: <span>${item.pogoda}</span></div>`:''}</div>` : '';
            let plants = (item.rosliny || []).map(p => `<div class="task-plant-item" onclick="if(!isDown){ event.stopPropagation(); goToPlantPageByName('${p}'); }">${p}</div>`).join('');
            el.innerHTML = `<i class="carousel-icon ra ${item.icon || 'ra-leaf'}"></i><div class="carousel-title">${item.tytul}</div><div class="carousel-desc">${item.desc}</div><div class="task-plants-list" style="z-index:100; pointer-events:auto;">${meta}${plants}</div>`;
        }
        carousel.appendChild(el);
    });
    carousel.classList.add('active'); setTimeout(() => { carousel.scrollLeft = 0; carousel.dispatchEvent(new Event('scroll')); }, 50);
}

// ==========================================
// BESTIARIUSZ
// ==========================================
function renderBestiary() {
    const grid = document.getElementById('bestiaryGrid');
    if (!grid) return;
    grid.innerHTML = plantsData.map(plant => `
        <div class="witcher-card"><div class="witcher-card-img" style="background-image: url('${getBestImageUrl(plant)}')"></div><div class="witcher-card-content"><h3 class="witcher-card-title">${plant.nazwa_pl}</h3><p class="witcher-card-desc">${plant.rodzina || ''}</p><a href="${getPlantUrl(plant.id)}" class="witcher-btn">Zbadaj</a></div></div>
    `).join('');
}
renderBestiary();