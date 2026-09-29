// ==========================================
// MAGICZNY OBIEKTYW – rozpoznawanie rośliny ze zdjęcia (plant.id)
// Działa na stronie głównej (#universalSearch) i w Przepiśniku (#recipeSearch).
// Strona może zdefiniować window.onPlantRecognized({latin, polish}) -> nazwa do pokazania;
// wtedy sama decyduje, co wpisać w wyszukiwarkę (strona główna dopasowuje nazwę łacińską do Bestiariusza).
// window.kwRecognizeFile(file) pozwala rozpoznać zdjęcie wklejone lub upuszczone na wyszukiwarkę.
// ==========================================
document.addEventListener("DOMContentLoaded", () => {
    const magicBtn = document.getElementById("magicLensBtn");
    const cameraInput = document.getElementById("magicCameraInput");
    const searchInput = document.getElementById("universalSearch") || document.getElementById("recipeSearch");
    const saveFavBtn = document.getElementById("saveFavoriteBtn");
    const originalBtnHtml = magicBtn ? magicBtn.innerHTML : "";

    let currentRecognizedPlant = "";
    let busy = false;

    // 1. AKTYWACJA APARATU / WYBORU PLIKU
    if (magicBtn && cameraInput) {
        magicBtn.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (busy) return;
            cameraInput.value = "";
            cameraInput.click();
        });
    }

    // 2. TŁUMACZ WIKIPEDII: nazwa łacińska -> polska
    async function getPolishName(latinName) {
        try {
            const searchUrl = `https://en.wikipedia.org/w/api.php?action=query&prop=langlinks&lllang=pl&redirects=1&titles=${encodeURIComponent(latinName)}&format=json&origin=*`;
            const response = await fetch(searchUrl);
            const data = await response.json();
            const pages = data.query.pages;
            const pageId = Object.keys(pages)[0];
            if (pageId !== "-1" && pages[pageId].langlinks) {
                return pages[pageId].langlinks[0]['*'];
            }
            return latinName;
        } catch (error) {
            console.error("Błąd tłumaczenia Wiki:", error);
            return latinName;
        }
    }

    // 3. ANALIZA ZDJĘCIA
    async function handleFile(file) {
        if (!file || busy) return;
        if (file.type && !file.type.startsWith("image/")) {
            alert("To nie jest zdjęcie. Wybierz plik graficzny (JPG, PNG…).");
            return;
        }
        busy = true;
        if (magicBtn) {
            magicBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> <span class="kw-lens-label">Analiza...</span>';
            magicBtn.disabled = true;
        }
        try {
            const base64Image = await getBase64(file);
            const latinResult = await identifyPlantAPI(base64Image);
            if (!latinResult) {
                alert("Nie udało się rozpoznać rośliny. Spróbuj ostrzejszego zdjęcia liścia lub kwiatu, z bliska i w dobrym świetle.");
                return;
            }
            const polishResult = await getPolishName(latinResult);
            let name = polishResult;

            if (typeof window.onPlantRecognized === "function") {
                name = window.onPlantRecognized({ latin: latinResult, polish: polishResult }) || polishResult;
            } else if (searchInput) {
                searchInput.value = name;
                searchInput.dispatchEvent(new Event('input', { bubbles: true }));
            }
            currentRecognizedPlant = name;
            showRecognizedModal(name);
        } catch (error) {
            console.error("Błąd:", error);
            alert("Problem z rozpoznawaniem. Sprawdź połączenie z internetem i spróbuj ponownie.");
        } finally {
            busy = false;
            if (magicBtn) {
                magicBtn.innerHTML = originalBtnHtml;
                magicBtn.disabled = false;
            }
            if (cameraInput) cameraInput.value = "";
        }
    }
    window.kwRecognizeFile = handleFile;

    if (cameraInput) {
        cameraInput.addEventListener("change", (event) => handleFile(event.target.files[0]));
    }

    function showRecognizedModal(plantName) {
        const modalEl = document.getElementById('favoritePlantModal');
        if (modalEl && window.bootstrap) {
            document.getElementById("recognizedPlantName").textContent = plantName;
            bootstrap.Modal.getOrCreateInstance(modalEl).show();
        }
    }

    // 4. ZAPIS DO ZIELNIKA (Ulubione)
    if (saveFavBtn) {
        saveFavBtn.addEventListener("click", () => {
            if (!currentRecognizedPlant) return;
            let favorites = [];
            try { favorites = JSON.parse(localStorage.getItem("herbariumFavorites")) || []; } catch (e) { favorites = []; }
            if (!favorites.includes(currentRecognizedPlant)) {
                favorites.push(currentRecognizedPlant);
                try { localStorage.setItem("herbariumFavorites", JSON.stringify(favorites)); } catch (e) { /* brak pamięci przeglądarki */ }
            }
            const modalEl = document.getElementById('favoritePlantModal');
            const modalInstance = window.bootstrap ? bootstrap.Modal.getInstance(modalEl) : null;
            if (modalInstance) modalInstance.hide();

            if (typeof window.refreshGlobalFavorites === "function") window.refreshGlobalFavorites();
            if (typeof sortResultsByFavorites === "function") sortResultsByFavorites();
        });
    }
});

// --- INTEGRACJA Z PLANT.ID ---
async function identifyPlantAPI(base64Image) {
    // usuwamy "data:image/jpeg;base64," z początku
    const cleanBase64 = base64Image.split(',')[1] || base64Image;

    const apiKey = "b9TobMZCwqPYHccRApN4feLLocZljMRsx5JfBMAEk6njbBUOR7";

    const response = await fetch("https://plant.id/api/v3/identification", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Api-Key": apiKey
        },
        body: JSON.stringify({
            "images": [cleanBase64],
            "latitude": 50.1,
            "longitude": 18.4,
            "similar_images": true
        })
    });

    const data = await response.json();

    if (data.result && data.result.classification && data.result.classification.suggestions.length > 0) {
        const bestMatch = data.result.classification.suggestions[0];
        console.log("Rozpoznano:", bestMatch.name, "Prawdopodobieństwo:", bestMatch.probability);
        return bestMatch.name;
    }
    return null;
}

function getBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
    });
}
