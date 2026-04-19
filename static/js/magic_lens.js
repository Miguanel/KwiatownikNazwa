document.addEventListener("DOMContentLoaded", () => {
    const magicBtn = document.getElementById("magicLensBtn");
    const cameraInput = document.getElementById("magicCameraInput");
    const searchInput = document.getElementById("universalSearch") || document.getElementById("recipeSearch");
    const saveFavBtn = document.getElementById("saveFavoriteBtn");

    let currentRecognizedPlant = "";

    // 1. BEZPIECZNA AKTYWACJA APARATU
    if(magicBtn && cameraInput) {
        magicBtn.addEventListener("click", (e) => {
            e.preventDefault(); // Blokujemy domyślne akcje
            e.stopPropagation(); // Zapobiegamy "bąbelkowaniu" zdarzenia

            cameraInput.value = ""; // Czyścimy input przed otwarciem
            cameraInput.click();
        });
    }

    // 2. PRZECHWYCENIE ZDJĘCIA I ANALIZA
    // --- NOWA FUNKCJA: TŁUMACZ WIKIPEDII ---
    async function getPolishName(latinName) {
        try {
            // 1. Szukamy strony na łacińskiej (lub angielskiej) Wikipedii
            const searchUrl = `https://en.wikipedia.org/w/api.php?action=query&prop=langlinks&lllang=pl&titles=${encodeURIComponent(latinName)}&format=json&origin=*`;

            const response = await fetch(searchUrl);
            const data = await response.json();

            const pages = data.query.pages;
            const pageId = Object.keys(pages)[0];

            if (pageId !== "-1" && pages[pageId].langlinks) {
                // Pobieramy tytuł polskiej strony
                const polishTitle = pages[pageId].langlinks[0]['*'];
                console.log(`Znaleziono polską nazwę: ${polishTitle}`);
                return polishTitle;
            }

            // Jeśli nie znaleźliśmy w langlinks, spróbujmy uprościć nazwę (np. tylko pierwszy człon)
            return latinName;
        } catch (error) {
            console.error("Błąd tłumaczenia Wiki:", error);
            return latinName;
        }
    }

    // --- ZMODYFIKOWANA OBSŁUGA ZDJĘCIA ---
    if(cameraInput) {
        cameraInput.addEventListener("change", async (event) => {
            const file = event.target.files[0];
            if (!file) return;

            magicBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analiza...';
            magicBtn.disabled = true;

            try {
                const base64Image = await getBase64(file);

                // 1. Rozpoznajemy (dostajemy np. "Viola alba")
                const latinResult = await identifyPlantAPI(base64Image);

                if (latinResult) {
                    // 2. Tłumaczymy przez Wikipedię (dostajemy np. "Fiołek biały")
                    const polishResult = await getPolishName(latinResult);
                    currentRecognizedPlant = polishResult;

                    // 3. Wpisujemy do wyszukiwarki i pokazujemy modal
                    if(searchInput) {
                        searchInput.value = currentRecognizedPlant;
                        searchInput.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                    showRecognizedModal(currentRecognizedPlant);
                }

            } catch (error) {
                console.error("Błąd:", error);
                alert("Problem z rozpoznawaniem.");
            } finally {
                magicBtn.innerHTML = '<i class="bi bi-camera"></i> Rozpoznaj';
                magicBtn.disabled = false;
                cameraInput.value = "";
            }
        });
    }

    function showRecognizedModal(plantName) {
        const modalEl = document.getElementById('favoritePlantModal');
        if (modalEl) {
            document.getElementById("recognizedPlantName").textContent = plantName;
            const modalInstance = bootstrap.Modal.getOrCreateInstance(modalEl);
            modalInstance.show();
        }
    }

    // 3. ZAPIS DO ZIELNIKA
    if(saveFavBtn) {
        saveFavBtn.addEventListener("click", () => {
            if (!currentRecognizedPlant) return;

            let favorites = JSON.parse(localStorage.getItem("herbariumFavorites")) || [];
            if (!favorites.includes(currentRecognizedPlant)) {
                favorites.push(currentRecognizedPlant);
                localStorage.setItem("herbariumFavorites", JSON.stringify(favorites));
            }

            const modalEl = document.getElementById('favoritePlantModal');
            const modalInstance = bootstrap.Modal.getInstance(modalEl);
            if (modalInstance) modalInstance.hide();

            if(typeof window.refreshGlobalFavorites === "function") window.refreshGlobalFavorites();
            if(typeof sortResultsByFavorites === "function") sortResultsByFavorites();
        });
    }
});

// --- INTEGRACJA Z PLANT.ID (JEDNO API) ---

async function identifyPlantAPI(base64Image) {
    // USUŃ "data:image/jpeg;base64," z początku ciągu, jeśli istnieje
    const cleanBase64 = base64Image.split(',')[1] || base64Image;

    const apiKey = "b9TobMZCwqPYHccRApN4feLLocZljMRsx5JfBMAEk6njbBUOR7"; // Wpisz tutaj swój klucz

    const response = await fetch("https://plant.id/api/v3/identification", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Api-Key": apiKey
        },
        body: JSON.stringify({
            "images": [cleanBase64],
            "latitude": 50.1, // Możesz dodać współrzędne Czyżowic dla lepszej trafności
            "longitude": 18.4,
            "similar_images": true
        })
    });

    const data = await response.json();

    // Pobieramy pierwszą sugestię z najwyższym prawdopodobieństwem
    if (data.result && data.result.classification && data.result.classification.suggestions.length > 0) {
        const bestMatch = data.result.classification.suggestions[0];
        console.log("Rozpoznano:", bestMatch.name, "Prawdopodobieństwo:", bestMatch.probability);

        // Zwracamy nazwę (możesz użyć bestMatch.name dla łacińskiej lub spróbować mapować na polską)
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

