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
    if(cameraInput) {
        cameraInput.addEventListener("change", async (event) => {
            const file = event.target.files[0];
            if (!file) return;

            // Zmiana UI na tryb ładowania
            const originalContent = magicBtn.innerHTML;
            magicBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analiza...';
            magicBtn.disabled = true;

            try {
                const base64Image = await getBase64(file);

                // Wywołanie JEDNEGO API (Plant.id)
                currentRecognizedPlant = await identifyPlantAPI(base64Image);

                if (currentRecognizedPlant) {
                    // Wpisanie do wyszukiwarki
                    if(searchInput) {
                        searchInput.value = currentRecognizedPlant;
                        searchInput.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                    // Pokazanie modalu sukcesu
                    showRecognizedModal(currentRecognizedPlant);
                }

            } catch (error) {
                console.error("Błąd rozpoznawania:", error);
                alert("Nie udało się rozpoznać rośliny. Spróbuj ponownie.");
            } finally {
                magicBtn.innerHTML = originalContent;
                magicBtn.disabled = false;
                // Ważne: czyścimy wartość, by aparat nie otworzył się ponownie przy błędzie
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