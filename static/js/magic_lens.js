document.addEventListener("DOMContentLoaded", () => {
    const magicBtn = document.getElementById("magicLensBtn");
    const cameraInput = document.getElementById("magicCameraInput");

    // Nie inicjalizuj modalu globalnie na starcie, zrób to w funkcji
    let favModal = null;

    if(magicBtn && cameraInput) {
        magicBtn.addEventListener("click", () => {
            cameraInput.click();
        });
    }

    // Funkcja pomocnicza do bezpiecznego otwierania modalu
    function showRecognizedModal(plantName) {
        const modalEl = document.getElementById('favoritePlantModal');
        if (modalEl) {
            const modalInstance = bootstrap.Modal.getOrCreateInstance(modalEl);
            document.getElementById("recognizedPlantName").textContent = plantName;
            modalInstance.show(); // Użyj lokalnej instancji
        }
    }
    const searchInput = document.getElementById("universalSearch") || document.getElementById("recipeSearch");
//    const favModal = new bootstrap.Modal(document.getElementById('favoritePlantModal'));
    const recognizedNameDisplay = document.getElementById("recognizedPlantName");
    const saveFavBtn = document.getElementById("saveFavoriteBtn");

    let currentRecognizedPlant = "";

    // 1. Aktywacja aparatu
    if(magicBtn && cameraInput) {
        magicBtn.addEventListener("click", () => {
            cameraInput.click();
        });
    }

    // 2. Przechwycenie zdjęcia
    if(cameraInput) {
        cameraInput.addEventListener("change", async (event) => {
            const file = event.target.files[0];
            if (!file) return;

            // Zmień ikonę na ładowanie
            magicBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analiza...';
            magicBtn.disabled = true;

            try {
                // Konwersja do Base64 (wymagane przez większość API)
                const base64Image = await getBase64(file);

                // 3. Równoległe uderzenie do API (Ważenie wyników)
                currentRecognizedPlant = await analyzePlantWithMultipleAPIs(base64Image);

                // 4. Sukces - wstawienie do wyszukiwarki i pokazanie Modala
                if(searchInput) {
                    searchInput.value = currentRecognizedPlant;
                    // Wyzwolenie eventu input, by wyszukiwarka zaktualizowała wyniki
                    searchInput.dispatchEvent(new Event('input', { bubbles: true }));
                }

                recognizedNameDisplay.textContent = currentRecognizedPlant;
                favModal.show();

            } catch (error) {
                console.error("Błąd rozpoznawania:", error);
                alert("Nie udało się rozpoznać rośliny. Spróbuj ponownie z wyraźniejszym zdjęciem.");
            } finally {
                magicBtn.innerHTML = '<i class="bi bi-camera"></i> Rozpoznaj';
                magicBtn.disabled = false;
                cameraInput.value = ""; // Reset inputu
            }
        });
    }

    // 5. Zapis do LocalStorage
    if(saveFavBtn) {
        saveFavBtn.addEventListener("click", () => {
            let favorites = JSON.parse(localStorage.getItem("herbariumFavorites")) || [];

            // Unikamy duplikatów
            if (!favorites.includes(currentRecognizedPlant)) {
                favorites.push(currentRecognizedPlant);
                localStorage.setItem("herbariumFavorites", JSON.stringify(favorites));
            }

            favModal.hide();
            // Opcjonalnie: wywołaj funkcję odświeżającą wyniki z nowym sortowaniem
            if(typeof sortResultsByFavorites === "function") {
                sortResultsByFavorites();
            }
        });
    }
});

// --- FUNKCJE POMOCNICZE ---

function getBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
    });
}

async function analyzePlantWithMultipleAPIs(base64Image) {
    // UWAGA: W środowisku produkcyjnym klucze API nie powinny być na froncie!
    // Poniżej znajduje się architektura zapytań równoległych (Promise.all).

    // Zastąp to swoimi rzeczywistymi kluczami i endpointami
    const api1_Promise = mockApiCall("API_1", base64Image, { "Mniszek lekarski": 0.8, "Mlecz": 0.2 }); // Symulacja Plant.id
    const api2_Promise = mockApiCall("API_2", base64Image, { "Mniszek lekarski": 0.9, "Podbiał": 0.1 }); // Symulacja Pl@ntNet

    // Odpalamy zapytania w tym samym czasie
    const [resultsApi1, resultsApi2] = await Promise.all([api1_Promise, api2_Promise]);

    // Algorytm wagowy: API_2 jest dokładniejsze, dajemy mu wagę 1.5, API_1 wagę 1.0
    let combinedScores = {};

    function addScores(apiResults, weight) {
        for (let [plant, score] of Object.entries(apiResults)) {
            if (!combinedScores[plant]) combinedScores[plant] = 0;
            combinedScores[plant] += (score * weight);
        }
    }

    addScores(resultsApi1, 1.0);
    addScores(resultsApi2, 1.5);

    // Szukamy najwyższego połączonego wyniku
    let bestMatch = "";
    let highestScore = 0;

    for (let [plant, score] of Object.entries(combinedScores)) {
        if (score > highestScore) {
            highestScore = score;
            bestMatch = plant;
        }
    }

    return bestMatch;
}

// Symulacja działania API (Do usunięcia przy wdrażaniu prawdziwych Fetch)
function mockApiCall(apiName, image, simulatedResponse) {
    return new Promise((resolve) => {
        setTimeout(() => {
            console.log(`[${apiName}] Zwrócono wyniki.`);
            resolve(simulatedResponse);
        }, 1500); // Symulacja 1.5 sekundy opóźnienia sieciowego
    });
}