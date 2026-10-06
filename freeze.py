import os
from flask_frozen import Freezer

# Importujemy fabrykę aplikacji zamiast samej aplikacji
from app import create_app
from app.utils.helpers import get_all_plants_list

# 1. Inicjalizacja aplikacji i konfiguracja
app = create_app()
# Frozen-Flask liczy wzgledna sciezke od app.root_path (= folder pakietu app/), wiec bez pelnej sciezki
# strona trafialaby do app/build, a Render publikuje build/ z katalogu glownego repozytorium.
app.config['FREEZER_DESTINATION'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build')
freezer = Freezer(app)

# 2. Generowanie stron dla każdej rośliny
@freezer.register_generator
def generate_plant_details():
    # Ponieważ nasza funkcja get_all_plants_list() używa teraz current_app.root_path,
    # musimy wywołać ją wewnątrz "kontekstu aplikacji".
    with app.app_context():
        plants = get_all_plants_list()
        for pid in plants:
            # Zwracamy tuple: (nazwa_endpointu_z_blueprintem, parametry)
            yield 'plants.plant_detail', {'plant_id': pid}

# 3. Generowanie API bazy roślin dla JavaScriptu (Gildie)
@freezer.register_generator
def generate_api_all_plants():
    # Endpoint z blueprintu "api"
    yield 'api.api_all_plants', {}

# 4. Generowanie API bazy przepisów dla JavaScriptu (Przepiśnik)
@freezer.register_generator
def generate_api_all_recipes():
    # Endpoint z blueprintu "api"
    yield 'api.api_all_recipes', {}

# 5. Ciekawostki do paska na górze strony (static/js/ciekawostki.js)
@freezer.register_generator
def generate_api_ciekawostki():
    yield 'api.api_ciekawostki', {}

if __name__ == '__main__':
    print("Trwa zamrażanie Kwiatownika z nowej struktury...")
    freezer.freeze()
    print("Sukces! Gotowa strona statyczna znajduje się w folderze 'build/'.")