import os
from flask_frozen import Freezer

# Importujemy fabrykę aplikacji zamiast samej aplikacji
from app import create_app
from app.utils.helpers import get_all_plants_list

# 1. Inicjalizacja aplikacji i konfiguracja
app = create_app()
app.config['FREEZER_DESTINATION'] = 'build'
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

if __name__ == '__main__':
    print("Trwa zamrażanie Kwiatownika z nowej struktury...")
    freezer.freeze()
    print("Sukces! Gotowa strona statyczna znajduje się w folderze 'build/'.")