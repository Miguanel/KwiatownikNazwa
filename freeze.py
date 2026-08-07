import os
from flask_frozen import Freezer
from app import app
from app.utils.helpers import get_all_plants_list
# Konfiguracja: wygenerowane pliki trafią do folderu 'build'
app.config['FREEZER_DESTINATION'] = 'build'
freezer = Freezer(app)

# 1. Generowanie stron dla każdej rośliny
@freezer.register_generator
def plant_detail():
    plants = get_all_plants_list()
    for pid in plants:
        yield {'plant_id': pid}

# 2. Generowanie API bazy roślin dla JavaScriptu (Gildie)
@freezer.register_generator
def api_all_plants():
    yield {}

# 3. Generowanie API bazy przepisów dla JavaScriptu (Przepiśnik)
@freezer.register_generator
def api_all_recipes():
    yield {}

if __name__ == '__main__':
    print("Trwa zamrażanie Kwiatownika...")
    freezer.freeze()
    print("Sukces! Gotowa strona statyczna znajduje się w folderze 'build/'.")