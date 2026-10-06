# app/utils/helpers.py
import os
import json
import re
from flask import current_app
from app.utils.legacy import legacy_as_plant, legacy_only_ids
from app.utils.recipe_store import load_recipes, store_files


def plants_dir():
    return os.path.join(current_app.root_path, '..', 'data', 'plants')

def normalize_slug(text):
    accents = {'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z'}
    text = text.lower().replace(" ", "_")
    for char, replacement in accents.items():
        text = text.replace(char, replacement)
    return text

def get_plant_data(pid):
    slug = normalize_slug(pid)
    # Korzystamy z root_path aplikacji, aby zawsze trafiać w dobry folder
    path = os.path.join(current_app.root_path, '..', 'data', 'plants', f'{slug}.json')

    if not os.path.exists(path) or os.path.getsize(path) == 0:
        # roslina tylko w archiwum pierwszego Kwiatownika (data/plants/<kategoria>/)
        return legacy_as_plant(plants_dir(), slug)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None

def get_all_plants_list():
    folder = os.path.join(current_app.root_path, '..', 'data', 'plants')
    if not os.path.exists(folder):
        return []
    ids = [f.replace('.json', '') for f in os.listdir(folder) if f.endswith('.json')]
    return ids + [pid for pid in legacy_only_ids(folder) if pid not in ids]

def recipes_dir():
    return os.path.join(current_app.root_path, '..', 'data', 'przepisy')

def get_all_recipes():
    """Przepisy z magazynu data/przepisy: najnowszy plik z kazdej serii <seria>_<data>.json (app/utils/recipe_store.py)."""
    return load_recipes(recipes_dir())

def get_recipe_store_files():
    return store_files(recipes_dir())

def get_all_therapeutic_keywords():
    all_plants_ids = get_all_plants_list()
    keywords = set()
    for pid in all_plants_ids:
        data = get_plant_data(pid)
        if not data or not isinstance(data, dict):
            continue
        try:
            # czesci reczne + czesci z sieci (Siedziba Kwiatownika), z wiedza wmontowana w ich dzialanie
            from app.utils.merged import czesci_generatora
            for czesc in czesci_generatora(data).values():
                wlasciwosci = czesc.get('props') or ''
                words = [w.strip().lower() for w in wlasciwosci.replace(',', ' ').replace('.', ' ').split()]
                keywords.update(words)
            zastosowanie = data.get('zastosowanie', {})
            if isinstance(zastosowanie, dict):
                medyczne = zastosowanie.get('medyczne', '')
                if isinstance(medyczne, str):
                    med_words = [w.strip().lower() for w in medyczne.replace(',', ' ').replace('.', ' ').split()]
                    keywords.update(med_words)
        except Exception:
            continue
    return sorted([word for word in keywords if len(word) > 3])