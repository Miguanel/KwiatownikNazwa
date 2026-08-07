# app/utils/helpers.py
import os
import json
import re
from flask import current_app

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
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None

def get_all_plants_list():
    folder = os.path.join(current_app.root_path, '..', 'data', 'plants')
    if not os.path.exists(folder):
        return []
    return [f.replace('.json', '') for f in os.listdir(folder) if f.endswith('.json')]

def get_all_recipes():
    all_recipes = []
    recipes_dir = os.path.join(current_app.root_path, '..', 'data', 'przepisy')
    if os.path.exists(recipes_dir):
        for filename in os.listdir(recipes_dir):
            if filename.endswith('.json') and filename != 'wzorzec_przepisu.json':
                file_path = os.path.join(recipes_dir, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, dict) and "przepisy" in data:
                            all_recipes.extend(data["przepisy"])
                        elif isinstance(data, list):
                            all_recipes.extend(data)
                        else:
                            all_recipes.append(data)
                except Exception:
                    pass
    return all_recipes

def get_all_therapeutic_keywords():
    all_plants_ids = get_all_plants_list()
    keywords = set()
    for pid in all_plants_ids:
        data = get_plant_data(pid)
        if not data or not isinstance(data, dict):
            continue
        try:
            czesci = data.get('czesci_rosliny', {})
            if isinstance(czesci, dict):
                for czesc in czesci.values():
                    if isinstance(czesc, dict):
                        wlasciwosci = czesc.get('wlasciwości', '')
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