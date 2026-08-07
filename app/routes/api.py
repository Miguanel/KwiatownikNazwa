# app/routes/api.py
import re
from flask import Blueprint, jsonify
from app.utils.helpers import get_all_recipes, get_all_plants_list, get_plant_data

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/recipe_suggestions')
def recipe_suggestions():
    """Zwraca listę pojedynczych słów kluczowych (bez śmieci i spójników)"""
    all_recipes = get_all_recipes()
    keywords = set()

    STOP_WORDS = {
        'w', 'z', 'i', 'o', 'a', 'do', 'na', 'po', 'ze', 'za', 'się', 'lub', 'jak',
        'ml', 'g', 'kg', 'dag', 'lyz', 'łyż', 'łyżka', 'łyżeczka', 'szklanki', 'szklanka',
        'proporcja', 'ok', 'szt', 'sztuk', 'litr', 'gram', 'często', 'bardzo', 'jest'
    }

    def clean_and_split(text):
        if not text:
            return []
        text = re.sub(r'[^\w\s]', '', str(text)) # Upewniamy się, że to string
        words = text.lower().split()
        return [w for w in words if len(w) > 2 and not w.isdigit() and w not in STOP_WORDS]

    for r in all_recipes:
        # Analizujemy składniki (teraz odporne na słowniki)
        for skladnik in r.get('skladniki', []):
            if isinstance(skladnik, dict):
                keywords.update(clean_and_split(skladnik.get('nazwa', '')))
            else:
                keywords.update(clean_and_split(skladnik))

        # Analizujemy pozostałe rzeczy
        for prop in r.get('wlasciwosci', []):
            if isinstance(prop, str):
                keywords.update(clean_and_split(prop))

        for cecha in r.get('cechy', []):
            if isinstance(cecha, str):
                keywords.update(clean_and_split(cecha))

        keywords.update(clean_and_split(r.get('roslina', '')))
        keywords.update(clean_and_split(r.get('tytul', '')))

    return jsonify(sorted(list(keywords)))

@api_bp.route('/all_recipes.json')
def api_all_recipes():
    return jsonify(get_all_recipes())

@api_bp.route('/all_plants.json')
def api_all_plants():
    return jsonify([get_plant_data(pid) | {'slug': pid} for pid in get_all_plants_list() if get_plant_data(pid)])