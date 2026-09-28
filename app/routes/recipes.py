# app/routes/recipes.py
from flask import Blueprint, render_template, request

from app.utils.helpers import get_all_recipes

recipes_bp = Blueprint('recipes', __name__)


def _text(value):
    """Splaszcza dowolna wartosc (napis / lista / slownik) do tekstu - do wyszukiwania."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_text(v) for v in value)
    return ""


def recipe_search_text(recipe):
    skladniki = [s.get('nazwa', '') if isinstance(s, dict) else str(s) for s in (recipe.get('skladniki') or [])]
    parts = [recipe.get('tytul', ''), recipe.get('roslina') or '', recipe.get('opis') or '', recipe.get('metoda') or '',
             " ".join(skladniki), _text(recipe.get('wlasciwosci', [])), _text(recipe.get('cechy', [])),
             _text(recipe.get('tagi', []))]
    return " ".join(parts).lower()


def is_from_web(recipe):
    """Przepis zebrany z internetu przez Siedzibe Kwiatownika (ma metadane Siedziby albo zrodla z adresami)."""
    if recipe.get('siedziba'):
        return True
    return any(isinstance(z, dict) and z.get('url') for z in (recipe.get('zrodla') or []))


def recipes_for_plant(plant_id, plant_name=None):
    """Przepisy, w ktorych wystepuje roslina: glowna roslina (slug/roslina) albo skladnik z link_id."""
    name = (plant_name or '').lower().strip()
    out = []
    for r in get_all_recipes():
        linked = any(isinstance(s, dict) and s.get('link_id') == plant_id for s in (r.get('skladniki') or []))
        main = r.get('slug') == plant_id or (name and (r.get('roslina') or '').lower().strip() == name)
        if linked or main:
            out.append(r)
    return out


@recipes_bp.route('/przepisy/', methods=['GET'])
def przepisy():
    query = request.args.get('q', '').lower().strip()
    all_recipes = get_all_recipes()
    for r in all_recipes:
        r['_z_sieci'] = is_from_web(r)
    results = [r for r in all_recipes if query in recipe_search_text(r)] if query else all_recipes
    web_count = sum(1 for r in all_recipes if r['_z_sieci'])
    return render_template('recipes.html', results=results, query=query, web_count=web_count,
                           book_count=len(all_recipes) - web_count)
