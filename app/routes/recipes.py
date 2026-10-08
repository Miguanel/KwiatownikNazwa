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


def primary_source(recipe):
    """Pierwsze zrodlo przepisu z adresem: {'nazwa': domena/nazwa, 'url': adres, 'wiecej': ile jeszcze} albo None."""
    raw = recipe.get('zrodla')
    items = raw if isinstance(raw, list) else ([raw] if raw else [])
    if recipe.get('zrodlo'):
        items = items + [recipe['zrodlo']]
    found, books = [], []
    for z in items:
        if isinstance(z, dict):
            url, name = str(z.get('url') or '').strip(), z.get('nazwa')
        elif isinstance(z, str):
            url, name = z.strip(), None
        else:
            continue                                   # np. numery przypisow
        if url.lower().startswith(('http://', 'https://')):
            domain = url.split('//', 1)[1].split('/', 1)[0]
            domain = domain[4:] if domain.lower().startswith('www.') else domain
            found.append({'nazwa': name or domain, 'domena': domain, 'url': url})
        elif (name or url) and len(name or url) > 3:
            books.append({'nazwa': (name or url)[:90], 'domena': '', 'url': None})   # ksiazka / monografia
    allsrc = found + books
    if not allsrc:
        return None
    first = dict(allsrc[0])
    first['wiecej'] = len(allsrc) - 1
    return first


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


@recipes_bp.app_template_filter('kw_squash')
def kw_squash(html):
    """Usuwa wciecia z wyrenderowanego HTML (karty ~1300 przepisow: o ok. 40% mniej danych i wezlow DOM)."""
    import re
    from markupsafe import Markup
    return Markup(re.sub(r'\n\s+', '\n', str(html)))


def przepisnik_recipes():
    """Wszystkie przepisy Przepisnika z polami do wyswietlenia: _nr (numer pliku /api/przepis/<nr>.json),
    _z_sieci i _zrodlo. Kolejnosc = kolejnosc magazynu (get_all_recipes), wiec numery sa stale w jednej budowie."""
    out = []
    for nr, r in enumerate(get_all_recipes()):
        r['_nr'] = nr
        r['_z_sieci'] = is_from_web(r)
        r['_zrodlo'] = primary_source(r)
        out.append(r)
    return out


@recipes_bp.route('/przepisy/', methods=['GET'])
def przepisy():
    # Karty sa lekkie: bez pelnego JSON-a przepisu (dawniej 10 MB strony). Pelny przepis pobiera
    # static/js/recipes.js z /api/przepis/<nr>.json przy otwarciu grymuaru, a tekst do szukania z /api/przepisnik.json.
    query = request.args.get('q', '').lower().strip()
    all_recipes = przepisnik_recipes()
    results = [r for r in all_recipes if query in recipe_search_text(r)] if query else all_recipes
    web_count = sum(1 for r in all_recipes if r['_z_sieci'])
    return render_template('recipes.html', results=results, query=query, web_count=web_count,
                           book_count=len(all_recipes) - web_count)
