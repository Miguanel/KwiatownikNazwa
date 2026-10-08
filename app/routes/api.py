# app/routes/api.py
import re
from flask import Blueprint, jsonify
from app.utils.helpers import get_all_recipes, get_all_plants_list, get_plant_data, get_recipe_store_files

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

@api_bp.route('/przepisy_pliki.json')
def api_recipe_store_files():
    """Pliki magazynu przepisow: ktore sa wczytywane (najnowsze w serii), a ktore sa tylko historia."""
    files = get_recipe_store_files()
    return jsonify({'pliki': files, 'wczytywane': [f['name'] for f in files if f['used']]})

def _json_utf8(data):
    import json
    from flask import Response
    return Response(json.dumps(data, ensure_ascii=False, separators=(',', ':')), mimetype='application/json')


@api_bp.route('/szukaj.json')
def api_szukaj():
    """Odchudzone dane wyszukiwarki strony glownej (app/utils/home_data.py) - pobierane w tle przez index.js:
    rosliny (z gotowym tekstem do szukania), kalendarz, przepisy bez pelnego tekstu."""
    from app.utils.home_data import search_payload_cached
    data = dict(search_payload_cached())
    data.pop('przepisy_tekst', None)
    return _json_utf8(data)


@api_bp.route('/szukaj_przepisy.json')
def api_szukaj_przepisy():
    """Pelny tekst przepisow do wyszukiwarki (lista w tej samej kolejnosci co "przepisy" w /api/szukaj.json)."""
    from app.utils.home_data import search_payload_cached
    return _json_utf8({'wersja': 1, 'teksty': search_payload_cached()['przepisy_tekst']})


_przepisnik = {'key': None, 'rows': []}


def _przepisnik_rows():
    """Przepisy Przepisnika (z numerami) - liczone raz na budowe strony, a nie dla kazdego z ~1300 plikow."""
    from app.routes.recipes import przepisnik_recipes
    from app.utils.recipe_store import store_files
    from app.utils.helpers import recipes_dir
    key = tuple((f['name'], f['size']) for f in store_files(recipes_dir()) if f['used'])
    if key != _przepisnik['key']:
        _przepisnik.update(key=key, rows=przepisnik_recipes())
    return _przepisnik['rows']


@api_bp.route('/przepis/<int:nr>.json')
def api_przepis(nr):
    """Pelny przepis do grymuaru w Przepisniku (static/js/recipes.js pobiera go przy otwarciu)."""
    from flask import abort
    rows = _przepisnik_rows()
    if not 0 <= nr < len(rows):
        abort(404)
    return _json_utf8(rows[nr])


@api_bp.route('/przepisnik.json')
def api_przepisnik():
    """Tekst do wyszukiwania w Przepisniku: lista w kolejnosci numerow przepisow (_nr). Male litery, kazde slowo
    raz, bez zrodel i adresow - pobierany, gdy ktos zacznie szukac."""
    from app.utils.home_data import search_text
    skip = {'zrodla', 'zrodlo', 'siedziba', '_z_sieci', '_zrodlo', '_nr', '_plik', 'url'}
    return _json_utf8({'wersja': 1, 'teksty': [search_text(r, skip=skip, normalize=False) for r in _przepisnik_rows()]})


@api_bp.route('/zrodla_podglad.json')
def api_zrodla_podglad():
    """Czy strony-zrodla przepisow dzialaja + ich podglad (tytul, opis, obrazek). Plik robi sprawdz_zrodla.py,
    czyta go static/js/zrodla_dymki.js (dymek po kliknieciu w zrodlo przepisu)."""
    import json, os
    from flask import current_app
    path = os.path.join(current_app.root_path, '..', 'data', 'zrodla_podglad.json')
    try:
        with open(path, encoding='utf-8') as f:
            return jsonify(json.load(f))
    except (OSError, ValueError):
        return jsonify({'zrodla': {}})

@api_bp.route('/all_plants.json')
def api_all_plants():
    return jsonify([get_plant_data(pid) | {'slug': pid} for pid in get_all_plants_list() if get_plant_data(pid)])


def _ciekawostki_tekst(v):
    return " ".join(str(v).split()) if isinstance(v, str) else ""


@api_bp.route('/ciekawostki.json')
def api_ciekawostki():
    """Wszystkie ciekawostki do paska na gorze strony (static/js/ciekawostki.js losuje je po kolei).
    Zrodla: pole "ciekawostki" plikow roslin, sekcja "ciekawostki" wiedzy z Siedziby, wiedza o swietach Kola Roku.
    Format: [{"t": tekst, "r": roslina/naglowek, "id": id rosliny lub null}]"""
    from data_builder import FESTIVAL_KNOWLEDGE
    out, seen = [], set()

    def add(text, label, pid=None):
        text = _ciekawostki_tekst(text)
        if len(text) < 20 or text in seen:
            return
        seen.add(text)
        out.append({'t': text, 'r': label, 'id': pid})

    for pid in get_all_plants_list():
        data = get_plant_data(pid)
        if not isinstance(data, dict):
            continue
        name = data.get('nazwa_pl') or pid
        for c in data.get('ciekawostki') or []:
            add(c, name, pid)
        wiedza = data.get('wiedza') if isinstance(data.get('wiedza'), dict) else {}
        for sekcja in wiedza.get('sekcje') or []:
            if isinstance(sekcja, dict) and 'ciekaw' in str(sekcja.get('klucz', '')):
                for punkt in sekcja.get('punkty') or []:
                    if isinstance(punkt, dict):
                        add(punkt.get('tekst'), name, pid)
    for swieto, items in FESTIVAL_KNOWLEDGE.items():
        for it in items or []:
            if isinstance(it, dict):
                add(it.get('tresc'), it.get('roslina') or swieto)
    return jsonify(out)
