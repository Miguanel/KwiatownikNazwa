# app/utils/recipe_store.py
"""Magazyn przepisow: folder data/przepisy jako baza danych przepisow Kwiatownika.

Pliki maja nazwy <seria>_<RRRR-MM-DD>.json (np. siedziba_przepisy_2026-10-05.json; opcjonalnie z godzina
..._2026-10-05_1430.json). Kazdy plik serii to jej pelny stan, wiec wczytywany jest tylko NAJNOWSZY plik
z kazdej serii - starsze zostaja jako historia (mozna do nich wrocic, usuwajac nowszy plik).
Plik bez daty (np. przepisy_medyczne.json) to osobna seria; przegrywa z plikiem tej serii z data.
Przepis o tym samym "id" w kilku seriach (plikach) jest pokazywany raz (wygrywa seria wczesniejsza alfabetycznie,
czyli reczne pliki Kwiatownika przed eksportem Siedziby). Wynik jest buforowany do zmiany plikow.
Ta sama konwencja jest w Siedzibie: KwiatownikSiedziba/app/exporters/store.py.
"""
import json
import os
import re

SKIP = {'wzorzec_przepisu.json'}
DATED = re.compile(r'^(?P<series>.+?)_(?P<date>\d{4}-\d{2}-\d{2})(?:_(?P<time>\d{4,6}))?_?\.json$')

_cache = {'key': None, 'recipes': [], 'files': []}


def parse_name(name):
    """'siedziba_przepisy_2026-10-05.json' -> ('siedziba_przepisy', '2026-10-05'); bez daty -> (nazwa, '')."""
    m = DATED.match(name)
    if m:
        return m.group('series'), m.group('date') + ('_' + m.group('time') if m.group('time') else '')
    return (name[:-5] if name.endswith('.json') else name), ''


def store_files(folder):
    """Wszystkie pliki magazynu: [{name, series, date, used}] - used = wczytywany (najnowszy w serii)."""
    if not os.path.isdir(folder):
        return []
    names = sorted(f for f in os.listdir(folder) if f.endswith('.json') and f not in SKIP)
    best = {}
    for n in names:
        series, stamp = parse_name(n)
        if series not in best or stamp > best[series][0]:
            best[series] = (stamp, n)
    used = {n for _, n in best.values()}
    return [{'name': n, 'series': parse_name(n)[0], 'date': parse_name(n)[1], 'used': n in used,
             'size': os.path.getsize(os.path.join(folder, n))} for n in names]


def _read(path):
    with open(path, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)
    if isinstance(data, dict) and 'przepisy' in data:
        return data['przepisy']
    if isinstance(data, list):
        return data
    return [data]


def load_recipes(folder):
    """Przepisy z magazynu (kopie slownikow - mozna je bezpiecznie zmieniac)."""
    files = [f for f in store_files(folder) if f['used']]
    files.sort(key=lambda f: f['series'])
    key = tuple((f['name'], os.path.getmtime(os.path.join(folder, f['name'])), f['size']) for f in files)
    if key != _cache['key']:
        recipes, seen = [], set()
        for f in files:
            try:
                items = _read(os.path.join(folder, f['name']))
            except Exception:
                continue
            ids = set()
            for r in items:
                if not isinstance(r, dict):
                    continue
                rid = r.get('id')
                if rid and rid in seen:      # ten sam przepis w innej serii - zostaje pierwszy
                    continue
                if rid:
                    ids.add(rid)
                r.setdefault('_plik', f['name'])
                recipes.append(r)
            seen |= ids                      # w obrebie jednego pliku nic nie znika
        _cache.update(key=key, recipes=recipes, files=files)
    return [dict(r) for r in _cache['recipes']]
