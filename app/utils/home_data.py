# app/utils/home_data.py
"""Lekkie dane strony glownej (szybkie ladowanie na telefonie).

Wczesniej index.html mial w srodku pelne pliki wszystkich roslin i wszystkie przepisy jako JSON (ok. 5 MB) -
telefon musial to pobrac i przetworzyc, zanim strona zaczela dzialac. Teraz:
  - Bestiariusz jest renderowany na serwerze (bestiary()) z miniaturami ladowanymi dopiero przy przewijaniu,
  - wyszukiwarka dostaje odchudzony plik /api/szukaj.json (search_payload()), pobierany w tle po wczytaniu strony
    albo od razu, gdy ktos zacznie pisac. Pelny tekst roslin i przepisow jest w nim juz znormalizowany
    (male litery, bez polskich znakow, kazde slowo raz), wiec przegladarka nie musi budowac indeksu.
"""
import re

from app.utils.helpers import get_all_plants_list, get_plant_data, get_all_recipes

ACCENTS = str.maketrans('ąćęłńóśźż', 'acelnoszz')
POLISH_ORDER = 'aąbcćdeęfghijklłmnńoópqrsśtuvwxyzźż'
RECIPE_SKIP = {'id', 'slug', 'zrodla', 'url', 'zdjecie', 'zdjecie_url'}
WIKI_THUMB = re.compile(r'^(https://upload\.wikimedia\.org/.+/thumb/.+/)(\d+)px-([^/]+)$')
WORD = re.compile(r'[^\W_]+')


def norm(text):
    """Jak norm() w static/js/index.js: male litery, bez polskich znakow."""
    return str(text if text is not None else '').lower().translate(ACCENTS)


def flatten(value, skip=None, out=None, depth=0):
    """Splaszcza dowolny JSON do listy tekstow (jak flatten() w index.js)."""
    out = [] if out is None else out
    if value is None or depth > 7:
        return out
    if isinstance(value, bool):          # jak w JS: wartosci true/false nie trafiaja do tekstu
        return out
    if isinstance(value, (str, int, float)):
        out.append(str(value))
    elif isinstance(value, list):
        for v in value:
            flatten(v, skip, out, depth + 1)
    elif isinstance(value, dict):
        for k, v in value.items():
            if skip and k in skip:
                continue
            flatten(v, skip, out, depth + 1)
    return out


URL = re.compile(r'https?://\S+')


def search_text(*values, skip=None, normalize=True):
    """Znormalizowany tekst do wyszukiwania: kazde slowo raz, bez slow zawartych w dluzszych (index.js szuka
    fragmentu slowa przez includes(), wiec wynik wyszukiwania jest taki sam jak na pelnym tekscie)."""
    text = URL.sub(' ', ' '.join(flatten(list(values), skip)))
    text = norm(text) if normalize else text.lower()
    words = sorted(set(WORD.findall(text)), key=lambda w: (-len(w), w))
    kept, joined = [], ' '
    for w in words:
        if w not in joined:
            kept.append(w)
            joined += w + ' '
    return ' '.join(kept)


def polish_key(text):
    return [POLISH_ORDER.find(c) if c in POLISH_ORDER else 100 + ord(c) for c in str(text or '').lower()]


def thumb(url, width=330):
    """Miniatura z Wikimedia Commons w podanej szerokosci (Wikimedia ma gotowe rozmiary: 120, 250, 330, 500, 960)."""
    if not isinstance(url, str):
        return ''
    m = WIKI_THUMB.match(url)
    if m and int(m.group(2)) > width:
        return f'{m.group(1)}{width}px-{m.group(3)}'
    return url


def plant_image(plant):
    """Pierwsze zdjecie rosliny (jak getBestImageUrl() w index.js)."""
    if not isinstance(plant, dict):
        return ''
    url = plant.get('url')
    if isinstance(url, dict):
        for v in url.values():
            return v if isinstance(v, str) else ''
        return ''
    for k in ('zdjecie_url', 'zdjecie', 'image'):
        if isinstance(plant.get(k), str) and plant[k]:
            return plant[k]
    return url if isinstance(url, str) else ''


def _latin(p):
    return p.get('nazwa_lat') or p.get('nazwa_lacinska') or p.get('lacina') or ''


def _plants():
    out = []
    for pid in get_all_plants_list():
        p = get_plant_data(pid)
        if not isinstance(p, dict):
            continue
        p = dict(p)
        p['nazwa_pl'] = p.get('nazwa_pl') or p.get('gatunek') or 'Nieznana roślina'
        p['id'] = p.get('id') or p.get('slug') or pid
        out.append(p)
    return out


def bestiary(plants=None):
    """Karty Bestiariusza (alfabetycznie po polsku): id, nazwa, lacina, rodzina, miniatura (330 i 500 px)."""
    rows = []
    for p in plants if plants is not None else _plants():
        img = plant_image(p)
        small, big = thumb(img, 330), thumb(img, 500)
        rows.append({'id': p['id'], 'nazwa': p['nazwa_pl'], 'lat': _latin(p), 'rodzina': p.get('rodzina') or '',
                     'img': small, 'img2x': big if big != small else '', 'full': img if img != small else ''})
    rows.sort(key=lambda r: polish_key(r['nazwa']))
    return rows


def _js_join(items):
    """Jak Array.join(', ') w JS (zagniezdzone listy splaszczone, obiekty jako '[object Object]')."""
    out = []
    for x in items:
        if isinstance(x, list):
            out.append(_js_join(x).replace(', ', ','))
        elif isinstance(x, dict):
            out.append('[object Object]')
        elif x is None:
            out.append('')
        elif isinstance(x, bool):
            out.append('true' if x else 'false')
        else:
            out.append(str(x))
    return ', '.join(out)


def _symptom_parts(value):
    """Fragmenty tekstu "dzialania" (jak addSymptom() w index.js): podzial po , ; . : ( ), 3-60 znakow."""
    if not value:
        return []
    if isinstance(value, list):
        content = _js_join(value)
    elif isinstance(value, dict):
        content = ', '.join(flatten(value))
    else:
        content = str(value)
    out = []
    for part in re.split(r'[,;.:()]', content):
        tag = part.strip().lower()
        if 3 <= len(tag) <= 60:
            out.append(tag)
    return out


def _calendar_tasks(p):
    kal = p.get('kalendarz_ogrodnika') if isinstance(p.get('kalendarz_ogrodnika'), dict) else {}
    out = []
    for z in kal.get('zadania') or []:
        if isinstance(z, dict) and z.get('czynnosc'):
            out.append({'czynnosc': z.get('czynnosc'), 'opis': z.get('opis') or '',
                        'miesiace': [m for m in z.get('miesiace') or [] if isinstance(m, int)]})
    return out


def _guilds(p):
    raw = (p.get('permakultura') or {}).get('gildie') if isinstance(p.get('permakultura'), dict) else None
    raw = raw or p.get('gildie') or []
    out = []
    for g in raw if isinstance(raw, list) else []:
        if isinstance(g, str):
            out.append({'nazwa': g, 'rola': 'Powiązanie'})
        elif isinstance(g, dict):
            out.append({'nazwa': g.get('nazwa') or g.get('name') or 'Nieznany gość', 'rola': g.get('rola') or 'Powiązanie'})
    return out


def _short(text, n):
    t = ' '.join(str(text or '').split())
    return t if len(t) <= n else t[:n - 1].rstrip() + '…'


def _ingredients(r):
    s = r.get('skladniki')
    if isinstance(s, list):
        names = [(x.get('nazwa') or x.get('skladnik') or '') if isinstance(x, dict) else str(x) for x in s]
    elif isinstance(s, dict):
        names = list(s.keys())
    else:
        names = [str(s)] if s else []
    return [n for n in names if n][:2]


def _prep_text(r):
    p = r.get('sposob_przygotowania')
    if isinstance(p, (list, dict)):
        return ' '.join(flatten(p))
    return str(p or '')


def search_payload():
    """Dane wyszukiwarki strony glownej (/api/szukaj.json)."""
    from data_builder import build_calendar_from_jsons
    from app.routes.recipes import is_from_web

    plants = _plants()
    by_name = {norm(p['nazwa_pl']).strip(): p for p in plants}
    symptoms = {p['id']: [] for p in plants}

    recipes = []
    for r in get_all_recipes():
        if not isinstance(r, dict) or not r.get('tytul'):
            continue
        plant = by_name.get(norm(r.get('roslina')).strip()) if r.get('roslina') else None
        if plant:
            for k in ('zastosowanie', 'cechy', 'wlasciwosci', 'efekty', 'tagi'):
                symptoms[plant['id']] += _symptom_parts(r.get(k))
        recipes.append({
            'tytul': r['tytul'], 'roslina': r.get('roslina') or '',
            'opis': _short(r.get('opis') or _prep_text(r), 160),
            'sk': _ingredients(r), 'w': 1 if is_from_web(r) else 0,
            's': search_text(r, skip=RECIPE_SKIP),
        })

    rows = []
    for p in plants:
        zast = p.get('zastosowanie') if isinstance(p.get('zastosowanie'), dict) else {}
        own = _symptom_parts(zast.get('medyczne'))
        czesci = p.get('czesci_rosliny') if isinstance(p.get('czesci_rosliny'), dict) else {}
        for c in czesci.values():
            if isinstance(c, dict):
                own += _symptom_parts(c.get('wlasciwosci') or c.get('wlasciwości'))
        dz = list(dict.fromkeys(symptoms[p['id']] + own))
        ciek = [c if isinstance(c, str) else ' – '.join(flatten(c)) for c in (p.get('ciekawostki') or [])
                if c][:8] if isinstance(p.get('ciekawostki'), list) else []
        rows.append({
            'id': p['id'], 'nazwa_pl': p['nazwa_pl'], 'nazwa_lat': _latin(p), 'rodzina': p.get('rodzina') or '',
            'tagi': [t for t in p.get('tagi') or [] if isinstance(t, str)] if isinstance(p.get('tagi'), list) else [],
            'opis': p.get('opis') if isinstance(p.get('opis'), str) else ' '.join(flatten(p.get('opis'))),
            'ciekawostki': [_short(c, 400) for c in ciek],
            'img': thumb(plant_image(p), 330),
            'zadania': _calendar_tasks(p), 'gildie': _guilds(p), 'dz': dz,
            's': search_text(p.get('nazwa_pl'), _latin(p), p.get('rodzina'), p.get('opis'), p.get('tagi'),
                             p.get('zastosowanie'), p.get('czesci_rosliny'), p.get('ciekawostki'),
                             p.get('identyfikacja'), p.get('profil_energetyczny'), p.get('ostrzezenia'),
                             p.get('wymagania')),
        })
    # pelny tekst przepisow (najwieksza czesc danych) idzie osobnym plikiem: wyszukiwarka dziala od razu
    # po tytulach, roslinach i skladnikach, a pelnotekstowe trafienia dochodza chwile pozniej
    teksty = [r.pop('s') for r in recipes]
    return {'wersja': 1, 'rosliny': rows, 'przepisy': recipes, 'kalendarz': build_calendar_from_jsons(),
            'przepisy_tekst': teksty}


_cache = {'t': 0.0, 'data': None}


def search_payload_cached(max_age=30):
    """Ten sam wynik dla obu plikow wyszukiwarki podczas jednej budowy strony (freeze)."""
    import time
    if _cache['data'] is None or time.time() - _cache['t'] > max_age:
        _cache.update(t=time.time(), data=search_payload())
    return _cache['data']
