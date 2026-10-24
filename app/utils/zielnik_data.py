# app/utils/zielnik_data.py
"""Dane dla Mojego zielnika (/zielnik/, static/js/zielnik.js) i lekkie dane Ksiegi Gildii.
Liczone przy budowie strony (freeze.py -> /api/zielnik.json, /api/gildie.json), bo strona jest statyczna.

Mój zielnik pokazuje dla kazdej rosliny, co mozna z nia zrobic: przepisy (wg kategorii), barwienie wlosow (Paleta),
barwienie tkanin (Farbiarnia), czesci rosliny do zbioru i kiedy, dobrych sasiadow (gildie), ostrzezenia i ochrone."""
import json
import os
import re
import unicodedata

from flask import current_app

from app.utils.helpers import get_all_plants_list, get_plant_data
from app.utils.home_data import plant_image, thumb, _calendar_tasks, _guilds, _latin
from app.utils.ochrona import ochrona

KATEGORIE = {'apteka': '⚕ Apteka', 'farbiarnia': '🎨 Farbiarnia', 'toaletka': '🌸 Toaletka', 'rzemioslo': '♨ Rzemiosło'}
CZESCI = {'liscie': 'liście', 'kwiaty': 'kwiaty', 'korzen': 'korzeń', 'klacze': 'kłącze', 'ziele': 'ziele', 'owoce': 'owoce',
          'nasiona': 'nasiona', 'kora': 'kora', 'paki': 'pąki', 'sok': 'sok', 'zywica': 'żywica', 'pylek': 'pyłek',
          'szyszki': 'szyszki', 'galazki': 'gałązki', 'pedy': 'pędy', 'igly': 'igły'}


def norm(text):
    t = unicodedata.normalize('NFKD', str(text or '').lower().replace('ł', 'l'))
    t = ''.join(c for c in t if not unicodedata.combining(c))
    return re.sub(r'[^a-z0-9]+', ' ', t).strip()


def kategoria(recipe):
    """Ta sama kategoria co stempel karty w Przepisniku (templates/recipes.html)."""
    typ = str(recipe.get('typ') or '')
    if 'medyczn' in typ:
        return 'apteka'
    if typ.startswith('barwiersk'):
        return 'farbiarnia'
    if typ.startswith('kosmetyczn'):
        return 'toaletka'
    return 'rzemioslo'


def _plants():
    out = []
    for pid in get_all_plants_list():
        p = get_plant_data(pid)
        if isinstance(p, dict):
            out.append((pid, p))
    return out


def dopasuj_nazwe(nazwa, plants):
    """Nazwa z gildii ("Malina", "Bez czarny (Sambucus nigra)") -> id rosliny Kwiatownika albo None."""
    if not nazwa:
        return None
    lat = re.search(r'\(([^)]+)\)', str(nazwa))
    base = norm(str(nazwa).split('(')[0])
    if not base:
        return None
    for pid, p in plants:
        if norm(p.get('nazwa_pl')) == base:
            return pid
    if lat:
        ln = norm(lat.group(1))
        for pid, p in plants:
            if norm(_latin(p)).startswith(ln):
                return pid
    for pid, p in plants:
        if norm(p.get('nazwa_pl')).startswith(base + ' '):
            return pid
    return None


def gildie_payload():
    """Tylko to, czego potrzebuje Ksiega Gildii (zamiast ~500 KB pelnych plikow roslin)."""
    out = []
    for pid, p in _plants():
        perm = p.get('permakultura') if isinstance(p.get('permakultura'), dict) else {}
        out.append({'slug': pid, 'nazwa_pl': p.get('nazwa_pl') or pid, 'nazwa_lat': _latin(p),
                    'permakultura': {'gildie': perm.get('gildie') or [], 'opis': perm.get('opis') or '',
                                     'funkcje': perm.get('funkcje') or []},
                    'gildie': p.get('gildie') or []})
    return out


def _static_json(name):
    path = os.path.join(current_app.static_folder, 'json', name)
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _krotko(text, n=220):
    text = re.sub(r'\s+', ' ', str(text or '')).strip()
    return text if len(text) <= n else text[:n - 1].rsplit(' ', 1)[0] + '…'


def zielnik_payload():
    from app.routes.recipes import is_lead
    from app.utils.helpers import get_all_recipes
    plants = _plants()
    ids = {pid for pid, _ in plants}
    by_name = {}
    for pid, p in plants:
        nm = str(p.get('nazwa_pl') or '').lower().strip()
        if nm:
            by_name.setdefault(nm, pid)

    # przepisy: tytul, kategoria, rosliny (jak recipes_for_plant: glowna roslina albo skladnik z link_id)
    przepisy, po_roslinie = [], {}
    for r in get_all_recipes():
        if is_lead(r) or not r.get('tytul'):
            continue
        hit = {s.get('link_id') for s in (r.get('skladniki') or []) if isinstance(s, dict) and s.get('link_id') in ids}
        if r.get('slug') in ids:
            hit.add(r['slug'])
        nm = str(r.get('roslina') or '').lower().strip()
        if nm and nm in by_name:
            hit.add(by_name[nm])
        if not hit:
            continue
        nr = len(przepisy)
        przepisy.append({'t': r['tytul'], 'k': kategoria(r), 'r': sorted(hit)})
        for pid in hit:
            po_roslinie.setdefault(pid, []).append(nr)

    paleta = {z.get('karta'): z.get('id') for z in (_static_json('paleta.json').get('ziola') or []) if z.get('karta')}
    farb = {}
    for z in (_static_json('farbiarnia.json').get('rosliny') or []):
        if z.get('karta'):
            farb[z['karta']] = z.get('id')

    rosliny = []
    for pid, p in plants:
        czesci = []
        cr = p.get('czesci_rosliny') if isinstance(p.get('czesci_rosliny'), dict) else {}
        for k, v in cr.items():
            if not isinstance(v, dict):
                continue
            czesci.append({'k': k, 'n': CZESCI.get(k, k.replace('_', ' ')), 'sur': v.get('nazwa_surowca') or '',
                           'czas': _krotko(v.get('czas_zbioru'), 120), 'dz': _krotko(v.get('wlasciwości') or v.get('wlasciwosci'), 160)})
        gil = []
        for g in _guilds(p)[:8]:
            gil.append({'n': g['nazwa'].split('(')[0].strip(), 'id': dopasuj_nazwe(g['nazwa'], plants), 'rola': _krotko(g['rola'], 120)})
        och = ochrona(pid)
        zast = p.get('zastosowanie') if isinstance(p.get('zastosowanie'), dict) else {}
        rosliny.append({
            'id': pid, 'n': p.get('nazwa_pl') or pid, 'lat': _latin(p), 'img': thumb(plant_image(p), 250),
            'cz': czesci,
            'kal': [{'c': t['czynnosc'], 'm': t['miesiace'], 'o': _krotko(t['opis'], 160)} for t in _calendar_tasks(p)],
            'gil': gil,
            'ostr': _krotko(p.get('ostrzezenia'), 260) if isinstance(p.get('ostrzezenia'), str) else '',
            'och': {'s': och['status'], 'n': och['nazwa'], 'p': och.get('porada') or ''} if och else None,
            'pal': paleta.get(pid), 'farb': farb.get(pid),
            'zast': {k: _krotko(v, 200) for k, v in zast.items() if isinstance(v, str) and k in ('kulinarne', 'ogrodowe', 'rzemieslnicze', 'kosmetyczne')},
            'prz': po_roslinie.get(pid, []),
        })
    rosliny.sort(key=lambda r: norm(r['n']))
    return {'wersja': 1, 'kategorie': KATEGORIE, 'rosliny': rosliny, 'przepisy': przepisy}
