# app/utils/seo.py
"""Dane dla wyszukiwarek: adres strony, tytuly, opisy i obrazy podgladu (Open Graph)."""
import os
import re

SITE_URL = os.getenv('SITE_URL', 'https://kwiatownik.onrender.com').rstrip('/')
SITE_NAME = 'Kwiatownik'
DESCRIPTION_LIMIT = 158  # Google pokazuje ok. 150-160 znakow opisu


def shorten(text, limit=DESCRIPTION_LIMIT):
    """Tekst bez HTML i nadmiarowych spacji, uciety na granicy slowa."""
    text = re.sub(r'<[^>]+>', ' ', str(text or ''))
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit - 1].rsplit(' ', 1)[0].rstrip(' ,;:-–(')
    return cut + '…'


def absolute_url(url):
    """Adres bezwzgledny (Open Graph wymaga pelnego adresu obrazka). Tylko http(s) i sciezki od /."""
    if not isinstance(url, str) or not url:
        return None
    if url.startswith(('https://', 'http://')):
        return url
    if url.startswith('/'):
        return SITE_URL + url
    return None


def _main_photo(plant):
    photos = plant.get('url')
    if isinstance(photos, str):
        return absolute_url(photos)
    if not isinstance(photos, dict) or not photos:
        return None
    for key, value in photos.items():
        if str(key).strip().lower() == 'pokrój':
            return absolute_url(value)
    return absolute_url(next(iter(photos.values())))


def plant_seo(plant, plant_id, has_recipes=None):
    """Tytul, opis i zdjecie strony rosliny do wynikow wyszukiwania i podgladu linku.
    has_recipes: czy roslina ma przepisy w magazynie data/przepisy (przepisy nie sa juz w pliku rosliny)."""
    name = plant.get('nazwa_pl') or plant_id.replace('_', ' ').capitalize()
    latin = plant.get('nazwa_lat')
    full_name = f'{name} ({latin})' if latin else name

    opis = shorten(plant.get('opis'), 400)
    zast = plant.get('zastosowanie') if isinstance(plant.get('zastosowanie'), dict) else {}
    extras = []
    if plant.get('czesci_rosliny'):
        extras.append('surowce')
    if zast.get('medyczne'):
        extras.append('działanie lecznicze')
    if has_recipes or (has_recipes is None and (plant.get('przepisy_medyczne') or plant.get('przepisy_kulinarne'))):
        extras.append('przepisy')
    if plant.get('ostrzezenia'):
        extras.append('przeciwwskazania')
    lead = f'{full_name}: '
    description = shorten(lead + opis, DESCRIPTION_LIMIT) if opis else \
        shorten(f'{full_name} w Kwiatowniku – opis, właściwości, zastosowanie i przepisy.')

    return {
        'title': f'{full_name} – właściwości, zastosowanie i przepisy',
        'description': description,
        'image': _main_photo(plant),
        'name': name,
        'latin': latin,
        'topics': extras,
    }
