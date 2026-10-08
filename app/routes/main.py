# app/routes/main.py
import json
import random
import os
from datetime import date
from xml.sax.saxutils import escape
from flask import Blueprint, render_template, current_app, send_from_directory, url_for, Response
from astro_engine import get_astrological_data
from data_builder import FESTIVAL_KNOWLEDGE
from app.utils.helpers import get_all_plants_list, get_plant_data, get_all_recipes
from app.utils.kronika import kronika

main_bp = Blueprint('main', __name__)


# Plik weryfikacyjny Google Search Console - Google szuka go w KATALOGU GLOWNYM domeny
# (kwiatownik.onrender.com/google3d44376f166bf895.html), a pliki z static/ trafiaja pod /static/.
# Trasa bez parametrow -> Frozen-Flask (freeze.py) sam zapisze go do build/google3d44376f166bf895.html.
@main_bp.route('/google3d44376f166bf895.html')
def google_site_verification():
    return send_from_directory(current_app.static_folder, 'google3d44376f166bf895.html', mimetype='text/html')


# ---------------------------------------------------------------------------
# SEO: mapa witryny (sitemap.xml) i robots.txt
# Obie trasy sa bez parametrow, wiec freeze.py zapisze je do build/sitemap.xml i build/robots.txt,
# a Render opublikuje je pod https://kwiatownik.onrender.com/sitemap.xml i /robots.txt.
# Adres strony mozna zmienic zmienna srodowiskowa SITE_URL (np. po podpieciu wlasnej domeny).
# ---------------------------------------------------------------------------
from app.utils.seo import SITE_URL  # noqa: E402 - adres strony wspolny dla mapy, robots.txt i znacznikow SEO


@main_bp.app_context_processor
def inject_seo():
    """site_url i canonical_url dostepne w kazdym szablonie (link kanoniczny, Open Graph)."""
    from flask import request
    return {'site_url': SITE_URL, 'canonical_url': SITE_URL + request.path}


@main_bp.route('/favicon.ico')
def favicon():
    # Google i przegladarki pytaja o /favicon.ico w katalogu glownym
    return send_from_directory(current_app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@main_bp.route('/site.webmanifest')
def webmanifest():
    import json as _json
    data = {
        'name': 'Kwiatownik – Cyfrowy Zielnik', 'short_name': 'Kwiatownik', 'lang': 'pl', 'start_url': '/',
        'display': 'standalone', 'background_color': '#f4f1ea', 'theme_color': '#3e4a3d',
        'icons': [{'src': url_for('static', filename='img/icon-192.png'), 'sizes': '192x192', 'type': 'image/png'},
                  {'src': url_for('static', filename='img/icon-512.png'), 'sizes': '512x512', 'type': 'image/png'}],
    }
    return Response(_json.dumps(data, ensure_ascii=False, indent=2), mimetype='application/manifest+json')

# Strony stale (bez logowania/rejestracji i plikow API - tych nie indeksujemy)
SITEMAP_STATIC_PAGES = [
    ('main.index', 'daily', '1.0'),
    ('recipes.przepisy', 'weekly', '0.8'),
    ('plants.porownaj', 'weekly', '0.6'),
    ('plants.szukaj_terapeutyczna', 'monthly', '0.5'),
    ('plants.gildie', 'monthly', '0.5'),
    ('plants.generator', 'monthly', '0.5'),
]


def _plant_lastmod(data):
    """Data ostatniej aktualizacji wiedzy z Siedziby (RRRR-MM-DD) albo None."""
    wiedza = data.get('wiedza') if isinstance(data, dict) else None
    value = wiedza.get('zaktualizowano') if isinstance(wiedza, dict) else None
    if isinstance(value, str) and len(value) >= 10:
        try:
            return date.fromisoformat(value[:10]).isoformat()
        except ValueError:
            return None
    return None


@main_bp.route('/sitemap.xml')
def sitemap():
    entries = []
    for endpoint, changefreq, priority in SITEMAP_STATIC_PAGES:
        try:
            entries.append((url_for(endpoint), None, changefreq, priority))
        except Exception:
            pass  # endpoint nie istnieje (np. po zmianie nazwy) - pomijamy zamiast psuc cala mape

    for pid in sorted(get_all_plants_list()):
        data = get_plant_data(pid)
        if not data:
            continue
        entries.append((url_for('plants.plant_detail', plant_id=pid), _plant_lastmod(data), 'monthly', '0.7'))

    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for path, lastmod, changefreq, priority in entries:
        lines.append('  <url>')
        lines.append(f'    <loc>{escape(SITE_URL + path)}</loc>')
        if lastmod:
            lines.append(f'    <lastmod>{lastmod}</lastmod>')
        lines.append(f'    <changefreq>{changefreq}</changefreq>')
        lines.append(f'    <priority>{priority}</priority>')
        lines.append('  </url>')
    lines.append('</urlset>')
    return Response('\n'.join(lines) + '\n', mimetype='application/xml')


@main_bp.route('/robots.txt')
def robots_txt():
    body = ('User-agent: *\n'
            'Allow: /\n'
            'Disallow: /login/\n'
            'Disallow: /register/\n'
            'Disallow: /logout/\n'
            'Disallow: /api/\n'
            '\n'
            f'Sitemap: {SITE_URL}/sitemap.xml\n')
    return Response(body, mimetype='text/plain')


@main_bp.route('/')
def index():
    # Strona glowna jest lekka: Bestiariusz renderowany tutaj (z miniaturami), a dane wyszukiwarki przegladarka
    # pobiera w tle z /api/szukaj.json (app/utils/home_data.py). Wczesniej w HTML bylo ok. 5 MB JSON-a.
    from app.utils.home_data import bestiary
    from app.utils.kronika import stan_siedziby
    lat, lon = '49.95', '18.38'
    city_name = "Z (Domyślnie)"

    try:
        import requests
        ip_resp = requests.get('http://ip-api.com/json/', timeout=2).json()
        if ip_resp and ip_resp.get('status') == 'success':
            lat = str(ip_resp.get('lat'))
            lon = str(ip_resp.get('lon'))
            city_name = ip_resp.get('city', 'Nieznana okolica')
    except Exception:
        pass

    astro = get_astrological_data(lat=lat, lon=lon)
    astro['location'] = city_name
    current_fest = astro.get('festival', 'Zwyczajny Czas')

    fest_pool = FESTIVAL_KNOWLEDGE.get(current_fest, [])
    general_pool = FESTIVAL_KNOWLEDGE.get("GENERAL", [])
    full_knowledge_pool = fest_pool + general_pool

    if full_knowledge_pool:
        knowledge = random.sample(full_knowledge_pool, min(len(full_knowledge_pool), 10))
    else:
        knowledge = [{"roslina": "Kwiatownik", "tresc": "Wiedza o roślinach jest kluczem do zdrowia."}]

    rows = bestiary()
    return render_template(
        'index.html',
        plants=rows,
        bestiary=rows,
        astro=astro,
        knowledge=knowledge,
        kronika=kronika(12),
        stan=stan_siedziby(),
    )
