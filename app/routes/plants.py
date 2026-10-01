# app/routes/plants.py
from flask import Blueprint, render_template, abort, request, flash, redirect, url_for
from flask_login import current_user
from app.models import Comment
from app.extensions import db
from app.utils.helpers import get_plant_data, get_all_plants_list, get_all_therapeutic_keywords, plants_dir
from app.utils.legacy import get_legacy_plant
from app.utils.merged import czesci_generatora, ostrzezenia_generatora
from app.routes.recipes import recipes_for_plant, is_from_web
from astro_engine import get_astrological_data

plants_bp = Blueprint('plants', __name__)


@plants_bp.route('/plant/<plant_id>/')
def plant_detail(plant_id):
    plant_data = get_plant_data(plant_id)
    if not plant_data:
        abort(404)

    if current_user.is_authenticated:
        comments = Comment.query.filter(
            (Comment.plant_id == plant_id) &
            ((Comment.is_private == False) | (Comment.user_id == current_user.id))
        ).order_by(Comment.date_posted.desc()).all()
    else:
        comments = Comment.query.filter_by(plant_id=plant_id, is_private=False).order_by(
            Comment.date_posted.desc()).all()

    plant_recipes = recipes_for_plant(plant_id, plant_data.get('nazwa_pl'))
    for r in plant_recipes:
        r['_z_sieci'] = is_from_web(r)

    legacy = get_legacy_plant(plants_dir(), plant_id)
    return render_template('plant_detail.html', plant=plant_data, plant_id=plant_id, comments=comments,
                           plant_recipes=plant_recipes, legacy=legacy)


def _compare_row(data, legacy, recipes):
    """Najwazniejsze cechy rosliny do porownywarki (brakujace pola = None)."""
    if not data:
        return None
    zast = data.get('zastosowanie') if isinstance(data.get('zastosowanie'), dict) else {}
    parts = data.get('czesci_rosliny') if isinstance(data.get('czesci_rosliny'), dict) else {}
    barwniki = None
    if legacy:
        barwniki = next((v for k, t, v in legacy['sekcje'] if k == 'barwniki'), None)
        if isinstance(barwniki, dict):
            barwniki = barwniki.get('opis')
    return {
        'nazwa_pl': data.get('nazwa_pl'), 'nazwa_lat': data.get('nazwa_lat'), 'rodzina': data.get('rodzina'),
        'opis': data.get('opis'), 'profil': data.get('profil_energetyczny'), 'wymagania': data.get('wymagania'),
        'czesci': {k: (v.get('wlasciwości') or v.get('wlasciwosci') or '') if isinstance(v, dict) else '' for k, v in parts.items()},
        'medyczne': zast.get('medyczne'), 'rzemieslnicze': zast.get('rzemieslnicze'), 'barwniki': barwniki,
        'interakcje': data.get('interakcje'), 'ostrzezenia': data.get('ostrzezenia'),
        'przepisy': len(recipes), 'archiwum': bool(data.get('_archiwum')),
    }


@plants_bp.route('/porownaj/')
def porownaj():
    """Porownywarka 2-3 roslin (przeniesiona z pierwszego Kwiatownika).
    Strona jest zamrazana do statycznego HTML (freeze.py -> build/), wiec dane WSZYSTKICH roslin trafiaja
    do strony jako JSON, a wybor roslin (?a=&b=&c=) obsluguje JavaScript w przegladarce."""
    rows = {}
    for pid in get_all_plants_list():
        data = get_plant_data(pid)
        if data:
            rows[pid] = _compare_row(data, get_legacy_plant(plants_dir(), pid),
                                     recipes_for_plant(pid, data.get('nazwa_pl')))
    all_plants = sorted(({'id': pid, 'name': r.get('nazwa_pl') or pid} for pid, r in rows.items()),
                        key=lambda p: p['name'])
    return render_template('porownaj.html', all_plants=all_plants, rows=rows)


@plants_bp.route('/szukaj_terapeutyczna/', methods=['GET', 'POST'])
def szukaj_terapeutyczna():
    suggestions = get_all_therapeutic_keywords()
    results = []
    query = ""

    if request.method == 'POST':
        query = request.form.get('query', '').lower()
        all_plants_ids = get_all_plants_list()
        for pid in all_plants_ids:
            data = get_plant_data(pid)
            if data and query in str(data).lower():
                results.append(data)

    return render_template('szukaj_terapeutyczna.html', results=results, query=query, suggestions=suggestions)


@plants_bp.route('/gildie/', methods=['GET', 'POST'])
def gildie():
    # Pobieranie astro dla gildii (uproszczone z oryginału)
    lat, lon, city_name = '49.95', '18.38', "Z (Domyślnie)"
    astro = get_astrological_data(lat=lat, lon=lon)
    astro['location'] = city_name

    all_plants_ids = get_all_plants_list()
    all_plants_data = [{'id': pid, 'name': get_plant_data(pid).get('nazwa_pl')} for pid in all_plants_ids if
                       get_plant_data(pid)]
    selected_plant = None
    companions = []

    if request.method == 'POST':
        plant_id = request.form.get('main_plant') or request.form.get('search_query')
        if plant_id and not get_plant_data(plant_id):
            for p in all_plants_data:
                if p['name'].lower() == plant_id.lower():
                    plant_id = p['id']
                    break

        selected_plant = get_plant_data(plant_id)
        if selected_plant:
            raw_companions = selected_plant.get('permakultura', {}).get('gildie', [])
            if isinstance(raw_companions, list):
                for c in raw_companions:
                    base_name = c['nazwa'].split('(')[0].strip()
                    comp_id = next((p['id'] for p in all_plants_data if p['name'].lower() == base_name.lower()), None)
                    companions.append({'nazwa': c['nazwa'], 'rola': c['rola'], 'id': comp_id})

    return render_template('gildie.html', all_plants=all_plants_data, selected_plant=selected_plant,
                           companions=companions, astro=astro)


@plants_bp.route('/generator/', methods=['GET', 'POST'])
def generator():
    all_plants_ids = get_all_plants_list()
    plants_data = []
    all_properties = set()

    for pid in all_plants_ids:
        data = get_plant_data(pid)
        if not data:
            continue
        # czesci reczne (z wiedza z sieci wmontowana przez Siedzibe) + nowe czesci znane tylko z sieci
        parts_info = czesci_generatora(data)
        if not parts_info:
            continue
        # przeciwwskazania + interakcje calej rosliny (z wiedza z sieci, gdy scalona)
        general_warn_str = ostrzezenia_generatora(data)
        for info in parts_info.values():
            if info['props']:
                words = [p.strip().lower() for p in info['props'].replace(',', ' ').split() if len(p) > 3]
                all_properties.update(words)
        plants_data.append({'slug': pid, 'nazwa_pl': data.get('nazwa_pl', 'Nieznana'), 'parts': parts_info,
                            'warnings': general_warn_str})

    plants_data.sort(key=lambda x: x['nazwa_pl'])
    comments = Comment.query.filter_by(plant_id='generator').order_by(Comment.date_posted.desc()).all()

    if request.method == 'POST':
        if current_user.is_authenticated:
            content = request.form.get('content')
            is_private = request.form.get('is_private') == 'on'
            if content:
                new_comment = Comment(content=content, user_id=current_user.id, plant_id='generator',
                                      is_private=is_private)
                db.session.add(new_comment)
                db.session.commit()
                flash('Dodano notatkę do generatora.', 'success')
            return redirect(url_for('plants.generator'))
        else:
            flash('Musisz być zalogowany, aby dodawać notatki.', 'danger')

    return render_template('generator.html', plants=plants_data, suggestions=sorted(list(all_properties)),
                           comments=comments)