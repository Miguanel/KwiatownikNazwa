# app/routes/plants.py
from flask import Blueprint, render_template, abort, request, flash, redirect, url_for
from flask_login import current_user
from app.models import Comment
from app.extensions import db
from app.utils.helpers import get_plant_data, get_all_plants_list, get_all_therapeutic_keywords
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

    return render_template('plant_detail.html', plant=plant_data, plant_id=plant_id, comments=comments)


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
        if data and 'czesci_rosliny' in data:
            parts_info = {}
            raw_general_warn = data.get('ostrzezenia')
            general_warn_str = " ".join(raw_general_warn) if isinstance(raw_general_warn, list) else str(
                raw_general_warn or "")

            for part_name, part_data in data['czesci_rosliny'].items():
                props_text = part_data.get('wlasciwości', '') or part_data.get('wlasciwosci', '')
                ingr_raw = part_data.get('skladniki_aktywne', [])
                ingr_text = ", ".join(ingr_raw) if isinstance(ingr_raw, list) else str(ingr_raw or "")

                part_warn_raw = part_data.get('ostrzezenia')
                part_warn_str = " ".join(part_warn_raw) if isinstance(part_warn_raw, list) else str(
                    part_warn_raw or general_warn_str)

                parts_info[part_name] = {'props': props_text, 'ingr': ingr_text, 'warn': part_warn_str}
                if props_text:
                    words = [p.strip().lower() for p in props_text.replace(',', ' ').split() if len(p) > 3]
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