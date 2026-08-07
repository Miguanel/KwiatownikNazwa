
# app/routes/main.py
import json
import random
from flask import Blueprint, render_template
from astro_engine import get_astrological_data
from data_builder import build_calendar_from_jsons, FESTIVAL_KNOWLEDGE
from app.utils.helpers import get_all_plants_list, get_plant_data, get_all_recipes

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    plants = get_all_plants_list()
    dynamic_calendar = build_calendar_from_jsons()
    recipes = get_all_recipes()
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

    full_data_list = [get_plant_data(pid) for pid in plants if get_plant_data(pid)]

    return render_template(
        'index.html',
        plants=plants,
        plants_full_data=json.dumps(full_data_list),
        calendar_data=json.dumps(dynamic_calendar),
        astro=astro,
        knowledge=knowledge,
        recipes_full_data=json.dumps(recipes)
    )