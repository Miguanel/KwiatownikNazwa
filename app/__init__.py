# app/__init__.py
import os
import sys
from flask import Flask, request
from app.extensions import db, login_manager
from astro_engine import get_astrological_data


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    return os.path.join(base_path, relative_path)


def create_app():
    app = Flask(__name__,
                template_folder=resource_path('templates'),
                static_folder=resource_path('static'))

    app.config['SECRET_KEY'] = 'beka_has_lo'

    DATABASE_URL = os.getenv('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///local.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Inicjalizacja rozszerzeń
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Kontekst procesor dla zmiennych dostępnych w każdym HTML
    @app.context_processor
    def inject_astro():
        lat = request.cookies.get('user_lat')
        lon = request.cookies.get('user_lon')
        city_name = request.cookies.get('user_city')

        if not lat or not lon:
            lat, lon = '49.95', '18.38'
            city_name = "Z"

        try:
            astro_data = get_astrological_data(lat=lat, lon=lon)
            astro_data['location'] = city_name
        except Exception:
            astro_data = {"location": city_name, "temp": "??°C", "humidity": "??%", "phase_name": "-",
                          "festival": "Zwyczajny Czas"}

        return dict(astro=astro_data)

    # Rejestracja Blueprintów
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.plants import plants_bp
    from app.routes.api import api_bp
    # from app.routes.recipes import recipes_bp (Dodać gdy stworzysz plik)
    # from app.routes.comments import comments_bp (Dodać gdy stworzysz plik)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(plants_bp)
    app.register_blueprint(api_bp)

    return app