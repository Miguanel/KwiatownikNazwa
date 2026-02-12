import os
import json
import sys
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash


def resource_path(relative_path):
    """ Zwraca absolutną ścieżkę do zasobu, działa dla dev i dla PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


app = Flask(__name__,
            template_folder=resource_path('templates'),
            static_folder=resource_path('static'))
app.config['SECRET_KEY'] = 'twoj_super_tajny_klucz_123'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kwiatownik.db'
app.config['JSON_DATA_FOLDER'] = 'data/plants'

# Pobiera URL bazy z ustawień serwera, a jeśli go nie ma (lokalnie), używa SQLite
DATABASE_URL = os.getenv('DATABASE_URL')
# WAŻNE: Render/Neon często wymagają poprawki protokołu z postgres:// na postgresql://
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///local.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app, engine_options={
    "pool_pre_ping": True,
    "pool_recycle": 300,
})
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# --- MODELE BAZY DANYCH (SQLITE) ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    comments = db.relationship('Comment', backref='author', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=False)
    plant_id = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- FUNKCJE POMOCNICZE (JSON) ---

def get_plant_data(pid):
    # Zakładam, że Twoja ścieżka wygląda tak:
    path = os.path.join('data', f'{pid}.json')

    if not os.path.exists(path):
        print(f"BŁĄD: Plik {path} nie istnieje!")
        return None

    if os.path.getsize(path) == 0:
        print(f"BŁĄD: Plik {path} jest pustY (0 bajtów)!")
        return None

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"BŁĄD: Plik {path} zawiera niepoprawny format JSON!")
        return None


def get_all_plants_list():
    """Zwraca listę wszystkich dostępnych roślin (nazwy plików)."""
    if not os.path.exists(app.config['JSON_DATA_FOLDER']):
        return []
    return [f.replace('.json', '') for f in os.listdir(app.config['JSON_DATA_FOLDER']) if f.endswith('.json')]


# --- TRASY (ROUTES) ---

@app.route('/')
def index():
    plants = get_all_plants_list()
    return render_template('index.html', plants=plants)


@app.route('/plant/<plant_id>')
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


@app.route('/comments', methods=['GET', 'POST'])
def all_comments():
    """Podstrona ze wszystkimi komentarzami i dodawaniem ogólnych."""
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('Zaloguj się, aby dodać komentarz.', 'warning')
            return redirect(url_for('login'))

        new_comment = Comment(
            content=request.form.get('content'),
            author=current_user,
            plant_id=None
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('all_comments'))

    comments = Comment.query.order_by(Comment.date_posted.desc()).all()
    return render_template('all_comments.html', comments=comments)


# --- ZARZĄDZANIE KOMENTARZAMI (CRUD) ---

@app.route('/comment/add/<plant_id>', methods=['POST'])
@login_required
def add_comment(plant_id):
    content = request.form.get('content')

    is_private = True if request.form.get('is_private') else False

    if content:
        comment = Comment(
            content=content,
            plant_id=plant_id,
            author=current_user,
            is_private=is_private
        )
        db.session.add(comment)
        db.session.commit()
        if is_private:
            flash('Dodano prywatną notatkę.', 'info')
        else:
            flash('Dodano publiczny komentarz.', 'success')

    return redirect(url_for('plant_detail', plant_id=plant_id))


@app.route('/comment/edit/<int:comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user and not current_user.is_admin:
        abort(403)

    if request.method == 'POST':
        comment.content = request.form.get('content')
        db.session.commit()
        flash('Komentarz zaktualizowany.', 'success')
        return redirect(url_for('all_comments'))

    return render_template('edit_comment.html', comment=comment)


@app.route('/comment/delete/<int:comment_id>')
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user and not current_user.is_admin:
        abort(403)

    db.session.delete(comment)
    db.session.commit()
    flash('Komentarz usunięty.', 'info')
    return redirect(request.referrer or url_for('all_comments'))


# --- GILDIE ---


@app.route('/gildie', methods=['GET', 'POST'])
def gildie():
    all_plants_ids = get_all_plants_list()
    all_plants_data = []

    for pid in all_plants_ids:
        data = get_plant_data(pid)
        if data:
            all_plants_data.append({'id': pid, 'name': data.get('nazwa_pl')})

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
            perma_data = selected_plant.get('permakultura', {})
            raw_companions = perma_data.get('gildie', [])

            if isinstance(raw_companions, list):
                for c in raw_companions:
                    base_name = c['nazwa'].split('(')[0].strip()
                    comp_id = next((p['id'] for p in all_plants_data if p['name'].lower() == base_name.lower()), None)

                    companions.append({
                        'nazwa': c['nazwa'],
                        'rola': c['rola'],
                        'id': comp_id
                    })

    return render_template('gildie.html',
                           all_plants=all_plants_data,
                           selected_plant=selected_plant,
                           companions=companions)


# --- SZUKAJ OBJAWU ---
def get_all_therapeutic_keywords():
    all_plants_ids = get_all_plants_list()
    keywords = set()

    for pid in all_plants_ids:
        data = get_plant_data(pid)
        if data:
            for czesc in data.get('czesci_rosliny', {}).values():
                wlasciwosci = czesc.get('wlasciwości', '')
                # Rozbijamy tekst na słowa i czyścimy z przecinków
                words = [w.strip().lower() for w in wlasciwosci.replace(',', ' ').replace('.', ' ').split()]
                keywords.update(words)

            # Pobieramy słowa z zastosowania medycznego
            medyczne = data.get('zastosowanie', {}).get('medyczne', '')
            med_words = [w.strip().lower() for w in medyczne.replace(',', ' ').replace('.', ' ').split()]
            keywords.update(med_words)

    # Filtrujemy zbyt krótkie słowa (poniżej 4 znaków), aby uniknąć spójników
    return sorted([word for word in keywords if len(word) > 3])


@app.route('/szukaj_terapeutyczna', methods=['GET', 'POST'])
def szukaj_terapeutyczna():
    suggestions = get_all_therapeutic_keywords()  # Pobieramy słowa do autouzupełniania
    results = []
    query = ""

    if request.method == 'POST':
        query = request.form.get('query', '').lower()
        all_plants_ids = get_all_plants_list()

        for pid in all_plants_ids:
            data = get_plant_data(pid)
            if 'zastosowanie' not in data:
                print(f"UWAGA: Plik {pid}.json nie posiada sekcji zastosowanie!")

            full_text = str(data).lower()
            if query in full_text:
                results.append(data)

    return render_template('szukaj_terapeutyczna.html',
                           results=results,
                           query=query,
                           suggestions=suggestions)


# --- LOGIKA GENERATORA ---
@app.route('/generator', methods=['GET', 'POST'])
def generator():
    # 1. Przygotowanie danych o roślinach i ich częściach
    all_plants_ids = get_all_plants_list()
    plants_data = []
    all_properties = set()

    for pid in all_plants_ids:
        data = get_plant_data(pid)
        if data and 'czesci_rosliny' in data:
            parts_info = {}

            # Pobieramy ostrzeżenie ogólne dla całej rośliny i czyścimy je
            raw_general_warn = data.get('ostrzezenia')
            general_warn_str = ""
            if isinstance(raw_general_warn, list):
                general_warn_str = " ".join(raw_general_warn)
            elif isinstance(raw_general_warn, str):
                general_warn_str = raw_general_warn

            for part_name, part_data in data['czesci_rosliny'].items():
                # A. Właściwości
                props_text = part_data.get('wlasciwości', '') or part_data.get('wlasciwosci', '')

                # B. Składniki aktywne
                ingr_raw = part_data.get('skladniki_aktywne', [])
                if isinstance(ingr_raw, list):
                    ingr_text = ", ".join(ingr_raw)
                else:
                    ingr_text = str(ingr_raw) if ingr_raw else ""

                # C. Ostrzeżenia dla części
                part_warn_raw = part_data.get('ostrzezenia')
                part_warn_str = ""

                if part_warn_raw:
                    # Jeśli część ma własne ostrzeżenie
                    if isinstance(part_warn_raw, list):
                        part_warn_str = " ".join(part_warn_raw)
                    else:
                        part_warn_str = str(part_warn_raw)
                else:
                    # Fallback: Jeśli część nie ma, bierzemy ogólne
                    part_warn_str = general_warn_str

                # D. Zapisujemy dane
                parts_info[part_name] = {
                    'props': props_text,
                    'ingr': ingr_text,
                    'warn': part_warn_str  # To zawsze jest teraz stringiem
                }

                if props_text:
                    words = [p.strip().lower() for p in props_text.replace(',', ' ').split() if len(p) > 3]
                    all_properties.update(words)

            plants_data.append({
                'slug': pid,
                'nazwa_pl': data.get('nazwa_pl', 'Nieznana'),
                'parts': parts_info,
                'warnings': general_warn_str  # Przekazujemy czysty string do atrybutu HTML
            })

    plants_data.sort(key=lambda x: x['nazwa_pl'])

    # 2. Obsługa komentarzy
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
            return redirect(url_for('generator'))
        else:
            flash('Musisz być zalogowany, aby dodawać notatki.', 'danger')

    return render_template('generator.html', plants=plants_data, suggestions=sorted(list(all_properties)),
                           comments=comments)
# --- AUTENTYKACJA ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Użytkownik już istnieje.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        is_admin = True if User.query.count() == 0 else False

        new_user = User(username=username, password_hash=hashed_pw, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash('Konto utworzone! Możesz się zalogować.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Błędny login lub hasło.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Przepisy

def load_recipes():
    recipes = []
    # Zakładam, że pliki nazywają się tak jak poniżej - sprawdź to!
    files = ['data/przepisy/przepisy_medyczne.json', 'data/przepisy/przepisy_kulinarne.json']

    for file_path in files:
        # Pamiętaj o użyciu resource_path jeśli nadal budujesz .exe!
        # Jeśli uruchamiasz lokalnie/na Render, wystarczy os.path.join
        try:
            # full_path = resource_path(file_path) # Odkomentuj dla wersji .exe
            full_path = os.path.join(app.root_path, file_path)  # Dla wersji standardowej

            with open(full_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # POPRAWKA: Twoje dane są w kluczu "przepisy"
                if isinstance(data, dict) and "przepisy" in data:
                    recipes.extend(data["przepisy"])
                elif isinstance(data, list):
                    recipes.extend(data)

        except FileNotFoundError:
            print(f"Ostrzeżenie: Nie znaleziono pliku {file_path}")
        except Exception as e:
            print(f"Błąd ładowania pliku {file_path}: {e}")

    return recipes


@app.route('/przepisy', methods=['GET'])
def przepisy():
    query = request.args.get('q', '').lower().strip()
    all_recipes = load_recipes()
    results = []

    if query:
        for recipe in all_recipes:
            # Łączymy wszystkie ważne pola w jeden ciąg tekstowy do przeszukania
            # Obsługujemy sytuację, gdzie pole może być puste (None)
            ingredients = " ".join(recipe.get('skladniki', []))
            properties = " ".join(recipe.get('wlasciwosci', []))
            features = " ".join(recipe.get('cechy', []))

            # Dodajemy też nazwę rośliny i tytuł
            searchable_text = (
                f"{recipe.get('tytul', '')} "
                f"{recipe.get('roslina', '')} "
                f"{ingredients} {properties} {features}"
            ).lower()

            if query in searchable_text:
                results.append(recipe)
    else:
        # Jeśli nic nie wpisano, pokazujemy np. losowe 20 lub wszystkie (zależy od wydajności)
        results = all_recipes

    return render_template('recipes.html', results=results, query=query)


@app.route('/api/recipe_suggestions')
def recipe_suggestions():
    """Zwraca listę pojedynczych słów kluczowych (bez śmieci i spójników)"""
    all_recipes = load_recipes()
    keywords = set()

    # Słowa do zignorowania (spójniki, przyimki, jednostki miary)
    STOP_WORDS = {
        'w', 'z', 'i', 'o', 'a', 'do', 'na', 'po', 'ze', 'za', 'się', 'lub', 'jak',
        'ml', 'g', 'kg', 'dag', 'lyz', 'łyż', 'łyżka', 'łyżeczka', 'szklanki', 'szklanka',
        'proporcja', 'ok', 'szt', 'sztuk', 'litr', 'gram', 'często', 'bardzo', 'jest'
    }

    def clean_and_split(text):
        if not text:
            return []
        # 1. Usuń cyfry i znaki specjalne (zostaw tylko litery i spacje)
        text = re.sub(r'[^\w\s]', '', text)
        # 2. Zamień na małe litery i podziel na słowa
        words = text.lower().split()
        # 3. Filtruj: słowo musi mieć min. 3 litery, nie być liczbą i nie być na liście STOP_WORDS
        return [w for w in words if len(w) > 2 and not w.isdigit() and w not in STOP_WORDS]

    for r in all_recipes:
        # Analizujemy składniki (które są listą długich opisów)
        for skladnik in r.get('skladniki', []):
            keywords.update(clean_and_split(skladnik))

        # Analizujemy właściwości i cechy
        for prop in r.get('wlasciwosci', []):
            keywords.update(clean_and_split(prop))

        for cecha in r.get('cechy', []):
            keywords.update(clean_and_split(cecha))

        # Analizujemy nazwę rośliny i tytuł
        keywords.update(clean_and_split(r.get('roslina', '')))
        # Opcjonalnie tytuł (jeśli chcesz podpowiadać np. "nalewka")
        keywords.update(clean_and_split(r.get('tytul', '')))

    # Sortujemy alfabetycznie
    return jsonify(sorted(list(keywords)))
if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['JSON_DATA_FOLDER']):
            os.makedirs(app.config['JSON_DATA_FOLDER'])

    app.run(debug=True)
