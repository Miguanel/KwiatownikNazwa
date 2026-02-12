import os
import json
import sys
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort
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
    return User.query.get(int(user_id))


# --- FUNKCJE POMOCNICZE (JSON) ---

def get_plant_data(plant_name):
    """Wczytuje dane o roślinie z pliku JSON."""
    file_path = os.path.join(app.config['JSON_DATA_FOLDER'], f"{plant_name}.json")
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
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
    all_plants_ids = get_all_plants_list()
    plants_with_parts = []
    all_properties = set()

    for pid in all_plants_ids:
        data = get_plant_data(pid)
        if data and 'czesci_rosliny' in data:
            parts_info = []
            for part_name, part_data in data['czesci_rosliny'].items():
                props = part_data.get('wlasciwości', '').lower()
                all_properties.update([p.strip() for p in props.replace(',', ' ').split() if len(p) > 3])

                parts_info.append({
                    'name': part_name,
                    'properties': props
                })

            plants_with_parts.append({
                'id': pid,
                'name': data.get('nazwa_pl'),
                'parts': parts_info
            })

    result = None
    if request.method == 'POST':
        selected_items = request.form.getlist('selected_parts')
        gen_type = request.form.get('gen_type')
        volume = int(request.form.get('volume', 500))

        if selected_items:
            recipe_ingredients = []
            warnings = []

            for item in selected_items:
                plant_id, part_name = item.split(':')
                data = get_plant_data(plant_id)
                part_data = data['czesci_rosliny'][part_name]

                recipe_ingredients.append({
                    'plant_name': data['nazwa_pl'],
                    'part_name': part_name,
                    'latin_name': part_data.get('nazwa_surowca', ''),
                    'properties': part_data.get('wlasciwości', '')
                })
                if data.get('ostrzezenia'):
                    warnings.append(f"{data['nazwa_pl']} ({part_name}): {data['ostrzezenia']}")

            herb_weight = volume / 5 if gen_type == 'nalewka' else volume / 10

            result = {
                'type': gen_type,
                'volume': volume,
                'ingredients': recipe_ingredients,
                'proportions': [],
                'warnings': list(set(warnings))  # usunięcie duplikatów
            }

            for ing in recipe_ingredients:
                weight = herb_weight / len(recipe_ingredients)
                result['proportions'].append({
                    'label': f"{ing['part_name'].capitalize()} {ing['plant_name']} ({ing['latin_name']})",
                    'value': f"{round(weight, 1)}g",
                    'desc': ing['properties']
                })
    now = f" {datetime.now().day}.{datetime.now().month}.{datetime.now().year}"
    return render_template('generator.html',
                           plants_with_parts=plants_with_parts,
                           suggestions=sorted(list(all_properties)),
                           now=now,
                           result=result)


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


if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['JSON_DATA_FOLDER']):
            os.makedirs(app.config['JSON_DATA_FOLDER'])

    app.run(debug=True)
