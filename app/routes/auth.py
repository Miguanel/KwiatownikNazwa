# app/routes/auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app.extensions import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Użytkownik już istnieje.', 'danger')
            return redirect(url_for('auth.register'))
        hashed_pw = generate_password_hash(password)
        is_admin = True if User.query.count() == 0 else False
        new_user = User(username=username, password_hash=hashed_pw, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        flash('Konto utworzone! Możesz się zalogować.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html')

@auth_bp.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('main.index'))
        flash('Błędny login lub hasło.', 'danger')
    return render_template('login.html')

@auth_bp.route('/logout/')
def logout():
    logout_user()
    return redirect(url_for('main.index'))