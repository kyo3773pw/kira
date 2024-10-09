from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import cv2
import numpy as np
import base64
import mediapipe as mp
import math
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://sa:user123@anyone_else/usuarios?driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'user123'  # Cambia esto por una clave segura
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    permissions = db.Column(db.String(255), nullable=True)
    profile_image = db.Column(db.LargeBinary)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('No tienes permiso para acceder a esta página.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def coadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'coadmin']:
            flash('No tienes permiso para acceder a esta página.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@admin_required 
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        permissions = request.form.getlist('permissions')
        profile_image = request.form.get('profile_image')

        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya está en uso. Elige otro.')
            return redirect(url_for('create_user'))

        hashed_password = generate_password_hash(password)
        
        # Process the profile image
        if profile_image:
            # Remove the "data:image/png;base64," part
            image_data = profile_image.split(',')[1]
            image_binary = base64.b64decode(image_data)
        else:
            image_binary = None

        new_user = User(
            username=username, 
            password=hashed_password, 
            role=role, 
            permissions=",".join(permissions),
            profile_image=image_binary
        )
        
        db.session.add(new_user)
        db.session.commit()
        flash('Usuario creado correctamente.')
        return redirect(url_for('index'))

    return render_template('create_user.html')



@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@login_required
@coadmin_required
def edit_user(username):
    user = User.query.filter_by(username=username).first()
    
    if request.method == 'POST':
        user.username = request.form['username']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        user.role = request.form['role']
        user.permissions = ",".join(request.form.getlist('permissions'))

        db.session.commit()
        flash('Usuario actualizado correctamente.')
        return redirect(url_for('index'))

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<username>', methods=['DELETE'])
@login_required
@admin_required
def delete_user_route(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Usuario eliminado correctamente.')
    else:
        flash('El usuario no se encontró.')
    return '', 204  # No Content

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        face_image = request.form.get('face_image')
        
        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya está en uso.')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        face_binary = base64.b64decode(face_image.split(',')[1]) if face_image else None
        
        new_user = User(username=username, password=hashed_password, role='user', profile_image=face_binary)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registro exitoso. Por favor, inicia sesión.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/update_profile_image', methods=['POST'])
@login_required
def update_profile_image():
    face_image = request.form.get('face_image')
    if face_image:
        face_binary = base64.b64decode(face_image.split(',')[1])
        current_user.profile_image = face_binary
        db.session.commit()
        flash('Imagen de perfil actualizada correctamente.')
    else:
        flash('No se recibió ninguna imagen.')
    return redirect(url_for('profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        face_image = request.form.get('face_image')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if face_image:
                # Convertir la imagen base64 a binario
                face_binary = base64.b64decode(face_image.split(',')[1])
                
                # Almacenar la imagen facial en profile_image
                user.profile_image = face_binary
                db.session.commit()
            
            login_user(user)
            flash('Inicio de sesión exitoso.')
            return redirect(url_for('index'))
        else:
            flash('Credenciales inválidas.')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente.')
    return redirect(url_for('login')) 

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
