
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

users = []

# Ruta para la página de inicio
@app.route('/')
def index():
    return render_template('index.html', users=users)

# Ruta para agregar un nuevo usuario
@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        permissions = request.form.getlist('permissions')

        # Verifica si el usuario ya existe
        if any(user['username'] == username for user in users):
            flash('El nombre de usuario ya está en uso. Elige otro.')
            return redirect(url_for('create_user'))

        # Agregar nuevo usuario a la lista
        new_user = {
            'username': username,
            'password': password,  # En producción, asegúrate de encriptar la contraseña
            'role': role,
            'permissions': permissions
        }
        users.append(new_user)
        flash('Usuario creado correctamente.')
        return redirect(url_for('index'))

    return render_template('create_user.html')

# Ruta para editar un usuario existente
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = users[user_id]
    
    if request.method == 'POST':
        user['username'] = request.form['username']
        user['password'] = request.form['password']
        user['role'] = request.form['role']
        user['permissions'] = request.form.getlist('permissions')

        flash('Usuario actualizado correctamente.')
        return redirect(url_for('index'))

    return render_template('edit_user.html', user=user, user_id=user_id)

# Ruta para el registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Aquí manejarías el registro del usuario
        username = request.form['username']
        password = request.form['password']
        # Agrega lógica para almacenar el usuario
        return redirect(url_for('login'))
    return render_template('register.html')

# Ruta para el inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Aquí manejarías la autenticación del usuario
        username = request.form['username']
        password = request.form['password']
        # Agrega lógica para verificar las credenciales
        return redirect(url_for('home'))
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
