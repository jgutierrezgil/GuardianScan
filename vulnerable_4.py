from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Configuración de la base de datos SQLite
DATABASE = 'users.db'

def init_db():
    """
    Inicializa la base de datos y crea la tabla si no existe.
    También inserta un usuario inicial si la tabla está vacía.
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Crear la tabla si no existe
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')

    # Verificar si hay usuarios en la tabla
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Insertar un usuario inicial si la tabla está vacía
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'password123'))
        conn.commit()
        print("Usuario inicial 'admin' creado.")

    conn.close()

@app.route('/')
def home():
    return '''
    <h1>Bienvenido a la aplicación vulnerable</h1>
    <p>Esta aplicación es vulnerable a ataques XSS.</p>
    <ul>
        <li><a href="/login">Login (POST)</a></li>
        <li><a href="/search">Buscar usuario (GET)</a></li>
    </ul>
    '''

# Ruta vulnerable a XSS mediante POST
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Consulta segura usando parámetros
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        # Vulnerabilidad XSS: Respuesta no sanitizada
        if user:
            message = f"Bienvenido, <b>{username}</b>!"
        else:
            message = "Credenciales incorrectas."

        return f'''
        <h1>Resultado del login:</h1>
        <p>{message}</p>
        <a href="/login">Intentar de nuevo</a>
        '''

    # Formulario de login
    return '''
    <h1>Login</h1>
    <form method="POST">
        <label for="username">Usuario:</label>
        <input type="text" name="username" id="username"><br><br>
        <label for="password">Contraseña:</label>
        <input type="password" name="password" id="password"><br><br>
        <button type="submit">Iniciar sesión</button>
    </form>
    '''

# Ruta vulnerable a XSS mediante GET
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerabilidad XSS: Respuesta no sanitizada
    return f'''
    <h1>Resultados de búsqueda:</h1>
    <p>Buscaste: <b>{query}</b></p>
    <a href="/search">Buscar de nuevo</a>
    '''

if __name__ == '__main__':
    # Inicializar la base de datos al iniciar la aplicación
    init_db()
    app.run(port='5004', debug=True)