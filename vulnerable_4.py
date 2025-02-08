from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# SQLite database configuration
DATABASE = 'vulnerable4.db'

def init_db():
    """
    Initializes the database and creates the table if it doesn't exist.
    Also inserts an initial user if the table is empty.
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create the table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')

    # Check if there are any users in the table
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Insert an initial user if the table is empty
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'password123'))
        conn.commit()
        print("Initial user 'admin' created.")

    conn.close()

@app.route('/')
def home():
    return '''
    <h1>Welcome to safe App</h1>
    <p>This site has been protected from XSS by escaping user inputs
         and from SQL Injection by using parameterized queries.</p>
    <ul>
        <li><a href="/login">Login (POST)</a></li>
        <li><a href="/search">Buscar usuario (GET)</a></li>
    </ul>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Secure query using parameters to avoid SQL Injection
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        # Prevent XSS by rendering the message through a template that escapes special characters
        if user:
            message = f"Bienvenido, {username}!"
        else:
            message = "Credenciales incorrectas."

        return render_template_string('''
            <h1>Resultado del login:</h1>
            <p>{{ message }}</p>
            <a href="/login">Intentar de nuevo</a>
        ''', message=message)

    # Login form
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

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')

    # Aquí se incluye un formulario GET para realizar la búsqueda.
    # Al enviar el formulario, se recarga la misma ruta con el parámetro ?q=...
    return render_template_string('''
        <h1>Búsqueda</h1>
        <form method="GET" action="/search">
            <label for="q">Ingresa tu búsqueda:</label><br>
            <input type="text" name="q" id="q" value="{{ query }}"><br><br>
            <button type="submit">Buscar</button>
        </form>

        <h2>Resultados de búsqueda:</h2>
        <p>Buscaste: <b>{{ query }}</b></p>
        <a href="/search">Buscar de nuevo</a>
    ''', query=query)

if __name__ == '__main__':
    # Initialize the database when starting the application
    init_db()
    app.run(port='5004', debug=True)
