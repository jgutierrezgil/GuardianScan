import sqlite3
from flask import Flask, request, g

DATABASE = 'vulnerable2.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Crear tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')
    # Insertar algunos datos de ejemplo (evita duplicados en entornos reales)
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('user', 'userpass')")
    conn.commit()
    conn.close()

app = Flask(__name__)
init_db()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route("/", methods=["GET"])
def index():
    return """
    <h1>Bienvenido a la aplicación vulnerable a SQL Injection</h1>
    <p>Para probar la vulnerabilidad, utiliza la siguiente ruta:</p>
    <p><code>/sqli?id=</code> seguido de un valor numérico o una inyección SQL.</p>
    <p>Ejemplo: <a href="/sqli?id=1">/sqli?id=1</a> o <a href="/sqli?id=1 OR 1=1">/sqli?id=1 OR 1=1</a></p>
    """

@app.route("/sqli", methods=["GET"])
def vulnerable_sqli():
    user_id = request.args.get('id', '').strip()
    if not user_id:
        # Si no se recibe el parámetro id, se muestra un mensaje de ayuda
        return """
        <h1>Bienvenido a la aplicación vulnerable a SQL Injection</h1>
        <p>Esta aplicación es vulnerable a SQL Injection.</p>
        <p>Para probar la vulnerabilidad, agrega el parámetro <code>id</code> a la URL, por ejemplo:</p>
        <ul>
            <li><code>/sqli?id=1</code></li>
            <li><code>/sqli?id=1 OR 1=1</code> (prueba una inyección SQL)</li>
        </ul>
        """
    # Construcción de la consulta vulnerable concatenando el parámetro sin validación
    query = "SELECT * FROM users WHERE id = " + user_id
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except Exception as e:
        return f"Error en la consulta: {e}"
    
    if not rows:
        return "No se encontró ningún usuario."
    
    result = "<h1>Resultados:</h1>"
    for row in rows:
        result += f"<p>ID: {row[0]}, Usuario: {row[1]}, Contraseña: {row[2]}</p>"
    return result

if __name__ == '__main__':
    app.run(port=5002, debug=True)
