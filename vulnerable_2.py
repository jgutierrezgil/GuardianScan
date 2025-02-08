import sqlite3
from flask import Flask, request, g, render_template_string
from markupsafe import escape

DATABASE = 'vulnerable2.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')
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

def safe_url(url):
    """Sanitiza URLs para prevenir javascript: y otros protocolos maliciosos"""
    url = escape(url)
    if url.lower().startswith('javascript:') or not url.startswith(('http://', 'https://', '/')):
        return '#'
    return url

@app.route("/", methods=["GET"])
def index():
    base_url = escape(request.url_root)
    template = '''
    <h1>Welcome to the vulnerable application</h1>
    <p>This application is vulnerable to SQL Injection, but not to XSS.</p>
    <p>Test this app on the following routes or on GuardianScan:</p>
    <ul>
        <li><a href="{{ base_url }}sqli?id=1">SQL Injection</a></li>
        <li><a href="{{ base_url }}xss?message=test">XSS Protected</a></li>
        <li><a href="{{ base_url }}about">About</a></li>
    </ul>
    '''
    return render_template_string(template, base_url=base_url)

@app.route("/about", methods=["GET"])
def about():
    base_url = escape(request.url_root)
    template = '''
    <h1>About this application</h1>
    <p>This is a sample application with controlled vulnerabilities.</p>
    <p>This app is protected from XSS injections by escaping user inputs.</p>
    <p>This use the escape function from the markupsafe library, converting special characters to their equivalents in HTML.</p>
    <p>For example, the &lt; character is converted to <code>&amp;lt;</code></p>
    <p>The function safe_url is used to sanitize URLs and prevent malicious protocols like javascript:.</p>
    <p><a href="{{ base_url }}">Volver al inicio</a></p>
    '''
    return render_template_string(template, base_url=base_url)

@app.route("/xss", methods=["GET"])
def protected_xss():
    base_url = escape(request.url_root)
    message = escape(request.args.get('message', ''))
    # Validar que el mensaje no contenga javascript: urls
    message = safe_url(message) if ':' in message else message
    
    template = '''
    <h1>Mensaje recibido (protegido contra XSS):</h1>
    <p>{{ message|e }}</p>
    <p><a href="{{ base_url }}">Volver al inicio</a></p>
    <p><a href="{{ base_url }}xss?message=nuevo_mensaje">Probar otro mensaje</a></p>
    '''
    return render_template_string(template, message=message, base_url=base_url)

@app.route("/sqli", methods=["GET"])
def vulnerable_sqli():
    base_url = escape(request.url_root)
    user_id = request.args.get('id', '').strip()
    
    if not user_id:
        template = '''
        <h1>SQL Injection Test</h1>
        <p>Esta aplicación es vulnerable a SQL Injection.</p>
        <p>Ejemplos:</p>
        <ul>
            <li><a href="{{ base_url }}sqli?id=1">Usuario normal</a></li>
            <li><a href="{{ base_url }}sqli?id=1 OR 1=1">Inyección SQL</a></li>
        </ul>
        <p><a href="{{ base_url }}">Volver al inicio</a></p>
        '''
        return render_template_string(template, base_url=base_url)
    
    # Esta parte sigue siendo vulnerable a SQLi intencionalmente
    query = "SELECT * FROM users WHERE id = " + user_id
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except Exception as e:
        template = '''
        <p>Error en la consulta: {{ error }}</p>
        <p><a href="{{ base_url }}">Volver al inicio</a></p>
        '''
        return render_template_string(template, error=escape(str(e)), base_url=base_url)
    
    if not rows:
        template = '''
        <p>No se encontró ningún usuario.</p>
        <p><a href="{{ base_url }}">Volver al inicio</a></p>
        '''
        return render_template_string(template, base_url=base_url)
    
    template = '''
    <h1>Resultados:</h1>
    {% for row in rows %}
    <p>ID: {{ row[0]|e }}, Usuario: {{ row[1]|e }}, Contraseña: {{ row[2]|e }}</p>
    {% endfor %}
    <p><a href="{{ base_url }}">Volver al inicio</a></p>
    '''
    return render_template_string(template, rows=rows, base_url=base_url)

if __name__ == '__main__':
    app.run(port=5002, debug=True)