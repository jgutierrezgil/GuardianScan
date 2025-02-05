import sqlite3
from flask import Flask, request, g, render_template_string

DATABASE = 'vulnerable3.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Crear la tabla de productos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT
        )
    ''')
    # Insertar datos de ejemplo
    cursor.execute("INSERT INTO products (name, description) VALUES ('Laptop', 'Una laptop potente')")
    cursor.execute("INSERT INTO products (name, description) VALUES ('Smartphone', 'Un smartphone moderno')")
    conn.commit()
    conn.close()

app = Flask(__name__)
init_db()  # Inicializar la base de datos

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Endpoint de ayuda para la ruta raíz
@app.route("/", methods=["GET"])
def index():
    return """
    <h1>Bienvenido a la aplicación vulnerable a XSS y SQL Injection</h1>
    <p>Esta aplicación es vulnerable a:</p>
    <ul>
      <li>Cross-Site Scripting (XSS) en el parámetro <code>q</code>.</li>
      <li>SQL Injection (SQLi) en el parámetro <code>id</code>.</li>
    </ul>
    <p>Para probar la vulnerabilidad, utiliza la siguiente ruta:</p>
    <p>
      <code>/both?q=</code> seguido de tu payload XSS y <code>&amp;id=</code> con un valor numérico o una inyección SQL.
      <br>
      Ejemplo:
      <a href="/both?q=%3Cscript%3Ealert('XSS')%3C/script%3E&amp;id=1">
          /both?q=&lt;script&gt;alert('XSS')&lt;/script&gt;&amp;id=1
      </a>
    </p>
    """

@app.route('/both', methods=['GET'])
def vulnerable_both():
    # Obtener la entrada XSS sin sanear
    xss_input = request.args.get('q', '')
    # Obtener el parámetro 'id' para la consulta SQL
    product_id = request.args.get('id', '')
    query = "SELECT * FROM products WHERE id = " + product_id
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(query)
        product = cursor.fetchone()
    except Exception as e:
        product = None
        error = str(e)
    else:
        error = None

    # Plantilla que refleja el payload XSS (sin escape) y muestra los resultados de la consulta SQL
    template = """
    <html>
        <head>
            <title>App Vulnerable a XSS y SQLi</title>
        </head>
        <body>
            <h1>App Vulnerable a XSS y SQL Injection</h1>
            <h2>Resultado de Consulta SQL:</h2>
            {% if error %}
                <p>Error en la consulta: {{ error }}</p>
            {% elif product %}
                <p>ID: {{ product[0] }}, Nombre: {{ product[1] }}, Descripción: {{ product[2] }}</p>
            {% else %}
                <p>No se encontró producto.</p>
            {% endif %}
            <h2>Reflejo de Entrada XSS:</h2>
            <p>Entrada: {{ xss_input|safe }}</p>
        </body>
    </html>
    """
    return render_template_string(template, product=product, error=error, xss_input=xss_input)

if __name__ == '__main__':
    app.run(port=5003, debug=True)
