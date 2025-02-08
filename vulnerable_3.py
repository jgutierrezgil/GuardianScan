import sqlite3
from flask import Flask, request

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('vulnerable3.db')
    c = conn.cursor()
    # Crear tabla usuarios
    c.execute('''
        CREATE TABLE IF NOT EXISTS users 
        (id INTEGER PRIMARY KEY, username TEXT, password TEXT)
    ''')
    # Insertar datos de prueba
    c.execute("INSERT OR REPLACE INTO users (id, username, password) VALUES (1, 'admin', 'secretpass')")
    c.execute("INSERT OR REPLACE INTO users (id, username, password) VALUES (2, 'test', 'testpass')")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return """
        <h1>Test Vulnerabilities in XSS and SQLi</h1>
        <p>
        This app is vulnerable to XSS attacks and SQLi injections. Test it at the following links or at GuardianScan.
        </p>
        <p>Try XSS: <a href="/xss?input=<script>alert(1)</script>">/xss?input=&lt;script&gt;alert(1)&lt;/script&gt;</a></p>
        <p>Try SQLi: <a href="/sqli?id=1 OR 1=1">/sqli?id=1 OR 1=1</a></p>
    """

@app.route('/xss')
def xss():
    # Vulnerable a XSS - el input se inserta directamente sin sanitizar
    user_input = request.args.get('input', '')
    return f"""
        <h1>XSS Test</h1>
        <p>Your input: {user_input}</p>
        <a href="/">Back to home</a>
    """

@app.route('/sqli')
def sqli():
    # Vulnerable a SQLi - concatenación directa en la query
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    try:
        # Query vulnerable
        query = f"SELECT * FROM users WHERE id = {user_id}"
        results = c.execute(query).fetchall()
        
        output = "<h1>SQLi Test</h1>"
        for row in results:
            output += f"<p>User found: {row[1]}, Password: {row[2]}</p>"
        
        if not results:
            output += "<p>No users found</p>"
            
        output += '<a href="/">Back to home</a>'
        return output
        
    except sqlite3.Error as e:
        return f"Error: {str(e)}"
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5003)