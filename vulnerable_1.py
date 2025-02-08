from flask import Flask, request
app = Flask(__name__)

# Endpoint de ayuda para la ruta raíz
@app.route("/", methods=["GET"])
def index():
    return """
    <h1>Welcome to the XSS vulnerable application</h1>
    <p>This application is vulnerable to Cross-Site Scripting (XSS).</p>
    <p>The app doesn't sanitize the user input, allowing attackers to inject malicious scripts.</p>
    <p>To test the vulnerability, use the following path or use GuardianScan:</p>
    <p>
        <code>/xss?q=</code> followed by your payload.
        <br>
        Ejemplo:
        <a href="/xss?q=%3Cscript%3Ealert('XSS')%3C/script%3E">
            /xss?q=&lt;script&gt;alert('XSS')&lt;/script&gt;
        </a>
    </p>
    """

@app.route('/xss', methods=['GET'])
def vulnerable_xss():
    # Se espera un parámetro 'q' en la URL (ej: /xss?q=payload)
    user_input = request.args.get('q', '')
    html = f"""
    <html>
        <head>
            <title>App Vulnerable a XSS</title>
        </head>
        <body>
            <h1>Resultados de búsqueda</h1>
            <p>Has buscado: {user_input}</p>
        </body>
    </html>
    """
    return html

if __name__ == '__main__':
    app.run(port=5001, debug=True)
