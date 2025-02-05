from flask import Flask, request
app = Flask(__name__)

# Endpoint de ayuda para la ruta raíz
@app.route("/", methods=["GET"])
def index():
    return """
    <h1>Bienvenido a la aplicación vulnerable a XSS</h1>
    <p>Esta aplicación es vulnerable a Cross-Site Scripting (XSS).</p>
    <p>Para probar la vulnerabilidad, utiliza la siguiente ruta:</p>
    <p>
        <code>/xss?q=</code> seguido de tu payload.
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
    # ¡Vulnerabilidad! Se refleja el input del usuario sin ningún escape.
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
