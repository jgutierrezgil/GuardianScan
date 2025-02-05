from flask import Flask, render_template, request
import requests

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        url = request.form["url"]
        # Detectar qué tipo de payload se va a usar
        payload_type = request.form.get("payload_type", "default")
        if payload_type == "custom":
            # Si se seleccionó el custom, obtener el payload ingresado
            custom_payload = request.form.get("custom_payload", "").strip()
            # Si el usuario no ingresa nada, se usa el payload por defecto
            if custom_payload:
                xss_payloads = [custom_payload]
                sqli_payloads = [custom_payload]
            else:
                xss_payloads = leer_archivo_a_lista('payloads/xss_payloads.txt')
                sqli_payloads = leer_archivo_a_lista('payloads/sqli_payloads.txt')
        else:
            # Usar payloads por defecto
            xss_payloads = leer_archivo_a_lista('payloads/xss_payloads.txt')
            sqli_payloads = leer_archivo_a_lista('payloads/sqli_payloads.txt')

        try:
            response = requests.get(url)
            if response.status_code != 200:
                return render_template("index.html", error="Website not accessible")
        except requests.exceptions.RequestException:
            return render_template("index.html", error="Could not connect to website")
        
        result = {
            "url": url,
            "xss": check_xss(url, xss_payloads),
            "sqli": check_sqli(url, sqli_payloads)
        }
    return render_template("index.html", result=result)

def leer_archivo_a_lista(ruta_archivo):
    """
    Lee un archivo y devuelve una lista donde cada línea del archivo es un elemento.
    """
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as archivo:
            lineas = [linea.strip() for linea in archivo.readlines()]
        return lineas
    except FileNotFoundError:
        print(f"Error: El archivo '{ruta_archivo}' no fue encontrado.")
        return []
    except Exception as e:
        print(f"Error al leer el archivo: {e}")
        return []

def check_xss(url, payloads):
    """
    Por cada payload en la lista, realiza una petición GET a la URL y acumula los payloads exitosos.
    """
    xss_payload_success = []
    for payload in payloads:
        try:
            full_url = url + payload
            response = requests.get(full_url)
            if payload in response.text:
                xss_payload_success.append(payload)
                # Se acumulan todos los payloads exitosos
        except Exception as e:
            print(f"Error al probar el payload '{payload}': {e}")
    if xss_payload_success:
        return xss_payload_success
    return False

def check_sqli(url, payloads):
    """
    Por cada payload en la lista, realiza una petición GET a la URL y acumula los payloads exitosos.
    Se busca que en la respuesta aparezcan palabras que indiquen un error SQL.
    """
    sqli_payload_success = []
    error_keywords = ["error", "syntax", "sql"]
    for payload in payloads:
        try:
            full_url = url + payload
            response = requests.get(full_url)
            content = response.text.lower()
            if any(keyword in content for keyword in error_keywords):
                sqli_payload_success.append(payload)
        except Exception as e:
            print(f"Error al probar el payload '{payload}': {e}")
    if sqli_payload_success:
        return sqli_payload_success
    return False

if __name__ == '__main__':
    app.run(debug=True)
