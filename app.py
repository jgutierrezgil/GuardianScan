from flask import Flask, render_template, request
import requests

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        url = request.form["url"]
        
        try:
            response = requests.get(url)
            if response.status_code != 200:
                return render_template("index.html", error="Website not accessible")
        except requests.exceptions.RequestException:
            return render_template("index.html", error="Could not connect to website")
        
        result = {
            "url": url,
            "xss": check_xss(url),
            "sqli": check_sqli(url)
        }
    return render_template("index.html", result=result)

def leer_archivo_a_lista(ruta_archivo):
    """
    Lee un archivo y devuelve una lista donde cada línea del archivo es un elemento.

    Parámetros:
        ruta_archivo (str): Ruta del archivo a leer.

    Retorna:
        list: Lista donde cada elemento es una línea del archivo.
    """
    try:
        # Abrir el archivo en modo lectura ('r')
        with open(ruta_archivo, 'r', encoding='utf-8') as archivo:
            # Leer todas las líneas y eliminar los saltos de línea (\n) al final de cada línea
            lineas = [linea.strip() for linea in archivo.readlines()]
        return lineas
    except FileNotFoundError:
        print(f"Error: El archivo '{ruta_archivo}' no fue encontrado.")
        return []
    except Exception as e:
        print(f"Error al leer el archivo: {e}")
        return []

def check_xss(url):
    """
    Por cada payload en la lista de payloads de XSS, realiza una petición GET a la URL
    y acumula los payloads exitosos en una lista.
    """
    XSS_PAYLOADS = leer_archivo_a_lista('payloads/xss_payloads.txt')
    xss_payload_success = []
    for payload in XSS_PAYLOADS:
        try:
            full_url = url + payload
            response = requests.get(full_url)
            if payload in response.text:
                xss_payload_success.append(payload)
                print(f"PAYLOADS XSS EXITOSOS: {xss_payload_success}")
        except Exception as e:
            print(f"Error al probar el payload '{payload}': {e}")
    if xss_payload_success:
        return xss_payload_success
    return False


def check_sqli(url):
    """
    Por cada payload en la lista de payloads de SQL Injection, realiza una petición GET a la URL
    """
    SQLI_PAYLOADS = leer_archivo_a_lista('payloads/sqli_payloads.txt')
    sqli_payload_success = []
    error_keywords = ["error", "syntax", "sql"]
    for payload in SQLI_PAYLOADS:
        try:
            response = requests.get(url + payload)
            content = response.text.lower()
            if any(keyword in content for keyword in error_keywords):
                sqli_payload_success.append(payload)
                print(f"PAYLOADS SQLI EXITOSOS: {sqli_payload_success}")
        except Exception as e:
            print(f"Error al probar el payload '{payload}': {e}")
    if sqli_payload_success:
        return sqli_payload_success
    return False

if __name__ == '__main__':
    app.run(debug=True)