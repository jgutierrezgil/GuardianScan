from flask import Flask, render_template
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

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
    """
    XSS_PAYLOADS = leer_archivo_a_lista('payloads/xss_payloads.txt')
    for payload in XSS_PAYLOADS:
        try:
            response = requests.get(url + payload)
            if payload in response.text:
                return True
        except:
            pass
    return False

def check_sqli(url):
    """
    Por cada payload en la lista de payloads de SQL Injection, realiza una petición GET a la URL
    """
    SQLI_PAYLOADS = leer_archivo_a_lista('payloads/sqli_payloads.txt')
    error_keywords = ["error", "syntax", "sql"]
    for payload in SQLI_PAYLOADS:
        try:
            response = requests.get(url + payload)
            content = response.text.lower()
            if any(keyword in content for keyword in error_keywords):
                return True
        except:
            pass
    return False

if __name__ == '__main__':
    app.run(debug=True)