from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for

import requests

app = Flask(__name__)
# Variable global para almacenar el resultado del último escaneo
last_scan_data = None

@app.route("/", methods=["GET", "POST"])
def index():
    """
    Handles the primary route for the application, performing security scans
    (XSS and SQL injection) on a user-provided URL.

    This function:
    1. Retrieves the target URL and payload preference (default or custom)
       from the POST request form.
    2. Validates connectivity to the target URL.
    3. Uses a crawler to gather all internal links up to a given depth.
    4. Scans each discovered link for potential XSS (using GET parameters)
       and SQL injection vulnerabilities.
    5. Stores the scan results in a global variable (`last_scan_data`) and
       renders the results in the `index.html` template.

    Returns:
        A rendered template "index.html" with:
            - An empty result dictionary if the request is GET.
            - A dictionary (`result`) containing the scanned URL and
              any vulnerability findings if the request is POST.
            - An error message if the target URL is not accessible.

    Global Variables:
        last_scan_data (dict): A global variable used to store the
            most recent scan results.

    Form Data:
        url (str): The URL to be scanned.
        payload_type (str): Indicates whether default or custom payloads
            should be used ("default" or "custom").
        custom_payload (str, optional): The custom payload string
            provided by the user when `payload_type` is "custom".

    Example:
        If the user posts the form with:
            url = "http://example.com"
            payload_type = "default"
        The function will:
            1. Read default payloads from local files.
            2. Crawl and scan "http://example.com" and its internal links.
            3. Return a rendered page summarizing any detected vulnerabilities.
    """
    global last_scan_data
    
    result = {}
    
    if request.method == "POST":
        url = request.form["url"]
        payload_type = request.form.get("payload_type", "default")

        if payload_type == "custom":
            custom_payload = request.form.get("custom_payload", "").strip()
            if custom_payload:
                xss_payloads = [custom_payload]
                sqli_payloads = [custom_payload]
            else:
                xss_payloads = leer_archivo_a_lista('payloads/xss_payloads.txt')
                sqli_payloads = leer_archivo_a_lista('payloads/sqli_payloads.txt')
        else:
            xss_payloads = leer_archivo_a_lista('payloads/xss_payloads.txt')
            sqli_payloads = leer_archivo_a_lista('payloads/sqli_payloads.txt')

        # Check if the URL is accessible
        try:
            response = requests.get(url)
            if response.status_code != 200:
                return render_template("index.html", error="Website not accessible")
        except requests.exceptions.RequestException:
            return render_template("index.html", error="Could not connect to website")

        # 1) Crawl all internal links of the given domain
        all_links = crawl(url, max_depth=2)

        # 2) Scan each discovered link for XSS and SQLi
        scanned_data = []
        for link in all_links:
            xss_result = check_xss_get(link, xss_payloads)
            sqli_result = check_sqli_get(link, sqli_payloads)

            scanned_data.append({
                "url": link,
                "xss_get": xss_result,
                "sqli_get": sqli_result
            })

        # 3) Build the result dictionary for the template
        result = {
            "url": url,
            "scanned_data": scanned_data
        }
        
        # Store in the global variable
        last_scan_data = result

    return render_template("index.html", result=result)


@app.route("/report")
def report():
    """
    Displays the final report using a separate template (report_template.html).
    Returns:
        tuple: If no scan data is available, returns error message and 400 status code
        template: Renders report_template.html with last scan data if available
    Global Variables:
        last_scan_data: Contains the data from the most recent scan
    Template Variables:
        result: Passes the scan data to the template for display
    """
    global last_scan_data
    
    if not last_scan_data:
        return "No hay datos de escaneo disponibles.", 400

    # Renderizamos la plantilla de reporte con los datos guardados
    return render_template("report_template.html", result=last_scan_data)

def crawl(start_url, max_depth=2):
    """
    Crawls the domain of `start_url` up to a specified `max_depth`.

    This function performs a breadth-first search (BFS) crawl starting from the
    given `start_url`. It retrieves the HTML content of each page, extracts all
    <a> tags, converts relative links to absolute URLs, and follows only the
    links that belong to the same domain. It stops when it either reaches the
    `max_depth` or runs out of new URLs to visit. The function returns a set
    of all the URLs visited during the crawl.

    Args:
        start_url (str): The initial URL to start crawling.
        max_depth (int, optional): The maximum depth of links to follow.
            Defaults to 2.

    Returns:
        set: A set containing all the discovered URLs within the same domain.

    Example:
        >>> urls = crawl("https://example.com", max_depth=2)
        >>> for link in urls:
        ...     print(link)
    """
    to_visit = [(start_url, 0)]  # Queue of (url, current_depth)
    visited = set()

    while to_visit:
        current_url, depth = to_visit.pop(0)

        # Stop if we exceed the maximum depth
        if depth > max_depth:
            continue

        # Skip if this URL has already been visited
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            response = requests.get(current_url, timeout=5)
            if response.status_code != 200:
                continue
        except requests.exceptions.RequestException:
            # Network error, timeout, etc.
            continue

        # Parse the HTML content
        soup = BeautifulSoup(response.text, "html.parser")

        # Find all <a> tags with an 'href' attribute
        for link_tag in soup.find_all("a", href=True):
            href = link_tag["href"]
            # Convert relative link to absolute URL
            full_url = urljoin(current_url, href)

            # Only follow links from the same domain
            if urlparse(full_url).netloc == urlparse(start_url).netloc:
                to_visit.append((full_url, depth + 1))

    return visited

def leer_archivo_a_lista(ruta_archivo):
    """
    Reads a text file and returns its content as a list of lines.
    This function opens a specified text file, reads all its lines,
    removes leading and trailing whitespace from each line,
    and returns a list with the content.
    Args:
        ruta_archivo (str): Path to the file to be read.
    Returns:
        list: List of strings where each element is a line from the file.
              Returns an empty list if there is any error reading the file.
    Raises:
        FileNotFoundError: If the specified file does not exist.
        Exception: For any other error that occurs during reading.
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

def check_xss_get(url, payloads):
    """
    Test a URL for XSS vulnerabilities using GET requests with provided payloads.
    This function attempts to identify Cross-Site Scripting (XSS) vulnerabilities by sending
    GET requests with different XSS payloads and checking if they are reflected in the response.
    Args:
        url (str): The base URL to test for XSS vulnerabilities
        payloads (list): A list of XSS payload strings to test
    Returns:
        list or bool: Returns a list of successful payloads if any XSS vulnerabilities are found,
                     otherwise returns False if no vulnerabilities are detected
    Raises:
        Catches and prints any exceptions that occur during the requests, but does not raise them
    """
    
    xss_payload_success = []
    for payload in payloads:
        try:
            full_url = url + payload
            response = requests.get(full_url)
            if payload in response.text:
                # Se acumulan todos los payloads exitosos
                xss_payload_success.append(payload)
        except Exception as e:
            print(f"Error al probar el payload '{payload}': {e}")
    if xss_payload_success:
        return xss_payload_success
    return False

def check_sqli_get(url, payloads):
    """
    Test a URL for SQL injection vulnerabilities using GET requests with different payloads.

    This function attempts SQL injection by appending payloads to the URL and analyzing 
    the responses for SQL error messages.

    Args:
        url (str): The base URL to test for SQL injection vulnerabilities
        payloads (list): List of SQL injection payload strings to test

    Returns:
        list: List of successful payloads that triggered SQL errors
        bool: False if no payloads were successful

    Raises:
        Any exceptions from the GET request are caught and printed

    Example:
        payloads = ["'", "1' OR '1'='1"]
        results = check_sqli_get("http://example.com/page?id=", payloads)
        if results:
            print("Found vulnerable payloads:", results)
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
