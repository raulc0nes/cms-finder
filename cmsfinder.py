import requests
import ssl
import socket
import signal
import sys
from urllib.parse import urljoin
from tqdm import tqdm
import time
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INITIAL_TIMEOUT = 5
MAX_RETRIES = 3
MAX_REDIRECTS = 5

REDIRECTION_FILTERS = [
    "error", "not found", "403", "404", "forbidden", "dns", "redirect",
    "moved permanently", "moved temporarily", "unauthorized", "blocked", 
    "prohibited", "access denied", "not available", "time out", "timeout", 
    "bad gateway", "service unavailable", "gateway timeout"
]

LOGIN_FILTERS = [
    "login", "signin", "sign in", "sign-in", "access", "entrar", "authentication",
    "log in", "logon", "enter", "submit", "username", "password", "user", "pass", 
    "account", "register", "sign up", "log in page", "authentication required"
]

def debug(msg, debug_enabled):
    if debug_enabled:
        print(f"[DEBUG] {msg}")

def error(msg, error_enabled):
    if error_enabled:
        print(f"[ERROR] {msg}")

def calculate_rtt(ip, port, error_enabled, debug_enabled):
    try:
        start_time = time.time()
        sock = socket.create_connection((ip, port), INITIAL_TIMEOUT)
        rtt = time.time() - start_time
        sock.close()
        debug(f"RTT calculado: {rtt:.4f} segundos", debug_enabled)
        return rtt
    except Exception as e:
        error(f"Error al calcular RTT: {e}", error_enabled)
        return None

def validate_ssl(ip, port, error_enabled, debug_enabled):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((ip, port), INITIAL_TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=ip)
        ssock.close()
        debug(f"SSL establecido en {ip}:{port}", debug_enabled)
        return True
    except (ssl.SSLError, ssl.SSLCertVerificationError, ConnectionRefusedError) as e:
        error(f"No se pudo establecer SSL en {ip}:{port}: {e}", error_enabled)
        return False

def fetch_url(url, timeout, retries, error_enabled, debug_enabled, redirects=0):
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
        if response.is_redirect and redirects < MAX_REDIRECTS:
            new_url = response.headers.get('Location')
            if not new_url.startswith('http'):
                new_url = urljoin(url, new_url)
            debug(f"Redirección detectada a {new_url}", debug_enabled)
            return fetch_url(new_url, timeout, retries, error_enabled, debug_enabled, redirects + 1)
        return response
    except requests.exceptions.RequestException as e:
        error(f"Error al intentar conectar con {url}: {e}", error_enabled)
        if "Connection refused" in str(e):
            return None
    return None

def validate_url(ip, port, path, timeout, retries, ssl_supported, error_enabled, debug_enabled):
    protocol = "https" if ssl_supported else "http"
    base_url = f"{protocol}://{ip}:{port}/"
    full_url = urljoin(base_url, path)
    
    debug(f"Validando URL: {full_url}", debug_enabled)
    response = fetch_url(full_url, timeout, retries, error_enabled, debug_enabled)
    if response:
        status_code = response.status_code
        content = response.text

        if status_code == 200:
            login_detected = check_filters(content, LOGIN_FILTERS)

            if login_detected:
                indicio = "Login Detectado"
            else:
                indicio = "Página Válida sin Login"

            debug(f"Página válida detectada en {full_url}", debug_enabled)
            return full_url, status_code, indicio

        redirection_detected = check_filters(content, REDIRECTION_FILTERS)
        if redirection_detected:
            debug(f"Redirección no deseada detectada en {full_url}", debug_enabled)
            return None
    
    return None

def check_filters(content, filters):
    if content:
        for word in filters:
            if word.lower() in content.lower():
                return True
    return False

def process_urls(ip, port, error_enabled, debug_enabled):
    rtt = calculate_rtt(ip, port, error_enabled, debug_enabled)
    if rtt is None:
        return
    dynamic_timeout = max(INITIAL_TIMEOUT, rtt * 2)
    dynamic_retries = min(MAX_RETRIES, int(10 / rtt))
    dynamic_retries = max(1, dynamic_retries)
    
    ssl_supported = validate_ssl(ip, port, error_enabled, debug_enabled)
    
    debug(f"Timeout dinámico establecido: {dynamic_timeout:.2f} segundos", debug_enabled)
    debug(f"Reintentos dinámicos establecidos: {dynamic_retries}", debug_enabled)

    with open('cmslist.txt', 'r') as file:
        paths = file.readlines()

    validated_urls = set()  # Para evitar duplicados

    for path in tqdm(paths, desc="Procesando URLs"):
        path = path.strip()
        result = validate_url(ip, port, path, dynamic_timeout, dynamic_retries, ssl_supported, error_enabled, debug_enabled)
        if result:
            full_url, status_code, indicio = result
            if full_url not in validated_urls:  # Verifica si ya se ha validado antes
                validated_urls.add(full_url)  # Añade a la lista de URLs validadas
                with open('urls_verificadas.txt', 'a') as output_file:
                    output_file.write(f"{full_url} - Status Code: {status_code} - Indicio: {indicio}\n")
                print(f"[+] URL validada: {full_url} - Status Code: {status_code} - Indicio: {indicio}")

def signal_handler(sig, frame):
    print("\n[INFO] Proceso interrumpido por el usuario. Saliendo...")
    sys.exit(0)

if __name__ == "__main__":
    # Captura la señal de interrupción
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Escáner de URLs para detectar páginas de login de CMS.")
    parser.add_argument("ip", help="Dirección IP del servidor objetivo")
    parser.add_argument("port", type=int, help="Puerto del servidor objetivo")
    parser.add_argument("--errores", action="store_true", help="Mostrar mensajes de error")
    parser.add_argument("--debug", action="store_true", help="Mostrar mensajes de depuración")

    args = parser.parse_args()

    start_time = time.time()
    print(f"Estableciendo conexión con {args.ip}:{args.port}...")
    process_urls(args.ip, args.port, args.errores, args.debug)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Escáner finalizado. Tiempo de ejecución: {time.strftime('%H:%M:%S', time.gmtime(elapsed_time))}")

