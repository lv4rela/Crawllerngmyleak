from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import re
import os
import csv
import json
import time
import argparse
import requests
from urllib.parse import urljoin
from functools import partial
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from multiprocessing import Pool, cpu_count
from datetime import datetime

init(autoreset=True)
# recursos sao baixados via requests (sem verificar TLS de host mal configurado)
requests.packages.urllib3.disable_warnings()

def initialize_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    # liga o log de rede (CDP) pra capturar TODOS os recursos que a pagina chamar
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    return webdriver.Chrome(options=options)

def _safe_attr(el, attr):
    try:
        return el.get_attribute(attr)
    except Exception:
        return None  # elemento ficou stale / foi removido do DOM

def short_err(e):
    # fica so com a parte util da mensagem, sem o stacktrace do chromedriver
    return str(e).split('Stacktrace')[0].split('(Session info')[0].strip()

def fetch_js_files(driver, url):
    js_files = []
    try:
        script_elements = driver.find_elements(By.TAG_NAME, "script")
        link_elements = driver.find_elements(By.XPATH, "//link[@rel='preload' and @as='script']")
        for el in script_elements:
            src = _safe_attr(el, 'src')
            if src and src.endswith('.js'):
                js_files.append(src)
        for el in link_elements:
            href = _safe_attr(el, 'href')
            if href and href.endswith('.js'):
                js_files.append(href)
    except Exception:
        return []  # DOM mudou/pagina instavel: os recursos ja vem do log de rede (CDP)

    js_files = list(set(filter(None, js_files)))
    return [urljoin(url, js_file) for js_file in js_files]

def extract_sensitive_info(content, source):
    patterns = {
        #'AWS API Key': r'AKIA[0-9A-Z]{16}',
        #'Amazon MWS Auth Token': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        #'AWS S3 Bucket': r's3://[0-9a-z._/-]+',
        #'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
        #'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        #'Google OAuth': r'ya29\\.[0-9A-Za-z\\-_]+',
        #'JWT': r'eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*',
        #'OpenAI API Key': r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
        #'Github-1': r'\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b)',
        #'Github App Token': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
        #'Github OAuth Access Token': r'gho_[0-9a-zA-Z]{36}',
        #'Token':r'\"token\"\s*:\s*\"([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)\"',
        #'Token2': r'\"token\"\s*:\s*\"([a-zA-Z0-9/_-]{20,})\"',
        #'Generic API_1': r'\"x-api-key\"\s*:\s*\"([a-zA-Z0-9]{20,})\"',
        #'Generic API_2': r'\"api-key\"\s*:\s*\"([a-zA-Z0-9]{20,})\"',
        #'Generic API_3': r'\"apikey\"\s*:\s*\"([a-zA-Z0-9]{20,})\"',
        #'userPoolClientId': r'userPoolClientId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        #'userPoolId': r'userPoolId["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+_[a-zA-Z0-9-_]+)["\']',
        #'client_id': r'client_id["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        #'IdentityPoolId': r'IdentityPoolId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        #'userPoolWebClientId': r'userPoolWebClientId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        #'cognitoUserPoolClientId': r'cognitoUserPoolClientId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        #'cognitoUserPoolId': r'cognitoUserPoolId["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+_[a-zA-Z0-9-_]+)["\']',
        #'aws_cognito_identity_pool_id': r'aws_cognito_identity_pool_id["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+:[0-9a-fA-F-]+)["\']',
        #'identity_pool_id': r'identity_pool_id["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+:[0-9a-fA-F-]+)["\']',
        #'Vercel OIDC Token': r'VERCEL_OIDC_TOKEN\s*:\s*"(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)"',
        #'Vercel Build Containers Token': r'VERCEL_API_BUILD_CONTAINERS_TOKEN\s*:\s*"([A-Za-z0-9_-]{16,})"',
        #'Vercel Project ID': r'VERCEL_PROJECT_ID\s*:\s*"(prj_[A-Za-z0-9]{20,})"',
        #'Vercel Api Build Containers Endpoint': r'VERCEL_API_BUILD_CONTAINERS_ENDPOINT\s*:\s*"(https://[A-Za-z0-9._/\-]+)"',
        #'Vercel Artifacts Token': r'VERCEL_ARTIFACTS_TOKEN\s*:\s*"(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)"',
        #'Vercel Org ID': r'VERCEL_ORG_ID\s*:\s*"(team_[A-Za-z0-9]{20,})"',
        #'Runtime Cache Authorization JWT': r'RUNTIME_CACHE_HEADERS\s*:\s*\'\{[^}]*"Authorization"\s*:\s*"Bearer\s+(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)"',
        #'UUID Key': r'(?:api[_-]?key|token|secret|client[_-]?id)["\']?\s*[:=]\s*["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']',
    

    }

    sensitive_info = {key: set(re.findall(pattern, content)) for key, pattern in patterns.items()}

    findings = []
    if any(sensitive_info.values()):
        ts = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        print(f"{Fore.GREEN}\n[FOUND - {ts}]: {Fore.WHITE}{source}")
        for key, values in sensitive_info.items():
            if values:
                for value in values:
                    print(f"{Fore.MAGENTA}{key}: {Fore.WHITE}{value}")
                    findings.append({'timestamp': ts, 'type': key, 'value': value, 'url': source})
    return findings

PAGE_WAIT = 4        # segundos de espera pra pagina disparar XHR/fetch dinamicos
FETCH_THREADS = 16   # downloads de recursos em paralelo por pagina
FETCH_TIMEOUT = 15   # timeout (s) por recurso

def build_session(driver):
    """Sessao requests herdando cookies e User-Agent do browser (mantem auth)."""
    session = requests.Session()
    try:
        for c in driver.get_cookies():
            session.cookies.set(c.get('name'), c.get('value'), domain=c.get('domain'))
    except Exception:
        pass
    try:
        ua = driver.execute_script("return navigator.userAgent")
        if ua:
            session.headers.update({'User-Agent': ua})
    except Exception:
        pass
    return session

def fetch_resource(session, target):
    """Baixa um recurso via HTTP (muito mais rapido que dirigir o browser)."""
    try:
        resp = session.get(target, timeout=FETCH_TIMEOUT, verify=False)
        return target, resp.text, None
    except Exception as e:
        return target, None, short_err(e)

# extensoes binarias/visuais que nao vale a pena escanear
SKIP_EXT = ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.otf', '.eot',
            '.mp4', '.webm', '.mp3', '.css', '.map')

def is_scannable(u):
    if not u.startswith('http'):
        return False
    path = u.lower().split('?')[0].split('#')[0]
    return not path.endswith(SKIP_EXT)

def collect_requested_urls(driver):
    """Le o log de performance (CDP) e devolve toda URL que o navegador requisitou."""
    urls = set()
    try:
        logs = driver.get_log('performance')
    except Exception:
        return urls
    for entry in logs:
        try:
            msg = json.loads(entry['message'])['message']
        except Exception:
            continue
        params = msg.get('params', {})
        if msg.get('method') == 'Network.requestWillBeSent':
            u = params.get('request', {}).get('url')
        elif msg.get('method') == 'Network.responseReceived':
            u = params.get('response', {}).get('url')
        else:
            continue
        if u:
            urls.add(u)
    return urls

def process_page(url, wait=PAGE_WAIT, threads=FETCH_THREADS):
    driver = initialize_driver()
    url = ensure_http_prefix(url)
    findings = []
    try:
        driver.get(url)
        time.sleep(wait)  # deixa os requests dinamicos dispararem
        main_content = driver.page_source
        findings += extract_sensitive_info(main_content, url)

        # tudo que a pagina chamou (XHR, fetch, /_v/, api, .json, js...) + <script src>
        requested = collect_requested_urls(driver)
        js_files = set(fetch_js_files(driver, url))
        targets = js_files | {u for u in requested if is_scannable(u)}

        # baixa os recursos em paralelo via HTTP (herdando cookies/UA do browser).
        # o regex roda na thread principal pra nao embaralhar a saida do console.
        session = build_session(driver)
        if targets:
            with ThreadPoolExecutor(max_workers=min(threads, len(targets))) as ex:
                futures = {ex.submit(fetch_resource, session, t): t for t in targets}
                for fut in as_completed(futures):
                    target, text, err = fut.result()
                    if err:
                        print(f"{Fore.RED}Error fetching resource: {Fore.WHITE}{target} - {err}")
                    elif text:
                        findings += extract_sensitive_info(text, target)
    except Exception as e:
        print(f"{Fore.RED}Error fetching main page: {Fore.WHITE}{url} - {short_err(e)}")
    finally:
        driver.quit()
    return findings

def ensure_http_prefix(url):
    return 'https://' + url if not url.startswith(('http://', 'https://')) else url

def main_menu():
    ninja_ascii = r'''
             ___                 _ _                             _          _   
            / __|_ _ __ ___ __ _| | |___ _ _ _ _  __ _ _ __ _  _| |___ __ _| |__
           | (__| '_/ _` \ V  V / | / -_) '_| ' \/ _` | '  \ || | / -_) _` | / /
            \___|_| \__,_|\_/\_/|_|_\___|_| |_||_\__, |_|_|_\_, |_\___\__,_|_\_\
                                       |___/      |__/                
        '''
    print(f"{Fore.CYAN}{ninja_ascii}")
    print(f"{Fore.YELLOW}[INFO] - Welcome to Crawllermyleak - Search for secrets in JS files")
    print(f"{Fore.YELLOW}[INFO] - Author: {Fore.WHITE}@lv4rela")
    print(f"{Fore.YELLOW}[INFO] - Date: {Fore.WHITE}{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")

    parser = argparse.ArgumentParser(description='Cogcrowling- HELP')
    parser.add_argument("-u", "--url", help="The URL of the web page to crawl")
    parser.add_argument("-f", "--file", help="A file containing a list of URLs to crawl")
    parser.add_argument("-o", "--output", default="results.csv", help="CSV file to save results (default: results.csv)")
    parser.add_argument("-p", "--processes", type=int, default=None,
                        help="Paginas processadas em paralelo (default: nº de CPUs)")
    parser.add_argument("-t", "--threads", type=int, default=FETCH_THREADS,
                        help=f"Downloads de recursos em paralelo por pagina (default: {FETCH_THREADS})")
    parser.add_argument("-w", "--wait", type=float, default=PAGE_WAIT,
                        help=f"Espera (s) pra pagina disparar XHR dinamicos (default: {PAGE_WAIT})")
    args = parser.parse_args()

    if args.url:
        urls = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File {args.file} not found.")
            return
    else:
        print(f"{Fore.YELLOW}INFO: Please provide either a URL with -u or a file with -f.")
        return

    # escala com a maquina: 1 processo por CPU, mas nunca mais que o nº de URLs
    max_processes = args.processes or cpu_count()
    max_processes = max(1, min(max_processes, len(urls)))
    worker = partial(process_page, wait=args.wait, threads=args.threads)
    print(f"{Fore.YELLOW}[INFO] {len(urls)} URL(s) | {max_processes} processo(s) | "
          f"{args.threads} thread(s)/pagina | wait {args.wait}s\n")
    with Pool(processes=max_processes) as pool:
        results = pool.map(worker, urls)

    # achata os resultados de todos os processos e remove duplicatas
    all_findings = []
    seen = set()
    for sub in results:
        for f in sub:
            dedup_key = (f['type'], f['value'], f['url'])
            if dedup_key not in seen:
                seen.add(dedup_key)
                all_findings.append(f)

    if all_findings:
        output = args.output
        # se apontou pra uma pasta, grava um results.csv dentro dela
        if os.path.isdir(output):
            output = os.path.join(output, 'results.csv')
        try:
            parent = os.path.dirname(output)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(output, 'w', newline='', encoding='utf-8') as fp:
                writer = csv.DictWriter(fp, fieldnames=['timestamp', 'type', 'value', 'url'])
                writer.writeheader()
                writer.writerows(all_findings)
            print(f"{Fore.GREEN}\n[INFO] {len(all_findings)} resultado(s) salvo(s) em {Fore.WHITE}{output}")
        except OSError as e:
            # nao perde os achados: imprime na tela como fallback
            print(f"{Fore.RED}\n[ERRO] Nao consegui gravar em '{output}': {e}")
            print(f"{Fore.YELLOW}[INFO] Resultados (fallback):")
            print("timestamp,type,value,url")
            for f in all_findings:
                print(f"{f['timestamp']},{f['type']},{f['value']},{f['url']}")
    else:
        print(f"{Fore.YELLOW}\n[INFO] Nenhum resultado encontrado.")

if __name__ == "__main__":
    main_menu()
