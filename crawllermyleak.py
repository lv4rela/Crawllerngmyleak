from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
import re
import argparse
from urllib.parse import urljoin
from colorama import Fore, init
from multiprocessing import Pool

init(autoreset=True)

def initialize_driver():
    options = Options()
    options.add_argument("--headless") 
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    service = Service("/usr/local/bin/geckodriver")
    return webdriver.Firefox(service=service, options=options)

def fetch_js_files(driver, url):
    driver.get(url)
    script_elements = driver.find_elements(By.TAG_NAME, "script")
    link_elements = driver.find_elements(By.XPATH, "//link[@rel='preload' and @as='script']")
    
    js_files = [script.get_attribute('src') for script in script_elements if script.get_attribute('src') and script.get_attribute('src').endswith('.js')]
    js_files.extend([link.get_attribute('href') for link in link_elements if link.get_attribute('href').endswith('.js')])

    js_files = list(set(filter(None, js_files))) 
    return [urljoin(url, js_file) for js_file in js_files]

def extract_sensitive_info(content, source):
    patterns = {
        'AWS API Key': r'AKIA[0-9A-Z]{16}',
        'Amazon MWS Auth Token': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'AWS S3 Bucket': r's3://[0-9a-z._/-]+',
        'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
        'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        'Google OAuth': r'ya29\\.[0-9A-Za-z\\-_]+',
        'JWT': r'eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*',
        'OpenAI API Key': r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
        'Github-1': r'\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b)',
        'Github App Token': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
        'Github OAuth Access Token': r'gho_[0-9a-zA-Z]{36}',
        'Token':r'\"token\"\s*:\s*\"([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)\"',
        'Token': r'\"token\"\s*:\s*\"([a-zA-Z0-9/_-]{20,})\"',
        'Generic API_1': r'\"x-api-key\"\s*:\s*\"([a-zA-Z0-9]{20,})\"',
        'Generic API_2': r'\"api-key\"\s*:\s*\"([a-zA-Z0-9]{20,})\"',
        'Generic API_3': r'\"apikey\"\s*:\s*\"([a-zA-Z0-9]{20,})\"',
        'userPoolClientId': r'userPoolClientId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        'userPoolId': r'userPoolId["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+_[a-zA-Z0-9-_]+)["\']',
        'client_id': r'client_id["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        'IdentityPoolId': r'IdentityPoolId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        'userPoolWebClientId': r'userPoolWebClientId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        'cognitoUserPoolClientId': r'cognitoUserPoolClientId["\']?\s*:\s*["\']([a-zA-Z0-9-_]+)["\']',
        'cognitoUserPoolId': r'cognitoUserPoolId["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+_[a-zA-Z0-9-_]+)["\']',
        'aws_cognito_identity_pool_id': r'aws_cognito_identity_pool_id["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+:[0-9a-fA-F-]+)["\']',
        'identity_pool_id': r'identity_pool_id["\']?\s*:\s*["\']([a-z]{2}-[a-z]+-\d+:[0-9a-fA-F-]+)["\']'

    }

    sensitive_info = {key: set(re.findall(pattern, content)) for key, pattern in patterns.items()}

    if any(sensitive_info.values()):
        print(f"{Fore.GREEN}\n[FOUND]: {Fore.WHITE}{source}")
        for key, values in sensitive_info.items():
            if values:
                for value in values:
                    print(f"{Fore.MAGENTA}{key}: {Fore.WHITE}{value}")

def process_page(url):
    driver = initialize_driver()
    url = ensure_http_prefix(url)
    try:
        driver.get(url)
        main_content = driver.page_source
        extract_sensitive_info(main_content, url)

        js_files = fetch_js_files(driver, url)
        for js_file in js_files:
            try:
                driver.get(js_file)
                js_content = driver.page_source
                extract_sensitive_info(js_content, js_file)
            except Exception as e:
                print(f"{Fore.RED}Error fetching JS file: {Fore.WHITE}{js_file} - {e}")
    except Exception as e:
        print(f"{Fore.RED}Error fetching main page: {Fore.WHITE}{url} - {e}")
    finally:
        driver.quit()

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
    print(f"{Fore.YELLOW}[INFO] - Welcome to Cogcrowling - Search for cognito data in JS files")
    print(f"{Fore.YELLOW}[INFO] - Author: {Fore.WHITE}@lv4rela\n")

    parser = argparse.ArgumentParser(description='Cogcrowling- HELP')
    parser.add_argument("-u", "--url", help="The URL of the web page to crawl")
    parser.add_argument("-f", "--file", help="A file containing a list of URLs to crawl")
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

    max_processes = 10  #maximos simultaneous process
    with Pool(processes=max_processes) as pool:
        pool.map(process_page, urls)

if __name__ == "__main__":
    main_menu()
