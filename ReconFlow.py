import requests
import json
import time
import os
import urllib3
import random
import warnings
import logging
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Lock

# Security & Terminal Cleanup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# --- NEW: Tqdm-Compatible Logging ---
class TqdmLoggingHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg) # This prevents the log from breaking the progress bar
            self.flush()
        except Exception:
            self.handleError(record)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', '%H:%M:%S')

# File logging
file_handler = logging.FileHandler("reconflow.log")
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

# Console logging (Tqdm-aware)
console_handler = TqdmLoggingHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

class ReconFlow:
    def __init__(self, proxy_list=None):
        self.cc_index = "CC-MAIN-2026-04" 
        self.api_url = f"http://index.commoncrawl.org/{self.cc_index}-index"
        
        self.keywords = ['login', 'signin', 'auth', 'admin', 'portal', 'dashboard', 'account', 'register']
        self.blacklist = ('.jpg', '.png', '.css', '.js', '.pdf', '.svg', '.zip', '.docx', '.gif')
        self.noise_words = ['/news/', '/blog/', '/help/', '/faq/', '/terms/', '/privacy/']
        
        self.state_file = "recon_state.json"
        self.query_progress = self._load_progress_dict()
        self.proxy_pool = proxy_list if proxy_list else []
        self.ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        ]
        
        self.domain_locks = {}
        self.lock_manager = Lock()
        self.delay_per_domain = 1.2 
        self.total_portals_found = 0
        logger.info(f"ReconFlow initialized. Mode: Proxy-First. Index: {self.cc_index}")

    def _load_progress_dict(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                try: return json.load(f)
                except: return {}
        return {}

    def _get_folder(self, query):
        clean_name = query.replace("*", "").replace("/", "").replace(".", "_").strip("_")
        folder_name = f"recon_{clean_name}"
        if not os.path.exists(folder_name): 
            os.makedirs(folder_name)
        return folder_name

    def _check_url_life(self, target_url):
        p = urlparse(target_url)
        self._smart_delay(p.netloc)
        headers = {"User-Agent": random.choice(self.ua_list)}
        
        # --- PHASE 1: PROXY FIRST ---
        if self.proxy_pool:
            px = random.choice(self.proxy_pool)
            try:
                r = requests.get(target_url, proxies={"http":px, "https":px}, headers=headers, timeout=10, verify=False, allow_redirects=True)
                if r.status_code == 200:
                    return self._analyze_content(r.text), True
                logger.debug(f"Proxy {px} returned {r.status_code} for {target_url}")
            except Exception as e:
                logger.debug(f"Proxy Attempt Failed for {target_url} via {px}: {str(e)[:50]}")

        # --- PHASE 2: RAW FALLBACK ---
        try:
            r = requests.get(target_url, headers=headers, timeout=7, verify=False, allow_redirects=True)
            if r.status_code == 200:
                return self._analyze_content(r.text), True
            elif r.status_code in [403, 401]:
                return "LOCKED/WAF", True
        except Exception as e:
            logger.debug(f"Raw connection failed for {target_url}: {str(e)[:50]}")
            
        return "DEAD", False

    def _analyze_content(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        # Check for password fields or common portal indicators
        is_form = bool(soup.find('input', {'type': 'password'}))
        return "PORTAL" if is_form else "LIVE"

    def _smart_delay(self, domain):
        with self.lock_manager:
            last = self.domain_locks.get(domain, 0)
            wait = self.delay_per_domain - (time.time() - last)
            if wait > 0: time.sleep(wait)
            self.domain_locks[domain] = time.time()

    def run_discovery(self, query, record_limit=500):
        folder = self._get_folder(query)
        raw_path = os.path.join(folder, "discovered_urls.txt")
        seen_sigs = set()
        
        page = self.query_progress.get(query, 0)
        total_saved = 0

        with open(raw_path, "a") as f:
            while total_saved < record_limit:
                params = {'url': query, 'output': 'json', 'fl': 'url', 'page': page}
                try:
                    resp = requests.get(self.api_url, params=params, timeout=25)
                    if resp.status_code == 404: break
                    if resp.status_code != 200:
                        logger.error(f"CC API Error {resp.status_code}. Sleeping...")
                        time.sleep(10); continue

                    lines = resp.text.splitlines()
                    for line in lines:
                        url = json.loads(line).get('url', '').lower()
                        if any(k in url for k in self.keywords) and not url.endswith(self.blacklist):
                            f.write(url + "\n")
                            total_saved += 1
                    
                    logger.info(f"[{query}] Crawled Page {page} | Found {total_saved} unique URLs")
                    page += 1
                    self.query_progress[query] = page
                    with open(self.state_file, 'w') as sf: json.dump(self.query_progress, sf)
                except Exception as e:
                    logger.error(f"Discovery Error: {e}")
                    break

    def run_validation(self, query, threads=20):
        folder = self._get_folder(query)
        raw_path = os.path.join(folder, "discovered_urls.txt")
        gold_path = os.path.join(folder, "portals_found.txt")

        if not os.path.exists(raw_path): return
        
        with open(raw_path, "r") as f:
            to_validate = list(set(line.strip() for line in f if line.strip()))

        pbar = tqdm(total=len(to_validate), desc=f"Validating {query}", unit="url", ncols=100)

        with open(gold_path, "a") as gold_f:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self._check_url_life, u): u for u in to_validate}
                for fut in as_completed(futures):
                    url = futures[fut]
                    res, is_live = fut.result()
                    if is_live:
                        if res == "PORTAL":
                            logger.info(f"FOUND PORTAL: {url}") # This now prints above the bar!
                            gold_f.write(url + "\n")
                            self.total_portals_found += 1
                        else:
                            logger.info(f"Live Asset: {url}")
                    pbar.update(1)
        pbar.close()

if __name__ == "__main__":
    # Example Proxy: socks5h (dns handled by proxy)
    proxies = ["socks5h://127.0.0.1:31080"] 
    bot = ReconFlow(proxy_list=proxies)
    
    targets = ["*.edu/*", "*.gov/*"] # Can be expanded to read targets.txt
    for q in targets:
        bot.run_discovery(q, record_limit=100)
        bot.run_validation(q, threads=15)
    
    logger.info(f"Scan complete. Total Portals: {bot.total_portals_found}")
