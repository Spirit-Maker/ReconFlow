import requests
import json
import time
import os
import urllib3
import random
import warnings
import logging  # Added for logging
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Lock

# Security & Terminal Cleanup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# --- NEW: Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("reconflow.log"),  # Saves all logs to this file
        logging.StreamHandler()              # Prints logs to console
    ]
)
logger = logging.getLogger(__name__)

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
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        
        self.domain_locks = {}
        self.lock_manager = Lock()
        self.delay_per_domain = 1.0 
        self.total_portals_found = 0
        logger.info(f"ReconFlow initialized using index: {self.cc_index}")

    def _load_progress_dict(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                try: return json.load(f)
                except Exception as e:
                    logger.error(f"Failed to load state file: {e}")
                    return {}
        return {}

    def _get_folder(self, query):
        clean_name = query.replace("*", "").replace("/", "").replace(".", "_").strip("_")
        folder_name = f"recon_{clean_name}"
        if not os.path.exists(folder_name): 
            os.makedirs(folder_name)
            logger.info(f"Created results folder: {folder_name}")
        return folder_name

    def run_discovery(self, query, record_limit=500):
        folder = self._get_folder(query)
        raw_path = os.path.join(folder, "discovered_urls.txt")
        seen_sigs = set()
        
        if os.path.exists(raw_path):
            with open(raw_path, 'r') as f:
                for line in f:
                    p = urlparse(line.strip().lower())
                    seen_sigs.add(f"{p.netloc}{p.path}")

        page = self.query_progress.get(query, 0)
        total_saved = 0
        logger.info(f"Starting discovery for {query} at CC Page {page}")

        with open(raw_path, "a") as f:
            while True:
                if record_limit > 0 and total_saved >= record_limit: break
                params = {'url': query, 'output': 'json', 'fl': 'url', 'page': page}
                try:
                    resp = requests.get(self.api_url, params=params, timeout=25)
                    if resp.status_code == 404:
                        logger.warning(f"No more data for {query} (404 reached).")
                        break
                    if resp.status_code != 200:
                        logger.error(f"CC API Error {resp.status_code}. Retrying in 5s...")
                        time.sleep(5); continue

                    lines = resp.text.splitlines()
                    for line in lines:
                        try:
                            url = json.loads(line).get('url', '').lower()
                            if any(k in url for k in self.keywords) and not url.endswith(self.blacklist):
                                p = urlparse(url); sig = f"{p.netloc}{p.path}"
                                if sig not in seen_sigs:
                                    seen_sigs.add(sig); f.write(url + "\n")
                                    total_saved += 1
                        except: continue
                    
                    logger.info(f"Page {page} complete. Total discovered for this query: {total_saved}")
                    page += 1
                    self.query_progress[query] = page
                    with open(self.state_file, 'w') as sf: json.dump(self.query_progress, sf)
                    time.sleep(1) # Politely throttle CC API requests
                except Exception as e:
                    logger.error(f"Discovery interrupted: {e}")
                    break

    def _check_url_life(self, target_url):
        p = urlparse(target_url)
        self._smart_delay(p.netloc)
        
        # 1. Direct
        try:
            r = requests.get(target_url, headers=self.headers, timeout=6, verify=False, allow_redirects=True)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                is_form = bool(soup.find('input', {'type': 'password'}))
                return ("PORTAL" if is_form else "LIVE"), True
        except: pass

        # 2. Proxy Retries
        if self.proxy_pool:
            for attempt in range(2):
                try:
                    px = random.choice(self.proxy_pool)
                    r = requests.get(target_url, proxies={"http":px, "https":px}, headers=self.headers, timeout=10, verify=False)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'html.parser')
                        is_form = bool(soup.find('input', {'type': 'password'}))
                        return ("PORTAL" if is_form else "LIVE"), True
                except: continue
        return "DEAD", False

    def _smart_delay(self, domain):
        with self.lock_manager:
            last = self.domain_locks.get(domain, 0)
            wait = self.delay_per_domain - (time.time() - last)
            if wait > 0: time.sleep(wait)
            self.domain_locks[domain] = time.time()

    def run_validation(self, query, threads=20):
        folder = self._get_folder(query)
        raw_path = os.path.join(folder, "discovered_urls.txt")
        log_path = os.path.join(folder, "scan_history.txt")
        gold_path = os.path.join(folder, "portals_found.txt")
        subs_path = os.path.join(folder, "active_hosts.txt")

        history = set()
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                for line in f:
                    if "|" in line: history.add(line.split("|")[1].strip())

        if not os.path.exists(raw_path): 
            logger.warning(f"No URLs found to validate for {query}")
            return
        
        with open(raw_path, "r") as f:
            all_urls = list(set(line.strip() for line in f if line.strip()))

        to_validate = [u for u in all_urls if u not in history and not any(n in u for n in self.noise_words)]
        if not to_validate:
            logger.info(f"No new URLs to validate for {query}")
            return

        logger.info(f"Validating {len(to_validate)} URLs for {query}...")
        pbar = tqdm(total=len(to_validate), desc=f"Scanning {query[:15]}", ncols=70, disable=False)

        with open(log_path, "a") as log_f, open(gold_path, "a") as gold_f, open(subs_path, "a") as sub_f:
            seen_subs = set()
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self._check_url_life, u): u for u in to_validate}
                for fut in as_completed(futures):
                    url = futures[fut]
                    try:
                        res, is_live = fut.result()
                        if is_live:
                            log_f.write(f"{res} | {url}\n")
                            domain = urlparse(url).netloc
                            if domain not in seen_subs:
                                sub_f.write(domain + "\n")
                                seen_subs.add(domain)
                            if res == "PORTAL":
                                gold_f.write(url + "\n")
                                self.total_portals_found += 1
                            log_f.flush()
                    except Exception as e:
                        logger.debug(f"Error validating {url}: {e}")
                    finally: pbar.update(1)
        pbar.close()

if __name__ == "__main__":
    my_proxies = ["socks5h://127.0.0.1:31080"]
    bot = ReconFlow(proxy_list=my_proxies)
    
    targets_file = "targets.txt"
    if not os.path.exists(targets_file):
        with open(targets_file, "w") as f: f.write("*.edu/*\n")
        logger.info(f"Created {targets_file}. Add targets and restart.")
    else:
        with open(targets_file, "r") as f:
            queries = [line.strip() for line in f if line.strip()]
        
        logger.info(f"Loaded {len(queries)} target queries.")
        start_time = time.time()
        
        for q in queries:
            bot.run_discovery(q, record_limit=300)
            bot.run_validation(q, threads=25)
        
        duration = round((time.time() - start_time) / 60, 2)
        logger.info(f"Mission Complete in {duration} minutes.")
        logger.info(f"Total Portals Harvested: {bot.total_portals_found}")
