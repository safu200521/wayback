#!/usr/bin/env python3
"""
Multi-Source URL Grabber
Discovers URLs from Wayback Machine, Common Crawl, and urlscan.io.

Input logic:
  - Domain (e.g. something.com)  
    grabs URLs for domain + ALL subdomains
  - URL (e.g. https://aaa.something.com/)  
    grabs URLs ONLY for aaa.something.com

Status code handling:
  By default: NO status filter (all archived URLs included)
  --status-filter 200        Only HTTP 200 responses
  --no-redirects             Same as --status-filter 200

Resume support:
  --resume flag reloads progress from previous interrupted run.

Pause/Resume:
  Press ENTER at any time to pause. Press ENTER again to resume.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse
from datetime import datetime
from urllib.parse import urlparse
import time
import json
import hashlib
import threading
import concurrent.futures
import sys
import os


# ============================================================
# PAUSE CONTROLLER
# ============================================================

class PauseController:
    def __init__(self):
        self._paused = False
        self._lock = threading.Lock()
        self._resume_event = threading.Event()
        self._resume_event.set()
        self._running = True
        self._enabled = False
        self._pause_time = None

    def start(self):
        if not sys.stdin.isatty():
            return
        self._enabled = True
        thread = threading.Thread(target=self._monitor, daemon=True)
        thread.start()

    def _monitor(self):
        while self._running:
            try:
                sys.stdin.readline()
                with self._lock:
                    if self._paused:
                        elapsed = ""
                        if self._pause_time:
                            secs = int(time.time() - self._pause_time)
                            elapsed = f" (paused for {secs}s)"
                        self._paused = False
                        self._pause_time = None
                        self._resume_event.set()
                        print(f"\n  [>] RESUMED{elapsed}\n")
                    else:
                        self._paused = True
                        self._pause_time = time.time()
                        self._resume_event.clear()
                        now = datetime.now().strftime('%H:%M:%S')
                        print(f"\n  [||] PAUSED at {now} - press ENTER to resume\n")
            except (EOFError, OSError):
                break

    def check(self):
        if not self._enabled:
            return
        self._resume_event.wait()

    def is_paused(self):
        with self._lock:
            return self._paused

    def stop(self):
        self._running = False
        self._resume_event.set()


pause = PauseController()


# ============================================================
# CONFIG LOADER
# ============================================================

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')


def load_config(config_path=None):
    path = config_path or DEFAULT_CONFIG_PATH
    config = {
        'api_keys': {'urlscan': ''},
        'settings': {'timeout': 60, 'proxy': ''}
    }
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
            if 'api_keys' in loaded:
                for key in config['api_keys']:
                    if key in loaded['api_keys'] and loaded['api_keys'][key]:
                        config['api_keys'][key] = loaded['api_keys'][key]
            if 'settings' in loaded:
                for key in config['settings']:
                    if key in loaded['settings'] and loaded['settings'][key]:
                        config['settings'][key] = loaded['settings'][key]
        except json.JSONDecodeError:
            print("[!] Warning: config.json is malformed, using defaults")
        except Exception as e:
            print(f"[!] Warning: Could not read config.json: {e}")
    else:
        print("[*] No config.json found, using defaults")
    return config


def resolve_key(cli_value, env_name, config_value):
    if cli_value:
        return cli_value
    env_val = os.environ.get(env_name, '')
    if env_val:
        return env_val
    return config_value or ''


# ============================================================
# PROGRESS TRACKING
# ============================================================

def get_progress_path(target, mode):
    os.makedirs('output', exist_ok=True)
    safe = hashlib.md5(f"{target}_{mode}".encode()).hexdigest()[:12]
    return os.path.join('output', f".progress_grabber_{safe}.json")


def save_progress(progress_path, data):
    try:
        data['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(progress_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[!] Warning: Could not save progress: {e}")


def load_progress(progress_path):
    try:
        if os.path.exists(progress_path):
            with open(progress_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"[!] Warning: Could not load progress: {e}")
    return None


def cleanup_progress(progress_path):
    try:
        if os.path.exists(progress_path):
            os.remove(progress_path)
    except Exception:
        pass


# ============================================================
# SESSION SETUP
# ============================================================

def create_session(proxy=None):
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    })
    retry_strategy = Retry(
        total=3, backoff_factor=2,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
        print(f"[*] Using proxy: {proxy}")
    return session


# ============================================================
# INPUT DETECTION
# ============================================================

def detect_input_type(user_input):
    user_input = user_input.strip().rstrip('/')
    if user_input.startswith('http://') or user_input.startswith('https://'):
        parsed = urlparse(user_input)
        host = parsed.netloc
        if ':' in host:
            host = host.split(':')[0]
        return ('host', host)
    if '/' in user_input:
        host = user_input.split('/')[0]
        if ':' in host:
            host = host.split(':')[0]
        return ('host', host)
    domain = user_input.lower()
    if ':' in domain:
        domain = domain.split(':')[0]
    return ('domain', domain)


# ============================================================
# SOURCE 1: WAYBACK MACHINE
#
# Simple and clean CDX request — this is what works.
# The CDX API is meant to be used programmatically.
# Do NOT send Origin/Referer headers — it makes you look
# like a spoofed browser and triggers 403.
# ============================================================

def wayback_grab_urls(session, target, mode, timeout=60,
                      status_filter=None, wb_limit=50000):
    """Grab URLs from Wayback Machine CDX API.

    Simple approach: one clean request, optional retry on 403.
    No fake browser headers, no pagination, no complex strategies.
    This is how the original working script did it.
    """
    print("\n[WAYBACK] Grabbing URLs from Wayback Machine...")
    urls = set()

    try:
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        match_type = 'domain' if mode == 'domain' else 'host'

        params = {
            'url': target,
            'matchType': match_type,
            'output': 'json',
            'fl': 'original',
            'collapse': 'urlkey',
            'limit': wb_limit,
        }

        # Only add a filter if explicitly requested
        if status_filter:
            params['filter'] = f'statuscode:{status_filter}'
            filter_desc = f'statuscode:{status_filter}'
        else:
            filter_desc = 'none (all status codes)'

        print(f"[WAYBACK] Query: matchType={match_type}, target={target}")
        print(f"[WAYBACK] Status filter: {filter_desc}")
        print(f"[WAYBACK] Limit: {wb_limit}")

        # --- First attempt: clean simple request ---
        resp = None
        try:
            resp = session.get(cdx_url, params=params, timeout=timeout)
        except requests.exceptions.ConnectTimeout:
            print("[WAYBACK] Connection timeout")
        except requests.exceptions.ReadTimeout:
            print("[WAYBACK] Read timeout")
        except requests.exceptions.ConnectionError:
            print("[WAYBACK] Connection error")
        except Exception as e:
            print(f"[WAYBACK] Error: {e}")

        if resp is not None and resp.status_code == 200 and resp.text.strip():
            urls = _parse_wayback_response(resp.text)

        elif resp is not None and resp.status_code == 403:
            # --- 403: Retry once after delay with reduced limit ---
            print(f"[WAYBACK] Got 403 — CDX API throttled. Waiting 10s and retrying...")
            time.sleep(10)

            retry_limit = min(wb_limit, 10000)
            retry_params = dict(params)
            retry_params['limit'] = retry_limit

            try:
                resp2 = session.get(cdx_url, params=retry_params, timeout=timeout)
                if resp2.status_code == 200 and resp2.text.strip():
                    print(f"[WAYBACK] Retry succeeded (limit={retry_limit})")
                    urls = _parse_wayback_response(resp2.text)
                elif resp2.status_code == 403:
                    print(f"[WAYBACK] Still 403 after retry.")
                    # Fallback: try timemap endpoint
                    urls = _wayback_timemap_fallback(session, target, mode, timeout)
                else:
                    print(f"[WAYBACK] Retry returned HTTP {resp2.status_code}")
            except Exception as e:
                print(f"[WAYBACK] Retry error: {e}")
                urls = _wayback_timemap_fallback(session, target, mode, timeout)

        elif resp is not None and resp.status_code == 200:
            # 200 but empty
            print(f"[WAYBACK] Empty response (0 results)")
        elif resp is not None:
            print(f"[WAYBACK] HTTP {resp.status_code}")
            if resp.status_code == 403:
                urls = _wayback_timemap_fallback(session, target, mode, timeout)

        print(f"[WAYBACK] Found {len(urls)} URLs")

        if len(urls) == 0:
            if status_filter:
                print(f"[WAYBACK] Tip: Got 0 results with filter '{status_filter}'.")
                print(f"[WAYBACK] Try without it (default: no filter)")
            else:
                print(f"[WAYBACK] Tip: If this keeps happening, try:")
                print(f"[WAYBACK]   --proxy http://... or use a VPN")
                print(f"[WAYBACK]   Wait a few minutes and retry")
                print(f"[WAYBACK]   --wb-limit 10000 (smaller request)")

    except Exception as e:
        print(f"[WAYBACK] Error: {e}")

    return urls


def _parse_wayback_response(text):
    """Parse CDX JSON response into a set of URLs."""
    urls = set()
    try:
        data = json.loads(text)
        if isinstance(data, list) and len(data) > 1:
            for row in data[1:]:
                if row and row[0]:
                    url = row[0].strip()
                    if url.startswith('http://') or url.startswith('https://'):
                        urls.add(url)
    except json.JSONDecodeError:
        # Try line-by-line
        for line in text.strip().split('\n'):
            line = line.strip()
            if line.startswith('http'):
                urls.add(line)
    return urls


def _wayback_timemap_fallback(session, target, mode, timeout=60):
    """Fallback: use timemap endpoint which is less likely to 403."""
    print("[WAYBACK] Trying timemap API fallback...")
    urls = set()
    try:
        match = 'domain' if mode == 'domain' else 'host'
        tm_url = (f"https://web.archive.org/web/timemap/json?"
                  f"url={target}&matchType={match}"
                  f"&limit=5000&output=json&fl=original&collapse=urlkey")
        resp = session.get(tm_url, timeout=timeout)
        if resp.status_code == 200 and resp.text.strip():
            urls = _parse_wayback_response(resp.text)
            if urls:
                print(f"[WAYBACK] Timemap fallback: {len(urls)} URLs")
        elif resp.status_code == 403:
            print(f"[WAYBACK] Timemap also 403'd — IP is temporarily blocked")
        else:
            print(f"[WAYBACK] Timemap: HTTP {resp.status_code}")
    except Exception as e:
        print(f"[WAYBACK] Timemap error: {e}")
    return urls


# ============================================================
# SOURCE 2: COMMON CRAWL
# ============================================================

def commoncrawl_get_indexes(session, timeout=30):
    try:
        resp = session.get("https://index.commoncrawl.org/collinfo.json", timeout=timeout)
        if resp.status_code == 200:
            indexes = resp.json()
            return [idx['cdx-api'] for idx in indexes[:5]]
    except Exception as e:
        print(f"[COMMONCRAWL] Error fetching indexes: {e}")
    return []


def commoncrawl_grab_urls(session, target, mode, timeout=60, status_filter=None):
    print("\n[COMMONCRAWL] Grabbing URLs from Common Crawl...")
    urls = set()

    try:
        indexes = commoncrawl_get_indexes(session, timeout=timeout)
        if not indexes:
            print("[COMMONCRAWL] Could not fetch index list")
            return urls

        print(f"[COMMONCRAWL] Checking {len(indexes)} recent indexes...")
        query_url = f"*.{target}" if mode == 'domain' else f"{target}/*"

        for cdx_api in indexes:
            pause.check()
            try:
                params = {
                    'url': query_url,
                    'output': 'json',
                    'fl': 'url',
                    'limit': 10000,
                }
                if status_filter:
                    params['filter'] = f'status:{status_filter}'

                resp = session.get(cdx_api, params=params, timeout=timeout)
                if resp.status_code == 200 and resp.text.strip():
                    for line in resp.text.strip().split('\n'):
                        try:
                            record = json.loads(line)
                            url = record.get('url', '')
                            if url:
                                urls.add(url)
                        except json.JSONDecodeError:
                            continue
                time.sleep(0.5)
            except Exception:
                continue

        print(f"[COMMONCRAWL] Found {len(urls)} URLs")

    except Exception as e:
        print(f"[COMMONCRAWL] Error: {e}")

    return urls


# ============================================================
# SOURCE 3: URLSCAN.IO
# ============================================================

def urlscan_grab_urls(session, target, mode, timeout=30, api_key=None):
    print("\n[URLSCAN] Grabbing URLs from urlscan.io...")
    urls = set()

    try:
        search_url = "https://urlscan.io/api/v1/search/"
        query = f'domain:{target}' if mode == 'domain' else f'page.domain:"{target}"'
        headers = {}
        if api_key:
            headers['API-Key'] = api_key

        print(f"[URLSCAN] Query: {query}")

        total_fetched = 0
        search_after = None
        max_results = 10000

        while total_fetched < max_results:
            pause.check()
            params = {'q': query, 'size': 100}
            if search_after:
                params['search_after'] = search_after

            resp = session.get(search_url, params=params, timeout=timeout, headers=headers)

            if resp.status_code == 200:
                data = resp.json()
                results = data.get('results', [])
                if not results:
                    break
                for result in results:
                    page_url = result.get('page', {}).get('url', '')
                    if page_url:
                        urls.add(page_url)
                    task_url = result.get('task', {}).get('url', '')
                    if task_url:
                        urls.add(task_url)
                total_fetched += len(results)
                if not data.get('has_more', False):
                    break
                sort_values = results[-1].get('sort', [])
                if sort_values:
                    search_after = ','.join(str(v) for v in sort_values)
                else:
                    break
                time.sleep(1)
            elif resp.status_code == 429:
                print("[URLSCAN] Rate limited - waiting 10s...")
                time.sleep(10)
                continue
            else:
                print(f"[URLSCAN] HTTP {resp.status_code}")
                break

        print(f"[URLSCAN] Found {len(urls)} URLs")

    except requests.exceptions.ConnectTimeout:
        print("[URLSCAN] Connection timeout")
    except requests.exceptions.ReadTimeout:
        print("[URLSCAN] Read timeout")
    except Exception as e:
        print(f"[URLSCAN] Error: {e}")

    return urls


# ============================================================
# URL FILTERING & PROCESSING
# ============================================================

def filter_urls_by_host(urls, target, mode):
    filtered = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            if ':' in host:
                host = host.split(':')[0]
            if not host and not parsed.scheme:
                reparsed = urlparse('https://' + url)
                host = reparsed.netloc.lower()
                if ':' in host:
                    host = host.split(':')[0]
            if not host:
                continue
            if mode == 'domain':
                if host == target or host.endswith(f'.{target}'):
                    filtered.add(url)
            else:
                if host == target:
                    filtered.add(url)
        except Exception:
            continue
    return filtered


def filter_urls_by_extension(urls, extensions):
    if not extensions:
        return urls
    filtered = set()
    ext_list = [e.strip().lower().lstrip('.') for e in extensions.split(',')]
    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            for ext in ext_list:
                if path.endswith(f'.{ext}'):
                    filtered.add(url)
                    break
        except Exception:
            continue
    return filtered


def categorize_urls(urls):
    categories = {
        'js': [], 'css': [], 'json': [], 'xml': [], 'html': [],
        'php': [], 'asp': [], 'api': [], 'images': [],
        'documents': [], 'config': [], 'other': [],
    }
    config_patterns = ['.env', 'config', '.yml', '.yaml', '.toml', '.ini',
                       '.conf', 'robots.txt', 'sitemap', '.bak', '.old',
                       '.backup', '.swp', '.sql', '.log', '.key', '.pem']
    api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/',
                    '/endpoint', '/webhook']
    image_exts = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp']
    doc_exts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt']
    for url in sorted(urls):
        path = urlparse(url).path.lower()
        categorized = False
        for pattern in config_patterns:
            if pattern in path:
                categories['config'].append(url)
                categorized = True
                break
        if categorized:
            continue
        for pattern in api_patterns:
            if pattern in path.lower():
                categories['api'].append(url)
                categorized = True
                break
        if categorized:
            continue
        if path.endswith('.js'):
            categories['js'].append(url)
        elif path.endswith('.css'):
            categories['css'].append(url)
        elif path.endswith('.json'):
            categories['json'].append(url)
        elif path.endswith('.xml'):
            categories['xml'].append(url)
        elif path.endswith('.html') or path.endswith('.htm'):
            categories['html'].append(url)
        elif path.endswith('.php'):
            categories['php'].append(url)
        elif path.endswith('.asp') or path.endswith('.aspx'):
            categories['asp'].append(url)
        elif any(path.endswith(ext) for ext in image_exts):
            categories['images'].append(url)
        elif any(path.endswith(ext) for ext in doc_exts):
            categories['documents'].append(url)
        else:
            categories['other'].append(url)
    return categories


def extract_subdomains(urls, root_domain):
    subdomains = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            if ':' in host:
                host = host.split(':')[0]
            if host == root_domain or host.endswith(f'.{root_domain}'):
                subdomains.add(host)
        except Exception:
            continue
    return sorted(subdomains)


# ============================================================
# LIVENESS CHECKER
# ============================================================

def check_url_alive(session, url, timeout=10):
    try:
        resp = session.head(url, timeout=timeout, allow_redirects=True)
        if resp.status_code < 400:
            return (url, True, resp.status_code, None)
        return (url, False, resp.status_code, f"HTTP {resp.status_code}")
    except requests.exceptions.ConnectTimeout:
        return (url, False, 0, "Timeout")
    except requests.exceptions.ReadTimeout:
        return (url, False, 0, "Read timeout")
    except requests.exceptions.ConnectionError as e:
        reason = str(e)
        if 'Name or service not known' in reason or 'getaddrinfo failed' in reason:
            return (url, False, 0, "DNS failed")
        if 'Connection refused' in reason:
            return (url, False, 0, "Refused")
        return (url, False, 0, "Connection error")
    except Exception as e:
        return (url, False, 0, str(e)[:40])


def check_urls_alive(session, urls, timeout=10, max_workers=10):
    alive = []
    dead = []
    results = []
    total = len(urls)
    checked = 0
    lock = threading.Lock()
    url_list = sorted(urls)

    def _check(url):
        nonlocal checked
        result = check_url_alive(session, url, timeout=timeout)
        with lock:
            checked += 1
            if result[1]:
                alive.append(url)
            else:
                dead.append(url)
            results.append(result)
            if checked % 20 == 0 or checked == total:
                print(f"  [{checked}/{total}] alive:{len(alive)} dead:{len(dead)}", end='\r')

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(_check, url_list)

    print(f"  [{total}/{total}] alive:{len(alive)} dead:{len(dead)}")
    return alive, dead, results


# ============================================================
# OUTPUT
# ============================================================

def save_urls(urls, output_file):
    try:
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            if urls:
                for url in sorted(urls):
                    f.write(url + '\n')
            else:
                f.write(f"# No URLs found - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        return True
    except Exception as e:
        print(f"[!] Error saving to {output_file}: {e}")
        return False


def compute_output_path(target):
    safe_target = target.replace('/', '_').replace(':', '_').replace('*', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return os.path.join('output', f"{safe_target}_urls_{timestamp}.txt")


# ============================================================
# MAIN
# ============================================================

def grab_urls(session, target, mode, sources, timeout=60, urlscan_key=None,
              progress_path=None, resume_data=None,
              status_filter=None, wb_limit=50000):

    all_urls = set()
    source_counts = {}
    completed_sources = []

    if resume_data:
        prev_urls = resume_data.get('urls_found', [])
        all_urls.update(prev_urls)
        completed_sources = resume_data.get('completed_sources', [])
        source_counts = resume_data.get('source_counts', {})
        if completed_sources:
            print(f"[*] RESUME: Loaded {len(prev_urls)} URLs from previous run")
            print(f"[*] RESUME: Already completed: {', '.join(completed_sources)}")

    if 'wayback' in sources:
        if 'wayback' in completed_sources:
            print(f"\n[WAYBACK] SKIPPED (already completed)")
        else:
            pause.check()
            wb_urls = wayback_grab_urls(
                session, target, mode, timeout=timeout,
                status_filter=status_filter,
                wb_limit=wb_limit,
            )
            wb_urls = filter_urls_by_host(wb_urls, target, mode)
            source_counts['wayback'] = len(wb_urls)
            all_urls.update(wb_urls)
            completed_sources.append('wayback')
            if progress_path:
                save_progress(progress_path, {
                    'target': target, 'mode': mode, 'sources': sources,
                    'completed_sources': completed_sources,
                    'source_counts': source_counts,
                    'urls_found': sorted(all_urls),
                })
                print(f"[*] Progress saved ({len(all_urls)} URLs so far)")

    if 'commoncrawl' in sources:
        if 'commoncrawl' in completed_sources:
            print(f"\n[COMMONCRAWL] SKIPPED (already completed)")
        else:
            pause.check()
            cc_urls = commoncrawl_grab_urls(
                session, target, mode, timeout=timeout,
                status_filter=status_filter,
            )
            cc_urls = filter_urls_by_host(cc_urls, target, mode)
            source_counts['commoncrawl'] = len(cc_urls)
            all_urls.update(cc_urls)
            completed_sources.append('commoncrawl')
            if progress_path:
                save_progress(progress_path, {
                    'target': target, 'mode': mode, 'sources': sources,
                    'completed_sources': completed_sources,
                    'source_counts': source_counts,
                    'urls_found': sorted(all_urls),
                })
                print(f"[*] Progress saved ({len(all_urls)} URLs so far)")

    if 'urlscan' in sources:
        if 'urlscan' in completed_sources:
            print(f"\n[URLSCAN] SKIPPED (already completed)")
        else:
            pause.check()
            us_urls = urlscan_grab_urls(session, target, mode, timeout=timeout,
                                        api_key=urlscan_key)
            us_urls = filter_urls_by_host(us_urls, target, mode)
            source_counts['urlscan'] = len(us_urls)
            all_urls.update(us_urls)
            completed_sources.append('urlscan')
            if progress_path:
                save_progress(progress_path, {
                    'target': target, 'mode': mode, 'sources': sources,
                    'completed_sources': completed_sources,
                    'source_counts': source_counts,
                    'urls_found': sorted(all_urls),
                })
                print(f"[*] Progress saved ({len(all_urls)} URLs so far)")

    return all_urls, source_counts


def main():
    banner = """
============================================================
   Multi-Source URL Grabber
   Wayback + CommonCrawl + urlscan.io
============================================================
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description='Multi-source URL grabber',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scope Logic:
  -d something.com              -> domain + ALL subdomains
  -u https://aaa.something.com  -> ONLY aaa.something.com

Status Code Filtering:
  Default: NO filter (all archived URLs).
  --status-filter 200           Only HTTP 200 responses
  --no-redirects                Same as --status-filter 200

If Wayback returns 403:
  The tool retries once after 10s with a smaller limit,
  then falls back to the timemap API.
  Additional options:
    --proxy http://...    Use a proxy
    --wb-limit 10000      Reduce request size
    Wait a few minutes and retry

Examples:
  python url_grabber.py -d example.com
  python url_grabber.py -d x.com
  python url_grabber.py -d example.com --check-alive
  python url_grabber.py -d example.com -o urls.txt --resume
  python url_grabber.py -d example.com --filter js,json,xml
  python url_grabber.py -u https://api.example.com -o api_urls.txt
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-d', '--domain', help='Domain (includes subdomains)')
    input_group.add_argument('-u', '--url', help='URL/host (exact host only)')

    parser.add_argument('-o', '--output', help='Save URLs to file')
    parser.add_argument('--filter', help='Filter by extension (e.g. js,json,xml)')
    parser.add_argument('--sources', default='all',
                       help='Comma-separated: wayback,commoncrawl,urlscan,all')
    parser.add_argument('--urlscan-key', help='urlscan.io API key')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('-t', '--timeout', type=int, default=None)
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--no-categorize', action='store_true')
    parser.add_argument('-q', '--quiet', action='store_true')
    parser.add_argument('--no-save', action='store_true')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--check-alive', action='store_true',
                       help='Check which URLs are alive vs dead after grabbing')
    parser.add_argument('--alive-threads', type=int, default=10,
                       help='Threads for liveness check (default: 10)')
    parser.add_argument('--alive-timeout', type=int, default=10,
                       help='Timeout per liveness check (default: 10s)')
    parser.add_argument('--status-filter', default=None,
                       help='Wayback/CC status code filter (e.g. "200"). '
                            'Default: no filter (all URLs).')
    parser.add_argument('--no-redirects', action='store_true',
                       help='Only include HTTP 200 responses.')
    parser.add_argument('--wb-limit', type=int, default=50000,
                       help='Wayback CDX API limit (default: 50000). '
                            'Lower if you get 403.')

    args = parser.parse_args()

    pause.start()
    if sys.stdin.isatty():
        print("[*] Press ENTER at any time to pause/resume\n")

    config = load_config(args.config)
    urlscan_key = resolve_key(args.urlscan_key, 'URLSCAN_API_KEY',
                              config['api_keys'].get('urlscan', ''))

    if args.timeout is not None:
        timeout = args.timeout
    elif config['settings'].get('timeout'):
        timeout = int(config['settings']['timeout'])
    else:
        timeout = 60

    proxy = args.proxy or config['settings'].get('proxy', '') or None

    status_filter = args.status_filter
    if args.no_redirects:
        status_filter = '200'

    if args.domain:
        mode = 'domain'
        target = args.domain.lower().strip().rstrip('/')
        if target.startswith('http://') or target.startswith('https://'):
            target = urlparse(target).netloc
        if ':' in target:
            target = target.split(':')[0]
    else:
        input_type, target = detect_input_type(args.url)
        mode = 'host'

    if args.sources == 'all':
        sources = ['wayback', 'commoncrawl', 'urlscan']
    else:
        sources = [s.strip().lower() for s in args.sources.split(',')]
        valid = {'wayback', 'commoncrawl', 'urlscan'}
        for s in sources:
            if s not in valid:
                print(f"[!] Unknown source: {s}")
                return

    progress_path = get_progress_path(target, mode)
    resume_data = None
    if args.resume:
        resume_data = load_progress(progress_path)
        if resume_data:
            prev_count = len(resume_data.get('urls_found', []))
            print(f"[*] RESUME: {prev_count} URLs from {len(resume_data.get('completed_sources', []))} source(s)")
        else:
            print(f"[*] RESUME: No previous progress, starting fresh")

    auto_save_path = compute_output_path(target)

    if not args.quiet:
        us_status = "[+] loaded" if urlscan_key else "[-] not set"
        if status_filter:
            filter_desc = f"statuscode:{status_filter}"
        else:
            filter_desc = "No filter (all URLs)"

        print(f"{'=' * 60}")
        print(f"Mode:    {'DOMAIN (includes subdomains)' if mode == 'domain' else 'HOST (exact host only)'}")
        print(f"Target:  {target}")
        print(f"Sources: {', '.join(sources)}")
        print(f"Status:  {filter_desc}")
        print(f"Timeout: {timeout}s")
        print(f"WB Limit: {args.wb_limit}")
        print(f"US Key:  {us_status}")
        print(f"Resume:  {'ON' if args.resume else 'OFF'}")
        if args.check_alive:
            print(f"Alive:   CHECK ({args.alive_threads} threads, {args.alive_timeout}s timeout)")
        if args.filter:
            print(f"Filter:  {args.filter}")
        if args.output:
            print(f"Output:  {args.output}")
        if not args.no_save:
            print(f"Auto-save: {auto_save_path}")
        if proxy:
            print(f"Proxy:   {proxy}")
        print(f"{'=' * 60}")

    session = create_session(proxy=proxy)

    all_urls, source_counts = grab_urls(
        session, target, mode, sources, timeout=timeout,
        urlscan_key=urlscan_key, progress_path=progress_path,
        resume_data=resume_data,
        status_filter=status_filter,
        wb_limit=args.wb_limit,
    )

    if args.filter:
        before_filter = len(all_urls)
        all_urls = filter_urls_by_extension(all_urls, args.filter)
        if not args.quiet:
            print(f"\n[*] Filter: {before_filter} -> {len(all_urls)} URLs")

    # ============================================================
    # LIVENESS CHECK
    # ============================================================
    alive_urls = None
    dead_urls = None

    if args.check_alive and all_urls:
        print(f"\n{'=' * 60}")
        print(f"LIVENESS CHECK ({len(all_urls)} URLs)")
        print(f"{'=' * 60}")
        print(f"  Threads: {args.alive_threads} | Timeout: {args.alive_timeout}s")
        print(f"  Checking...")

        alive_list, dead_list, results = check_urls_alive(
            session, list(all_urls),
            timeout=args.alive_timeout,
            max_workers=args.alive_threads,
        )

        alive_urls = set(alive_list)
        dead_urls = set(dead_list)

        print(f"\n  Results:")
        print(f"    Alive: {len(alive_urls)}")
        print(f"    Dead:  {len(dead_urls)}")

        dead_reasons = {}
        for url, is_alive, code, reason in results:
            if not is_alive:
                r = reason or f"HTTP {code}"
                dead_reasons.setdefault(r, 0)
                dead_reasons[r] += 1

        if dead_reasons:
            print(f"\n  Dead URL breakdown:")
            for reason, count in sorted(dead_reasons.items(), key=lambda x: -x[1]):
                print(f"    {reason}: {count}")

        safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
        os.makedirs('output', exist_ok=True)

        alive_file = os.path.join('output', f"{safe_target}_alive.txt")
        dead_file = os.path.join('output', f"{safe_target}_dead.txt")

        if save_urls(alive_urls, alive_file):
            print(f"\n  [+] Alive URLs: {alive_file} ({len(alive_urls)})")
        if save_urls(dead_urls, dead_file):
            print(f"  [+] Dead URLs:  {dead_file} ({len(dead_urls)})")

        print(f"\n  Next step for dead URLs:")
        print(f"  python multi_source.py -l {dead_file} --archive-only -r")
        print(f"{'=' * 60}")

    # ============================================================
    # DISPLAY RESULTS
    # ============================================================
    if args.quiet:
        for url in sorted(all_urls):
            print(url)
    else:
        print(f"\n{'=' * 60}")
        print(f"RESULTS")
        print(f"{'=' * 60}")
        print(f"\nMode:   {'DOMAIN' if mode == 'domain' else 'HOST'}")
        print(f"Target: {target}")
        print(f"\nURLs per source:")
        print(f"{'-' * 40}")
        for src, count in source_counts.items():
            print(f"  {src:<15} {count:>6} URLs")
        print(f"{'-' * 40}")
        print(f"  {'TOTAL (deduped)':<15} {len(all_urls):>6} URLs")

        if alive_urls is not None:
            print(f"\nLiveness:")
            print(f"  Alive: {len(alive_urls)}")
            print(f"  Dead:  {len(dead_urls)}")

        if mode == 'domain':
            subdomains = extract_subdomains(all_urls, target)
            if subdomains:
                print(f"\nSubdomains discovered: {len(subdomains)}")
                print(f"{'-' * 40}")
                for sub in subdomains:
                    sub_count = sum(1 for u in all_urls
                                   if urlparse(u).netloc.lower().split(':')[0] == sub)
                    print(f"  {sub} ({sub_count} URLs)")

        if not args.no_categorize and all_urls:
            categories = categorize_urls(all_urls)
            print(f"\nURL Categories:")
            print(f"{'-' * 40}")
            for cat, cat_urls in categories.items():
                if cat_urls:
                    print(f"  {cat:<12} {len(cat_urls):>6} URLs")
            print(f"{'-' * 40}")
            if categories.get('config'):
                print(f"\n[!] Interesting (config/sensitive) files found:")
                for url in sorted(categories['config'])[:20]:
                    print(f"  {url}")
                if len(categories['config']) > 20:
                    print(f"  ... and {len(categories['config']) - 20} more")
            if categories.get('api'):
                print(f"\n[*] API endpoints found:")
                for url in sorted(categories['api'])[:20]:
                    print(f"  {url}")
                if len(categories['api']) > 20:
                    print(f"  ... and {len(categories['api']) - 20} more")

        if all_urls:
            print(f"\n{'=' * 60}")
            print(f"ALL URLs ({len(all_urls)})")
            print(f"{'=' * 60}")
            for url in sorted(all_urls):
                print(f"  {url}")
        else:
            print(f"\n[!] No URLs found")

    # ============================================================
    # SAVE OUTPUT
    # ============================================================
    saved_files = []

    if args.output:
        if save_urls(all_urls, args.output):
            saved_files.append(args.output)

    if not args.no_save:
        os.makedirs('output', exist_ok=True)
        if save_urls(all_urls, auto_save_path):
            saved_files.append(auto_save_path)

    if saved_files:
        print(f"\n{'=' * 60}")
        print(f"OUTPUT SAVED")
        print(f"{'=' * 60}")
        for f in saved_files:
            abs_path = os.path.abspath(f)
            print(f"  [+] {f}")
            print(f"    ({len(all_urls)} URLs, path: {abs_path})")
        if alive_urls is not None:
            safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
            print(f"  [+] output/{safe_target}_alive.txt ({len(alive_urls)} alive)")
            print(f"  [+] output/{safe_target}_dead.txt ({len(dead_urls)} dead)")
        print(f"{'=' * 60}")

    cleanup_progress(progress_path)
    pause.stop()

    if not args.quiet:
        print(f"\nDone. {len(all_urls)} unique URLs found.")
        if dead_urls:
            safe_target = target.replace('.', '_').replace('/', '_').replace(':', '_')
            print(f"\nTip: Analyze dead URLs with archived snapshots:")
            print(f"  python multi_source.py -l output/{safe_target}_dead.txt --archive-only -r")


if __name__ == "__main__":
    main()
