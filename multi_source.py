#!/usr/bin/env python3
"""
Multi-Source Web Change Detector
Fetches and compares snapshots from:
  - Wayback Machine (archive.org)
  - Common Crawl (commoncrawl.org)
  - urlscan.io
  - VirusTotal (virustotal.com)

Separate inputs for each phase:
  Phase 1: -u / -l  -> Wayback + CommonCrawl + urlscan (fast)
  Phase 2: --vt-url / --vt-list / -d -> VirusTotal (slow, runs last)

Phase 1 results are saved before Phase 2 starts.

Dead URL handling:
  --archive-only    Skip live fetch, always use newest archived snapshot as baseline
  (default)         Try live fetch first, auto-fallback to archived if dead

Resume support:
  --resume flag reloads progress from previous interrupted run.

Pause/Resume:
  Press ENTER at any time to pause. Press ENTER again to resume.

Reports:
  -r / --report     Generate styled HTML report with full VirusTotal data
                    plus text reports for each phase.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse
from datetime import datetime
from difflib import unified_diff, HtmlDiff
from urllib.parse import urlparse, quote
import time
import json
import gzip
import io
import base64
import hashlib
import threading
import sys
import os

from html import escape as html_escape


# ============================================================
# PAUSE CONTROLLER (ffuf-style Enter to pause/resume)
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
        'api_keys': {'virustotal': '', 'urlscan': ''},
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
        print("[*] Create config.json with API keys for VirusTotal/urlscan.io")
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

def get_progress_path(p1_urls, p2_urls, label="multi"):
    os.makedirs('output', exist_ok=True)
    all_inputs = sorted((p1_urls or [])[:10] + (p2_urls or [])[:10])
    key = "|".join(all_inputs)
    safe = hashlib.md5(key.encode()).hexdigest()[:12]
    return os.path.join('output', f".progress_{label}_{safe}.json")


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
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    })
    retry_strategy = Retry(
        total=3, backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=5, pool_maxsize=5)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
        print(f"[*] Using proxy: {proxy}")
    return session


def fetch_url(session, url, timeout=40, headers=None):
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, headers=headers or {})
        if resp.status_code == 200:
            return resp.text
        return None
    except requests.exceptions.ConnectTimeout:
        pass
    except requests.exceptions.ReadTimeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.RequestException:
        pass
    return None


def fetch_url_with_status(session, url, timeout=40, headers=None):
    """Fetch URL and return (content, status_code, error_reason)."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, headers=headers or {})
        if resp.status_code == 200:
            return resp.text, 200, None
        return None, resp.status_code, f"HTTP {resp.status_code}"
    except requests.exceptions.ConnectTimeout:
        return None, 0, "Connection timeout"
    except requests.exceptions.ReadTimeout:
        return None, 0, "Read timeout"
    except requests.exceptions.ConnectionError as e:
        reason = str(e)[:80]
        return None, 0, f"Connection error: {reason}"
    except requests.exceptions.RequestException as e:
        return None, 0, f"Request error: {str(e)[:80]}"


def fetch_bytes(session, url, timeout=40, headers=None):
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, headers=headers or {})
        if resp.status_code in [200, 206]:
            return resp.content
        return None
    except Exception:
        return None


def load_urls_from_file(filepath):
    urls = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)
        print(f"[+] Loaded {len(urls)} URLs from {filepath}")
    except Exception as e:
        print(f"[!] Error reading file {filepath}: {e}")
    return urls


# ============================================================
# SOURCE 1: WAYBACK MACHINE
# ============================================================

def wayback_get_snapshots(session, url, max_snapshots=10, timeout=60):
    print("\n[WAYBACK] Searching Wayback Machine...")
    snapshots = []
    try:
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            'url': url, 'matchType': 'exact', 'output': 'json',
            'limit': max_snapshots * 2,
            'fl': 'timestamp,statuscode,digest,original',
            'filter': 'statuscode:200', 'collapse': 'digest',
        }
        resp = session.get(cdx_url, params=params, timeout=timeout)
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            if len(data) > 1:
                for row in data[1:]:
                    ts = row[0]
                    snapshots.append({
                        'source': 'wayback', 'timestamp': ts,
                        'formatted_time': f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}",
                        'digest': row[2] if len(row) > 2 else '',
                        'fetch_url': f"https://web.archive.org/web/{ts}id_/{url}",
                        'view_url': f"https://web.archive.org/web/{ts}/{url}",
                    })
        print(f"[WAYBACK] Found {len(snapshots)} unique snapshots")
    except requests.exceptions.ConnectTimeout:
        print("[WAYBACK] Connection timeout")
    except requests.exceptions.ReadTimeout:
        print("[WAYBACK] Read timeout - try increasing -t")
    except requests.exceptions.ConnectionError:
        print("[WAYBACK] Connection error")
    except Exception as e:
        print(f"[WAYBACK] Error: {e}")
    snapshots = sorted(snapshots, key=lambda x: x['timestamp'], reverse=True)
    return snapshots[:max_snapshots]


def wayback_fetch_content(session, snapshot, timeout=40):
    content = fetch_url(session, snapshot['fetch_url'], timeout=timeout)
    if not content:
        alt_url = snapshot['fetch_url'].replace('id_/', '/')
        content = fetch_url(session, alt_url, timeout=timeout)
    return content


# ============================================================
# SOURCE 2: COMMON CRAWL
# ============================================================

def commoncrawl_get_indexes(session, timeout=30):
    try:
        resp = session.get("https://index.commoncrawl.org/collinfo.json", timeout=timeout)
        if resp.status_code == 200:
            indexes = resp.json()
            return [idx['cdx-api'] for idx in indexes[:6]]
    except Exception as e:
        print(f"[COMMONCRAWL] Error fetching indexes: {e}")
    return []


def commoncrawl_get_snapshots(session, url, max_snapshots=10, timeout=60):
    print("\n[COMMONCRAWL] Searching Common Crawl...")
    snapshots = []
    try:
        indexes = commoncrawl_get_indexes(session, timeout=timeout)
        if not indexes:
            print("[COMMONCRAWL] Could not fetch index list")
            return []
        print(f"[COMMONCRAWL] Checking {len(indexes)} recent crawl indexes...")
        for cdx_api in indexes:
            if len(snapshots) >= max_snapshots:
                break
            pause.check()
            try:
                params = {'url': url, 'output': 'json', 'limit': 5}
                resp = session.get(cdx_api, params=params, timeout=timeout)
                if resp.status_code == 200 and resp.text.strip():
                    for line in resp.text.strip().split('\n'):
                        try:
                            record = json.loads(line)
                            if record.get('status', '') == '200':
                                ts = record.get('timestamp', '')
                                snapshots.append({
                                    'source': 'commoncrawl', 'timestamp': ts,
                                    'formatted_time': f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}" if len(ts) >= 12 else ts,
                                    'digest': record.get('digest', ''),
                                    'filename': record.get('filename', ''),
                                    'offset': record.get('offset', ''),
                                    'length': record.get('length', ''),
                                    'fetch_url': '',
                                    'view_url': f"https://web.archive.org/web/{ts}/{url}",
                                })
                        except json.JSONDecodeError:
                            continue
                time.sleep(0.5)
            except Exception:
                continue
        print(f"[COMMONCRAWL] Found {len(snapshots)} snapshots")
    except Exception as e:
        print(f"[COMMONCRAWL] Error: {e}")
    seen = set()
    unique = []
    for snap in snapshots:
        d = snap.get('digest', '')
        if d and d in seen:
            continue
        if d:
            seen.add(d)
        unique.append(snap)
    unique = sorted(unique, key=lambda x: x.get('timestamp', ''), reverse=True)
    return unique[:max_snapshots]


def commoncrawl_fetch_content(session, snapshot, timeout=60):
    filename = snapshot.get('filename', '')
    offset = snapshot.get('offset', '')
    length = snapshot.get('length', '')
    if not filename or not offset or not length:
        return None
    try:
        offset = int(offset)
        length = int(length)
        end = offset + length - 1
        warc_url = f"https://data.commoncrawl.org/{filename}"
        headers = {'Range': f'bytes={offset}-{end}'}
        raw_data = fetch_bytes(session, warc_url, timeout=timeout, headers=headers)
        if not raw_data:
            return None
        try:
            decompressed = gzip.decompress(raw_data)
        except Exception:
            decompressed = raw_data
        text = decompressed.decode('utf-8', errors='replace')
        parts = text.split('\r\n\r\n', 2)
        if len(parts) >= 3:
            return parts[2]
        elif len(parts) == 2:
            return parts[1]
        return text
    except Exception as e:
        print(f"    [!] WARC fetch error: {e}")
        return None


# ============================================================
# SOURCE 3: URLSCAN.IO
# ============================================================

def urlscan_get_snapshots(session, url, max_snapshots=10, timeout=30, api_key=None):
    print("\n[URLSCAN] Searching urlscan.io...")
    snapshots = []
    try:
        search_url = "https://urlscan.io/api/v1/search/"
        query = f'page.url:"{url}"'
        headers = {}
        if api_key:
            headers['API-Key'] = api_key
        params = {'q': query, 'size': min(max_snapshots * 2, 100)}
        resp = session.get(search_url, params=params, timeout=timeout, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get('results', [])
            for result in results:
                scan_id = result.get('_id', '')
                scan_time = result.get('task', {}).get('time', '')
                if scan_id:
                    formatted = scan_time[:16].replace('T', ' ') if scan_time else 'Unknown'
                    ts = scan_time.replace('-', '').replace('T', '').replace(':', '').replace('Z', '')[:14] if scan_time else ''
                    snapshots.append({
                        'source': 'urlscan', 'timestamp': ts,
                        'formatted_time': formatted,
                        'scan_id': scan_id,
                        'fetch_url': f"https://urlscan.io/dom/{scan_id}/",
                        'view_url': f"https://urlscan.io/result/{scan_id}/",
                        'digest': '',
                    })
            print(f"[URLSCAN] Found {len(snapshots)} scans")
        elif resp.status_code == 429:
            print("[URLSCAN] Rate limited - try with --urlscan-key")
        elif resp.status_code == 401:
            print("[URLSCAN] Unauthorized - check your API key")
        else:
            print(f"[URLSCAN] HTTP {resp.status_code}")
    except requests.exceptions.ConnectTimeout:
        print("[URLSCAN] Connection timeout")
    except requests.exceptions.ReadTimeout:
        print("[URLSCAN] Read timeout")
    except Exception as e:
        print(f"[URLSCAN] Error: {e}")
    return snapshots[:max_snapshots]


def urlscan_fetch_content(session, snapshot, timeout=30):
    return fetch_url(session, snapshot['fetch_url'], timeout=timeout)


# ============================================================
# SOURCE 4: VIRUSTOTAL
# ============================================================

VT_RATE_LIMIT_WAIT = 60
VT_MAX_RETRIES = 3


def vt_request(session, url, params, timeout, headers=None, max_retries=VT_MAX_RETRIES):
    for attempt in range(1, max_retries + 1):
        try:
            resp = session.get(url, params=params, timeout=timeout, headers=headers or {})
            if resp.status_code == 200:
                try:
                    return resp.json(), True
                except json.JSONDecodeError:
                    return None, False
            elif resp.status_code in (204, 429):
                if attempt < max_retries:
                    print(f"[VIRUSTOTAL] Rate limited (HTTP {resp.status_code}) - waiting {VT_RATE_LIMIT_WAIT}s (retry {attempt}/{max_retries})...", end='\r')
                    time.sleep(VT_RATE_LIMIT_WAIT)
                    print(" " * 80, end='\r')
                else:
                    print(f"[VIRUSTOTAL] Rate limited - max retries reached")
                    return None, False
            elif resp.status_code == 403:
                print("[VIRUSTOTAL] Invalid API key (HTTP 403)")
                return None, False
            elif resp.status_code == 404:
                return None, False
            else:
                print(f"[VIRUSTOTAL] HTTP {resp.status_code}")
                return None, False
        except requests.exceptions.ConnectTimeout:
            print("[VIRUSTOTAL] Connection timeout")
            return None, False
        except requests.exceptions.ReadTimeout:
            print("[VIRUSTOTAL] Read timeout")
            return None, False
        except Exception as e:
            print(f"[VIRUSTOTAL] Request error: {e}")
            return None, False
    return None, False


def vt_v2_domain_report(session, domain, api_key, timeout):
    urls = set()
    subdomains = []
    v2_url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': api_key, 'domain': domain}
    print(f"[VIRUSTOTAL] v2 domain/report for {domain}...")
    data, success = vt_request(session, v2_url, params, timeout)
    if not success or not data:
        return urls, subdomains
    if data.get('response_code', 0) != 1:
        print(f"[VIRUSTOTAL] Domain '{domain}' not found")
        return urls, subdomains
    for entry in data.get('detected_urls', []):
        url = entry.get('url', '')
        if url:
            urls.add(url)
    for entry in data.get('undetected_urls', []):
        if isinstance(entry, list) and len(entry) >= 1:
            url = entry[0]
            if url and isinstance(url, str):
                urls.add(url)
        elif isinstance(entry, dict):
            url = entry.get('url', '')
            if url:
                urls.add(url)
    subs = data.get('subdomains', [])
    if subs:
        subdomains = [s for s in subs if isinstance(s, str)]
    print(f"[VIRUSTOTAL] v2: {len(data.get('detected_urls', []))} detected, {len(data.get('undetected_urls', []))} undetected, {len(subdomains)} subdomains")
    return urls, subdomains


def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')


def virustotal_get_snapshots(session, url, timeout=30, api_key=None):
    print(f"\n[VIRUSTOTAL] Analyzing: {url}")
    snapshots = []
    if not api_key:
        print("[VIRUSTOTAL] Skipped - no API key")
        return []
    try:
        url_id = vt_url_id(url)
        vt_url_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {'x-apikey': api_key, 'Accept': 'application/json'}
        data, success = vt_request(session, vt_url_endpoint, {}, timeout, headers=headers)
        if success and data:
            attrs = data.get('data', {}).get('attributes', {})
            last_analysis = attrs.get('last_analysis_date', 0)
            last_response_sha256 = attrs.get('last_http_response_content_sha256', '')
            last_headers = attrs.get('last_http_response_headers', {})
            times_submitted = attrs.get('times_submitted', 0)
            last_final_url = attrs.get('last_final_url', url)
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            if last_analysis:
                dt = datetime.fromtimestamp(last_analysis)
                formatted = dt.strftime('%Y-%m-%d %H:%M')
                ts = dt.strftime('%Y%m%d%H%M%S')
            else:
                formatted = 'Unknown'
                ts = ''
            snapshots.append({
                'source': 'virustotal', 'timestamp': ts, 'formatted_time': formatted,
                'fetch_url': '', 'view_url': f"https://www.virustotal.com/gui/url/{url_id}",
                'digest': last_response_sha256,
                'vt_data': {
                    'response_sha256': last_response_sha256,
                    'headers': last_headers,
                    'times_submitted': times_submitted,
                    'final_url': last_final_url,
                    'detections': {'malicious': malicious, 'suspicious': suspicious,
                                   'harmless': harmless, 'undetected': undetected},
                },
            })
            print(f"[VIRUSTOTAL] Analysis from {formatted}")
            print(f"[VIRUSTOTAL] Detections: {malicious} malicious, {suspicious} suspicious")
            if malicious > 0 or suspicious > 0:
                print(f"[VIRUSTOTAL] [!!] WARNING: URL flagged by {malicious + suspicious} vendors!")
        time.sleep(0.5)
        try:
            dl_url = f"https://www.virustotal.com/api/v3/urls/{url_id}/downloaded_file"
            dl_resp = session.get(dl_url, timeout=timeout, headers=headers)
            if dl_resp.status_code == 200:
                content = dl_resp.text
                if snapshots:
                    snapshots[0]['content'] = content
                    print(f"[VIRUSTOTAL] Response body retrieved ({len(content)} chars)")
            else:
                print(f"[VIRUSTOTAL] Response body not available (HTTP {dl_resp.status_code})")
        except Exception:
            print("[VIRUSTOTAL] Could not fetch response body")
    except Exception as e:
        print(f"[VIRUSTOTAL] Error: {e}")
    return snapshots


def virustotal_fetch_content(session, snapshot, timeout=30, api_key=None):
    if snapshot.get('content'):
        return snapshot['content']
    return None


# ============================================================
# SNAPSHOT CONTENT FETCHER (generic)
# ============================================================

def fetch_snapshot_content(session, snap, timeout=60, vt_key=None):
    if snap['source'] == 'wayback':
        return wayback_fetch_content(session, snap, timeout=timeout)
    elif snap['source'] == 'commoncrawl':
        return commoncrawl_fetch_content(session, snap, timeout=timeout)
    elif snap['source'] == 'urlscan':
        return urlscan_fetch_content(session, snap, timeout=timeout)
    elif snap['source'] == 'virustotal':
        return virustotal_fetch_content(session, snap, timeout=timeout, api_key=vt_key)
    return None


# ============================================================
# COMPARISON & REPORTING
# ============================================================

def compare_content(old_content, new_content):
    if old_content == new_content:
        return False, 0, 0, []
    old_lines = old_content.split('\n')
    new_lines = new_content.split('\n')
    diff = list(unified_diff(old_lines, new_lines, lineterm='', n=0))
    changes = []
    for line in diff:
        if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
            continue
        if line.startswith('+') or line.startswith('-'):
            changes.append(line)
    added = sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))
    removed = sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))
    return True, added, removed, changes


def generate_html_diff(old_content, new_content, source, timestamp, url):
    try:
        html_folder = "html"
        os.makedirs(html_folder, exist_ok=True)
        old_lines = old_content.split('\n')
        new_lines = new_content.split('\n')
        ts = str(timestamp).ljust(14, '0')
        formatted_date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        diff_maker = HtmlDiff()
        html_diff = diff_maker.make_file(
            old_lines, new_lines,
            fromdesc=f'{source.upper()} Archived ({formatted_date})',
            todesc='Baseline Version',
            context=True, numlines=3
        )
        domain = urlparse(url).netloc.replace('.', '_')
        filename = f"diff_{source}_{domain}_{timestamp}.html"
        output_file = os.path.join(html_folder, filename)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_diff)
        return output_file
    except Exception as e:
        print(f"    [!] Error generating HTML diff: {e}")
        return None


def save_multi_report(url, all_changed, source_counts, phase_label="", baseline_info=""):
    try:
        reports_folder = "reports"
        os.makedirs(reports_folder, exist_ok=True)
        domain = urlparse(url).netloc.replace('.', '_')
        phase_suffix = f"_{phase_label}" if phase_label else ""
        filename = f"multi_report_{domain}{phase_suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        output_path = os.path.join(reports_folder, filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"Multi-Source Web Change Detection Report")
            if phase_label:
                f.write(f" ({phase_label})")
            f.write(f"\n{'=' * 70}\n")
            f.write(f"URL: {url}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if baseline_info:
                f.write(f"Baseline: {baseline_info}\n")
            f.write(f"{'=' * 70}\n\n")
            f.write(f"SOURCE SUMMARY:\n{'-' * 40}\n")
            for source, count in source_counts.items():
                f.write(f"  {source}: {count['found']} snapshots, {count['changed']} with changes\n")
            f.write(f"{'-' * 40}\n\n")
            f.write(f"Total versions with changes: {len(all_changed)}\n\n")
            for i, snap in enumerate(all_changed, 1):
                f.write(f"\n{'=' * 70}\n")
                f.write(f"[{snap['source'].upper()}] Version {i}: {snap['formatted_time']}\n")
                f.write(f"{'=' * 70}\n")
                f.write(f"Source: {snap['source']}\n")
                f.write(f"Lines Added: +{snap.get('added', 0)}\n")
                f.write(f"Lines Removed: -{snap.get('removed', 0)}\n")
                f.write(f"View URL: {snap.get('view_url', 'N/A')}\n\n")
                if snap['source'] == 'virustotal' and snap.get('vt_data'):
                    vt = snap['vt_data']
                    f.write(f"VirusTotal Data:\n")
                    f.write(f"  Response SHA256: {vt.get('response_sha256', 'N/A')}\n")
                    f.write(f"  Final URL: {vt.get('final_url', 'N/A')}\n")
                    det = vt.get('detections', {})
                    f.write(f"  Detections: {det.get('malicious', 0)} malicious, {det.get('suspicious', 0)} suspicious\n")
                    if vt.get('headers'):
                        f.write(f"  Response Headers:\n")
                        for k, v in vt['headers'].items():
                            f.write(f"    {k}: {v}\n")
                    f.write("\n")
                if snap.get('changes'):
                    f.write(f"Changes (first 50):\n" + "-" * 70 + "\n")
                    for change in snap['changes'][:50]:
                        if change.startswith('+'):
                            f.write(f"+ (Added)   {change[1:]}\n")
                        elif change.startswith('-'):
                            f.write(f"- (Removed) {change[1:]}\n")
                    if len(snap['changes']) > 50:
                        f.write(f"\n... and {len(snap['changes']) - 50} more changes\n")
                    f.write("-" * 70 + "\n")
        return output_path
    except Exception as e:
        print(f"[!] Error saving report: {e}")
        return None


def save_baseline_content(url, content, source_label, timestamp):
    try:
        os.makedirs('output', exist_ok=True)
        domain = urlparse(url).netloc.replace('.', '_')
        filename = f"baseline_{source_label}_{domain}_{timestamp}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        output_path = os.path.join('output', filename)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# Baseline content\n")
            f.write(f"# URL: {url}\n")
            f.write(f"# Source: {source_label}\n")
            f.write(f"# Timestamp: {timestamp}\n")
            f.write(f"# Saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {'=' * 60}\n\n")
            f.write(content)
        return output_path
    except Exception as e:
        print(f"[!] Error saving baseline: {e}")
        return None


# ============================================================
# COMPREHENSIVE HTML REPORT (with full VT data)
# ============================================================

SOURCE_COLORS = {
    'wayback': '#17a2b8',
    'commoncrawl': '#28a745',
    'urlscan': '#6f42c1',
    'virustotal': '#dc3545',
}


def generate_full_html_report(url, all_p1_changed, all_p2_changed,
                               p1_source_counts, p2_source_counts,
                               dead_urls, baseline_info="",
                               archive_only=False):
    """Generate a comprehensive styled HTML report with all findings
    including full VirusTotal metadata, headers, and detection data."""
    try:
        reports_folder = "reports"
        os.makedirs(reports_folder, exist_ok=True)
        domain = urlparse(url).netloc.replace('.', '_')
        filename = f"multi_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = os.path.join(reports_folder, filename)

        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        is_dead = url in (dead_urls or [])

        all_source_counts = {}
        if p1_source_counts:
            all_source_counts.update(p1_source_counts)
        if p2_source_counts:
            all_source_counts.update(p2_source_counts)

        total_found = sum(c.get('found', 0) for c in all_source_counts.values())
        total_changed = sum(c.get('changed', 0) for c in all_source_counts.values())
        all_changed = (all_p1_changed or []) + (all_p2_changed or [])

        # Collect VT data for dedicated section
        vt_entries = [c for c in all_changed if c.get('source') == 'virustotal' and c.get('vt_data')]
        # Also include VT snapshots that didn't produce "changes" but have metadata
        # (they get passed through already)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Multi-Source Report: {html_escape(url)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; }}
h1 {{ color: #58a6ff; font-size: 1.8rem; margin-bottom: 0.3rem; }}
h2 {{ color: #58a6ff; margin: 2rem 0 1rem; font-size: 1.3rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
h3 {{ color: #c9d1d9; margin: 1rem 0 0.5rem; font-size: 1rem; }}
.meta {{ color: #8b949e; margin-bottom: 1.5rem; font-size: 0.85rem; }}
.meta a {{ color: #58a6ff; text-decoration: none; }}
.meta a:hover {{ text-decoration: underline; }}
.stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.5rem 0; }}
.stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 0.8rem 1.2rem; min-width: 100px; text-align: center; }}
.stat .num {{ font-size: 1.8rem; font-weight: bold; }}
.stat .label {{ font-size: 0.7rem; color: #8b949e; text-transform: uppercase; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: bold; color: #fff; }}
.badge-dead {{ background: #f85149; }}
.badge-alive {{ background: #238636; }}
.badge-archive {{ background: #d29922; color: #000; }}
.source-badge {{ padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; color: #fff; display: inline-block; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th, td {{ padding: 0.5rem 0.8rem; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.85rem; }}
th {{ color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin: 1rem 0; overflow: hidden; }}
.card-header {{ padding: 0.8rem 1.2rem; background: #0d1117; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap; }}
.card-body {{ padding: 1rem 1.2rem; }}
.card-body-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0; }}
.card-left {{ padding: 1rem 1.2rem; border-right: 1px solid #21262d; }}
.card-right {{ padding: 1rem 1.2rem; background: #0d1117; }}
pre.code {{ background: #010409; border: 1px solid #30363d; border-radius: 6px; padding: 0.7rem; overflow-x: auto; font-size: 0.8rem; color: #e6edf3; white-space: pre-wrap; word-break: break-all; margin: 0.4rem 0; max-height: 300px; overflow-y: auto; }}
.added {{ color: #3fb950; }}
.removed {{ color: #f85149; }}
.vt-warning {{ background: #3d1117; border: 2px solid #f85149; border-radius: 8px; padding: 1rem 1.5rem; margin: 1rem 0; }}
.vt-warning h3 {{ color: #f85149; }}
.vt-safe {{ background: #0d2818; border: 2px solid #238636; border-radius: 8px; padding: 1rem 1.5rem; margin: 1rem 0; }}
.vt-safe h3 {{ color: #3fb950; }}
.vt-section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; margin: 1rem 0; }}
.vt-det {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 0.8rem 0; }}
.vt-det-item {{ text-align: center; padding: 0.5rem 1rem; border-radius: 8px; min-width: 100px; }}
.vt-det-item .n {{ font-size: 1.5rem; font-weight: bold; }}
.vt-det-item .l {{ font-size: 0.7rem; text-transform: uppercase; }}
.vt-mal {{ background: #3d1117; border: 1px solid #f85149; }}
.vt-mal .n {{ color: #f85149; }}
.vt-sus {{ background: #3d2b00; border: 1px solid #d29922; }}
.vt-sus .n {{ color: #d29922; }}
.vt-ok {{ background: #0d2818; border: 1px solid #238636; }}
.vt-ok .n {{ color: #3fb950; }}
.vt-unk {{ background: #21262d; border: 1px solid #30363d; }}
.vt-unk .n {{ color: #8b949e; }}
.header-table {{ margin: 0.5rem 0; }}
.header-table td {{ font-family: monospace; font-size: 0.8rem; padding: 0.2rem 0.5rem; }}
.header-table td:first-child {{ color: #79c0ff; font-weight: bold; white-space: nowrap; padding-right: 1rem; }}
a {{ color: #58a6ff; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.no-changes {{ background: #161b22; border: 1px solid #238636; border-radius: 8px; padding: 1.5rem; text-align: center; color: #3fb950; font-size: 1rem; margin: 1rem 0; }}
.diff-sample {{ max-height: 200px; overflow-y: auto; }}
@media (max-width: 900px) {{
    .card-body-grid {{ grid-template-columns: 1fr; }}
    .card-left {{ border-right: none; border-bottom: 1px solid #21262d; }}
}}
</style>
</head>
<body>
<div class="container">
<h1>\U0001f50d Multi-Source Change Detection Report</h1>
<p class="meta">
  URL: <a href="{html_escape(url)}" target="_blank">{html_escape(url)}</a><br>
  Generated: {ts}<br>
  Status: """

        if is_dead:
            html += f'<span class="badge badge-dead">DEAD</span>'
        else:
            html += f'<span class="badge badge-alive">ALIVE</span>'
        if archive_only:
            html += f' <span class="badge badge-archive">ARCHIVE-ONLY</span>'
        if baseline_info:
            html += f'<br>Baseline: {html_escape(baseline_info)}'
        html += '</p>\n'

        # Stats cards
        html += '<div class="stats">\n'
        html += f'<div class="stat"><div class="num" style="color:#58a6ff">{total_found}</div><div class="label">Snapshots Found</div></div>\n'
        html += f'<div class="stat"><div class="num" style="color:{"#f85149" if total_changed > 0 else "#3fb950"}">{total_changed}</div><div class="label">With Changes</div></div>\n'
        for src, counts in all_source_counts.items():
            color = SOURCE_COLORS.get(src, '#8b949e')
            html += f'<div class="stat"><div class="num" style="color:{color}">{counts.get("found", 0)}</div><div class="label">{html_escape(src)}</div></div>\n'
        html += '</div>\n'

        # ── VIRUSTOTAL SECTION (prominent) ──
        if vt_entries or (p2_source_counts and p2_source_counts.get('virustotal', {}).get('found', 0) > 0):
            html += '<h2>\U0001f6e1 VirusTotal Analysis</h2>\n'

            for snap in all_changed:
                if snap.get('source') != 'virustotal' or not snap.get('vt_data'):
                    continue
                vt = snap['vt_data']
                det = vt.get('detections', {})
                mal = det.get('malicious', 0)
                sus = det.get('suspicious', 0)
                harmless = det.get('harmless', 0)
                undetected = det.get('undetected', 0)
                total_engines = mal + sus + harmless + undetected

                # Warning / Safe banner
                if mal > 0 or sus > 0:
                    html += f'<div class="vt-warning">'
                    html += f'<h3>\u26a0\ufe0f URL flagged by {mal + sus} security vendor(s)</h3>'
                    html += f'<p style="color:#f85149;margin-top:0.3rem">{mal} malicious, {sus} suspicious out of {total_engines} engines</p>'
                    html += '</div>\n'
                else:
                    html += f'<div class="vt-safe">'
                    html += f'<h3>\u2705 No security vendors flagged this URL</h3>'
                    html += f'<p style="color:#3fb950;margin-top:0.3rem">{harmless} harmless, {undetected} undetected out of {total_engines} engines</p>'
                    html += '</div>\n'

                # Detection breakdown
                html += '<div class="vt-section">\n'
                html += '<h3>Detection Breakdown</h3>\n'
                html += '<div class="vt-det">\n'
                html += f'<div class="vt-det-item vt-mal"><div class="n">{mal}</div><div class="l">Malicious</div></div>\n'
                html += f'<div class="vt-det-item vt-sus"><div class="n">{sus}</div><div class="l">Suspicious</div></div>\n'
                html += f'<div class="vt-det-item vt-ok"><div class="n">{harmless}</div><div class="l">Harmless</div></div>\n'
                html += f'<div class="vt-det-item vt-unk"><div class="n">{undetected}</div><div class="l">Undetected</div></div>\n'
                html += '</div>\n'

                # Metadata table
                html += '<table style="margin-top:1rem">\n'
                html += '<tr><th style="width:200px">Property</th><th>Value</th></tr>\n'
                html += f'<tr><td>Last Analysis</td><td>{html_escape(snap.get("formatted_time", "N/A"))}</td></tr>\n'
                html += f'<tr><td>Final URL</td><td><a href="{html_escape(vt.get("final_url", ""))}" target="_blank">{html_escape(vt.get("final_url", "N/A"))}</a></td></tr>\n'
                sha = vt.get('response_sha256', '')
                if sha:
                    html += f'<tr><td>Response SHA-256</td><td><code style="color:#79c0ff">{html_escape(sha)}</code></td></tr>\n'
                html += f'<tr><td>Times Submitted</td><td>{vt.get("times_submitted", "N/A")}</td></tr>\n'
                html += f'<tr><td>VT Report</td><td><a href="{html_escape(snap.get("view_url", ""))}" target="_blank">View on VirusTotal</a></td></tr>\n'
                html += '</table>\n'

                # Response headers
                hdrs = vt.get('headers', {})
                if hdrs:
                    html += '<h3 style="margin-top:1.2rem">Last Known Response Headers</h3>\n'
                    html += '<table class="header-table">\n'
                    # Highlight security-relevant headers
                    security_headers = {
                        'content-security-policy', 'strict-transport-security',
                        'x-frame-options', 'x-content-type-options',
                        'x-xss-protection', 'access-control-allow-origin',
                        'set-cookie', 'server', 'x-powered-by',
                        'www-authenticate', 'authorization',
                    }
                    for k, v in hdrs.items():
                        is_sec = k.lower() in security_headers
                        style = ' style="color:#ffa657"' if is_sec else ''
                        html += f'<tr><td{style}>{html_escape(k)}</td><td>{html_escape(str(v))}</td></tr>\n'
                    html += '</table>\n'

                    # Security header analysis
                    missing = []
                    present_lower = {k.lower(): v for k, v in hdrs.items()}
                    recommended = [
                        ('Content-Security-Policy', 'content-security-policy'),
                        ('Strict-Transport-Security', 'strict-transport-security'),
                        ('X-Frame-Options', 'x-frame-options'),
                        ('X-Content-Type-Options', 'x-content-type-options'),
                    ]
                    for display, lower in recommended:
                        if lower not in present_lower:
                            missing.append(display)
                    if missing:
                        html += '<div style="margin-top:0.8rem;padding:0.6rem;background:#3d2b00;border:1px solid #d29922;border-radius:6px;font-size:0.85rem">'
                        html += f'\u26a0 Missing security headers: <strong>{", ".join(missing)}</strong>'
                        html += '</div>\n'

                    # Flag interesting headers
                    server = present_lower.get('server', '')
                    powered = present_lower.get('x-powered-by', '')
                    if server or powered:
                        html += '<div style="margin-top:0.5rem;padding:0.5rem;background:#21262d;border-radius:6px;font-size:0.85rem">'
                        html += '\U0001f50d Server fingerprint: '
                        if server:
                            html += f'<code>{html_escape(str(server))}</code> '
                        if powered:
                            html += f'| X-Powered-By: <code>{html_escape(str(powered))}</code>'
                        html += '</div>\n'

                html += '</div>\n'  # end vt-section

        # ── SOURCE SUMMARY TABLE ──
        html += '<h2>\U0001f4ca Source Summary</h2>\n'
        html += '<table><tr><th>Source</th><th>Snapshots Found</th><th>With Changes</th></tr>\n'
        for src, counts in all_source_counts.items():
            color = SOURCE_COLORS.get(src, '#8b949e')
            changed_style = f' style="color:#f85149;font-weight:bold"' if counts.get('changed', 0) > 0 else ''
            html += f'<tr><td><span class="source-badge" style="background:{color}">{html_escape(src)}</span></td>'
            html += f'<td>{counts.get("found", 0)}</td>'
            html += f'<td{changed_style}>{counts.get("changed", 0)}</td></tr>\n'
        html += '</table>\n'

        # ── ALL CHANGES ──
        if all_changed:
            html += f'<h2>\U0001f4dd All Changes ({len(all_changed)})</h2>\n'

            for i, snap in enumerate(all_changed, 1):
                src = snap['source']
                color = SOURCE_COLORS.get(src, '#8b949e')
                added = snap.get('added', 0)
                removed = snap.get('removed', 0)
                formatted = snap.get('formatted_time', 'Unknown')
                view_url = snap.get('view_url', '')

                html += f'<div class="card" style="border-left:4px solid {color}">\n'
                html += f'<div class="card-header">'
                html += f'<span class="source-badge" style="background:{color}">{html_escape(src)}</span>'
                html += f'<strong>#{i}</strong> {html_escape(formatted)}'
                if added or removed:
                    html += f' &mdash; <span class="added">+{added}</span> <span class="removed">-{removed}</span>'
                if view_url:
                    html += f' <a href="{html_escape(view_url)}" target="_blank" style="margin-left:auto;font-size:0.8rem">View \u2197</a>'
                html += '</div>\n'

                html += '<div class="card-body">\n'

                # VT metadata inline
                if src == 'virustotal' and snap.get('vt_data'):
                    vt = snap['vt_data']
                    det = vt.get('detections', {})
                    mal = det.get('malicious', 0)
                    sus = det.get('suspicious', 0)
                    if mal > 0 or sus > 0:
                        html += f'<div style="color:#f85149;font-weight:bold;margin-bottom:0.5rem">\u26a0 {mal} malicious, {sus} suspicious detections</div>\n'
                    sha = vt.get('response_sha256', '')
                    if sha:
                        html += f'<div style="font-size:0.8rem;color:#8b949e">SHA-256: <code>{html_escape(sha[:32])}...</code></div>\n'
                    final = vt.get('final_url', '')
                    if final and final != url:
                        html += f'<div style="font-size:0.8rem;color:#d29922">Redirects to: <a href="{html_escape(final)}" target="_blank">{html_escape(final)}</a></div>\n'

                # Diff sample
                changes = snap.get('changes', [])
                if changes:
                    html += '<h3 style="margin-top:0.8rem">Change Preview</h3>\n'
                    html += '<pre class="code diff-sample">'
                    for change in changes[:30]:
                        escaped = html_escape(change[:200])
                        if change.startswith('+'):
                            html += f'<span class="added">{escaped}</span>\n'
                        elif change.startswith('-'):
                            html += f'<span class="removed">{escaped}</span>\n'
                        else:
                            html += f'{escaped}\n'
                    if len(changes) > 30:
                        html += f'\n... and {len(changes) - 30} more changes'
                    html += '</pre>\n'
                elif src != 'virustotal':
                    html += '<div style="color:#8b949e;font-size:0.85rem">No diff content available</div>\n'

                html += '</div></div>\n'
        else:
            html += '<div class="no-changes">\u2705 No changes detected across all sources.</div>\n'

        # Footer
        html += f'<p class="meta" style="text-align:center;margin-top:2rem">Multi-Source Web Change Detector | {ts}</p>\n'
        html += '</div></body></html>'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path

    except Exception as e:
        print(f"[!] Error generating HTML report: {e}")
        import traceback
        traceback.print_exc()
        return None


# ============================================================
# PHASE RUNNER: Compare snapshots against baseline
# ============================================================

def compare_snapshots_phase(session, url, baseline_content, snapshots, source_counts,
                            save_diff=False, timeout=60, vt_key=None,
                            baseline_label="current"):
    all_changed = []
    fetched_count = 0
    total = len(snapshots)

    for i, snap in enumerate(snapshots, 1):
        pause.check()
        src = snap['source'].upper()
        formatted = snap.get('formatted_time', 'Unknown')
        print(f"[{i}/{total}] [{src}] {formatted}")

        content = fetch_snapshot_content(session, snap, timeout=timeout, vt_key=vt_key)

        if content:
            fetched_count += 1
            has_changes, added, removed, changes = compare_content(content, baseline_content)
            if has_changes:
                print(f"    [!] CHANGES vs {baseline_label}: +{added} -{removed} lines")
                if changes:
                    print(f"    [*] Sample (first 5):")
                    for change in changes[:5]:
                        prefix = change[0]
                        text = change[1:].strip()[:65]
                        print(f"        {prefix} {text}")
                source_counts[snap['source']]['changed'] += 1
                changed_data = {
                    'source': snap['source'],
                    'timestamp': snap.get('timestamp', ''),
                    'formatted_time': formatted,
                    'view_url': snap.get('view_url', ''),
                    'added': added, 'removed': removed,
                    'changes': changes, 'content': content,
                    'vt_data': snap.get('vt_data'),
                }
                all_changed.append(changed_data)
                if save_diff:
                    diff_file = generate_html_diff(
                        content, baseline_content,
                        snap['source'], snap.get('timestamp', 'unknown'), url
                    )
                    if diff_file:
                        print(f"    [+] Diff saved: {diff_file}")
            else:
                print(f"    [=] No changes from {baseline_label}")
        else:
            if snap['source'] == 'virustotal' and snap.get('vt_data'):
                print(f"    [*] No content body, but metadata available")
                det = snap['vt_data'].get('detections', {})
                print(f"    [*] Detections: {det.get('malicious', 0)} malicious, {det.get('suspicious', 0)} suspicious")
                if det.get('malicious', 0) > 0 or det.get('suspicious', 0) > 0:
                    changed_data = {
                        'source': 'virustotal',
                        'timestamp': snap.get('timestamp', ''),
                        'formatted_time': formatted,
                        'view_url': snap.get('view_url', ''),
                        'added': 0, 'removed': 0, 'changes': [],
                        'content': '', 'vt_data': snap.get('vt_data'),
                    }
                    all_changed.append(changed_data)
                    source_counts['virustotal']['changed'] += 1
            else:
                print(f"    [!] Could not fetch content")
        print()
        time.sleep(0.5)

    return all_changed, fetched_count


# ============================================================
# FALLBACK: Find baseline from archived snapshots
# ============================================================

def find_archived_baseline(session, snapshots, timeout=60, vt_key=None):
    """Find the newest archived snapshot that has fetchable content.
    Returns (content, baseline_snapshot, remaining_snapshots)."""
    sorted_snaps = sorted(snapshots, key=lambda x: x.get('timestamp', ''), reverse=True)

    for i, snap in enumerate(sorted_snaps):
        src = snap['source'].upper()
        formatted = snap.get('formatted_time', 'Unknown')
        print(f"    Trying [{src}] {formatted} as baseline...")

        content = fetch_snapshot_content(session, snap, timeout=timeout, vt_key=vt_key)

        if content:
            print(f"    [+] Baseline found: [{src}] {formatted} ({len(content)} chars)")
            remaining = sorted_snaps[:i] + sorted_snaps[i+1:]
            return content, snap, remaining
        else:
            print(f"    [-] Could not fetch, trying next...")

    return None, None, sorted_snaps


# ============================================================
# LIVENESS CHECK
# ============================================================

def quick_liveness_check(session, url, timeout=10):
    try:
        resp = session.head(url, timeout=timeout, allow_redirects=True)
        if resp.status_code < 400:
            return True, resp.status_code, None
        return False, resp.status_code, f"HTTP {resp.status_code}"
    except requests.exceptions.ConnectTimeout:
        return False, 0, "Connection timeout"
    except requests.exceptions.ReadTimeout:
        return False, 0, "Read timeout"
    except requests.exceptions.ConnectionError as e:
        reason = str(e)
        if 'Name or service not known' in reason or 'getaddrinfo failed' in reason:
            return False, 0, "DNS resolution failed (domain does not exist)"
        if 'Connection refused' in reason:
            return False, 0, "Connection refused"
        if 'SSLError' in reason or 'SSL' in reason:
            return False, 0, "SSL error"
        return False, 0, "Connection error"
    except Exception as e:
        return False, 0, str(e)[:60]


# ============================================================
# PHASE 1: Analyze URL with Wayback + CC + urlscan
# ============================================================

def analyze_url_phase1(session, url, max_snapshots=10, timeout=60,
                       save_diff=False, save_report=False, urlscan_key=None,
                       archive_only=False):

    print(f"\n{'=' * 70}")
    print(f"PHASE 1: Wayback + CommonCrawl + urlscan")
    print(f"{'=' * 70}")
    print(f"URL: {url}")
    print(f"Max snapshots per source: {max_snapshots}")
    if archive_only:
        print(f"Mode: ARCHIVE-ONLY (skip live fetch, use newest snapshot as baseline)")
    else:
        print(f"Mode: AUTO (try live, fallback to archive if dead)")
    print(f"{'=' * 70}")

    phase1_snapshots = []
    source_counts = {}

    wb_snaps = wayback_get_snapshots(session, url, max_snapshots, timeout)
    phase1_snapshots.extend(wb_snaps)
    source_counts['wayback'] = {'found': len(wb_snaps), 'changed': 0}

    cc_snaps = commoncrawl_get_snapshots(session, url, max_snapshots, timeout)
    phase1_snapshots.extend(cc_snaps)
    source_counts['commoncrawl'] = {'found': len(cc_snaps), 'changed': 0}

    us_snaps = urlscan_get_snapshots(session, url, max_snapshots, timeout, api_key=urlscan_key)
    phase1_snapshots.extend(us_snaps)
    source_counts['urlscan'] = {'found': len(us_snaps), 'changed': 0}

    print(f"\n[*] Phase 1 snapshots found: {len(phase1_snapshots)}")

    if not phase1_snapshots:
        print("[!] No snapshots found from any source")
        return [], source_counts, None, ""

    baseline = None
    baseline_label = "current"
    baseline_info = "Live version"
    url_is_dead = False

    if archive_only:
        url_is_dead = True
        print("\n[*] ARCHIVE-ONLY mode: skipping live URL fetch")
        print("[*] Finding newest archived snapshot as baseline...\n")

        baseline, baseline_snap, remaining_snaps = find_archived_baseline(
            session, phase1_snapshots, timeout=timeout
        )

        if baseline:
            bl_src = baseline_snap['source'].upper()
            bl_time = baseline_snap.get('formatted_time', 'Unknown')
            baseline_label = f"baseline ({bl_src} {bl_time})"
            baseline_info = f"Newest archived: [{bl_src}] {bl_time} (archive-only mode)"

            print(f"\n[+] Using baseline: [{bl_src}] {bl_time}")

            bl_file = save_baseline_content(
                url, baseline,
                baseline_snap['source'],
                baseline_snap.get('timestamp', 'unknown')
            )
            if bl_file:
                print(f"[+] Baseline content saved: {bl_file}")

            phase1_snapshots = remaining_snaps
            print(f"[*] Comparing {len(phase1_snapshots)} remaining snapshots against baseline\n")
        else:
            print("[!] Could not fetch ANY archived snapshot content")
            print("[!] Nothing to compare")
            return [], source_counts, None, ""
    else:
        print("\n[*] Checking if URL is alive...")

        is_alive, status_code, reason = quick_liveness_check(session, url, timeout=min(timeout, 15))

        if is_alive:
            print(f"[+] URL is alive (HTTP {status_code})")
            print("[*] Fetching current content...")
            current, http_code, err = fetch_url_with_status(session, url, timeout=timeout)

            if current:
                baseline = current
                print(f"[+] Current version fetched ({len(current)} chars)\n")
            else:
                print(f"[!] Could not fetch content: {err}")
                print("[*] FALLBACK: Using newest archived snapshot as baseline...\n")
                url_is_dead = True
        else:
            url_is_dead = True
            print(f"[!] URL is DEAD/UNREACHABLE: {reason}")
            print(f"[*] FALLBACK: Using newest archived snapshot as baseline")
            print(f"[*] (All {len(phase1_snapshots)} archived snapshots will still be analyzed)\n")

        if url_is_dead:
            baseline, baseline_snap, remaining_snaps = find_archived_baseline(
                session, phase1_snapshots, timeout=timeout
            )

            if baseline:
                bl_src = baseline_snap['source'].upper()
                bl_time = baseline_snap.get('formatted_time', 'Unknown')
                baseline_label = f"baseline ({bl_src} {bl_time})"
                baseline_info = f"Newest archived: [{bl_src}] {bl_time} (URL is dead: {reason})"

                print(f"\n[+] Using baseline: [{bl_src}] {bl_time}")

                bl_file = save_baseline_content(
                    url, baseline,
                    baseline_snap['source'],
                    baseline_snap.get('timestamp', 'unknown')
                )
                if bl_file:
                    print(f"[+] Baseline content saved: {bl_file}")

                phase1_snapshots = remaining_snaps
                print(f"[*] Comparing {len(phase1_snapshots)} remaining snapshots against baseline\n")
            else:
                print("[!] Could not fetch ANY archived snapshot content")
                print("[!] Nothing to compare")
                return [], source_counts, None, ""

    all_changed = []

    if phase1_snapshots:
        print(f"{'=' * 70}")
        if url_is_dead:
            print(f"COMPARING SNAPSHOTS (vs archived baseline)")
        else:
            print(f"COMPARING SNAPSHOTS (vs current live version)")
        print(f"{'=' * 70}\n")

        p1_changed, p1_fetched = compare_snapshots_phase(
            session, url, baseline, phase1_snapshots, source_counts,
            save_diff=save_diff, timeout=timeout,
            baseline_label=baseline_label
        )
        all_changed.extend(p1_changed)

        if save_report and p1_changed:
            print("\n[*] Saving Phase 1 text report...")
            p1_report = save_multi_report(
                url, p1_changed, source_counts,
                phase_label="phase1", baseline_info=baseline_info
            )
            if p1_report:
                print(f"[+] Phase 1 report saved: {p1_report}")

    print(f"\n{'=' * 70}")
    print(f"PHASE 1 COMPLETE: {url}")
    print(f"{'=' * 70}")
    if url_is_dead:
        print(f"  NOTE: URL is dead - compared against archived baseline")
        print(f"  Baseline: {baseline_info}")
    for src, c in source_counts.items():
        print(f"  {src}: {c['found']} found, {c['changed']} changed")
    print(f"  Total changes: {len(all_changed)}")
    print(f"{'=' * 70}")

    return all_changed, source_counts, baseline if not url_is_dead else None, baseline_info


# ============================================================
# PHASE 2: VirusTotal
# ============================================================

def analyze_url_phase2(session, url, timeout=60,
                       save_diff=False, save_report=False, vt_key=None,
                       archive_only=False):

    print(f"\n{'=' * 70}")
    print(f"PHASE 2: VirusTotal")
    print(f"{'=' * 70}")
    print(f"URL: {url}")
    print(f"{'=' * 70}")

    source_counts = {'virustotal': {'found': 0, 'changed': 0}}

    if not vt_key:
        print("[VIRUSTOTAL] Skipped - no API key")
        return [], source_counts

    vt_snaps = virustotal_get_snapshots(session, url, timeout, api_key=vt_key)
    source_counts['virustotal']['found'] = len(vt_snaps)

    baseline = None
    baseline_label = "current"
    url_is_dead = False

    if archive_only:
        url_is_dead = True
        print("\n[*] ARCHIVE-ONLY mode: skipping live fetch")
    else:
        print("\n[*] Fetching current version...")
        current, http_code, err = fetch_url_with_status(session, url, timeout=timeout)
        if current:
            baseline = current
            print(f"[+] Current version fetched ({len(current)} chars)\n")
        else:
            url_is_dead = True
            print(f"[!] Could not fetch current version: {err}")

    if url_is_dead:
        if vt_snaps and vt_snaps[0].get('content'):
            vt_content = vt_snaps[0]['content']
            vt_time = vt_snaps[0].get('formatted_time', 'Unknown')
            print(f"[*] VT has cached response body from {vt_time}")
            ref_file = save_baseline_content(
                url, vt_content, 'virustotal',
                vt_snaps[0].get('timestamp', 'unknown')
            )
            if ref_file:
                print(f"[+] VT cached content saved: {ref_file}")
            print("[*] Reporting metadata only (single VT snapshot)")
        else:
            print("[*] VT has no cached content body")
            print("[*] Reporting metadata only")

    all_changed = []

    if vt_snaps:
        if baseline:
            print(f"\n[VIRUSTOTAL] Comparing {len(vt_snaps)} snapshot(s) vs current...\n")
            p2_changed, p2_fetched = compare_snapshots_phase(
                session, url, baseline, vt_snaps, source_counts,
                save_diff=save_diff, timeout=timeout, vt_key=vt_key,
                baseline_label=baseline_label
            )
            all_changed.extend(p2_changed)
        else:
            for snap in vt_snaps:
                if snap.get('vt_data'):
                    det = snap['vt_data'].get('detections', {})
                    mal = det.get('malicious', 0)
                    sus = det.get('suspicious', 0)
                    print(f"\n[VIRUSTOTAL] Metadata for dead URL:")
                    print(f"  Response SHA256: {snap['vt_data'].get('response_sha256', 'N/A')}")
                    print(f"  Final URL: {snap['vt_data'].get('final_url', 'N/A')}")
                    print(f"  Times submitted: {snap['vt_data'].get('times_submitted', 0)}")
                    print(f"  Detections: {mal} malicious, {sus} suspicious")
                    if snap['vt_data'].get('headers'):
                        print(f"  Last known headers:")
                        for k, v in list(snap['vt_data']['headers'].items())[:10]:
                            print(f"    {k}: {v}")
                    # Always include VT data in results for HTML report
                    changed_data = {
                        'source': 'virustotal',
                        'timestamp': snap.get('timestamp', ''),
                        'formatted_time': snap.get('formatted_time', 'Unknown'),
                        'view_url': snap.get('view_url', ''),
                        'added': 0, 'removed': 0, 'changes': [],
                        'content': '', 'vt_data': snap.get('vt_data'),
                    }
                    all_changed.append(changed_data)
                    if mal > 0 or sus > 0:
                        source_counts['virustotal']['changed'] += 1

        if save_report and all_changed:
            print("\n[*] Saving Phase 2 (VT) text report...")
            p2_report = save_multi_report(
                url, all_changed, source_counts,
                phase_label="phase2_vt",
                baseline_info="URL is dead" if url_is_dead else "Live version"
            )
            if p2_report:
                print(f"[+] Phase 2 report saved: {p2_report}")

    print(f"\n{'=' * 70}")
    print(f"PHASE 2 COMPLETE: {url}")
    print(f"{'=' * 70}")
    if url_is_dead:
        print(f"  NOTE: URL is dead - reported metadata only")
    c = source_counts['virustotal']
    print(f"  virustotal: {c['found']} found, {c['changed']} changed")
    print(f"{'=' * 70}")

    return all_changed, source_counts


# ============================================================
# DOMAIN MODE
# ============================================================

def discover_domain_urls(session, domain, vt_key, timeout):
    print(f"\n{'=' * 70}")
    print(f"DOMAIN DISCOVERY: {domain}")
    print(f"{'=' * 70}")
    if not vt_key:
        print("\n[!] Domain mode requires VirusTotal API key")
        return [], [], None
    print(f"\n[*] Querying VT for URLs related to {domain}...")
    discovered_urls, subdomains = vt_v2_domain_report(session, domain, vt_key, timeout)
    if not discovered_urls:
        print(f"\n[!] No URLs found for domain {domain} on VirusTotal")
        return [], subdomains, None
    print(f"\n[+] Discovered {len(discovered_urls)} URLs")
    if subdomains:
        print(f"Subdomains found: {len(subdomains)}")
        for sub in subdomains[:20]:
            print(f"  {sub}")
        if len(subdomains) > 20:
            print(f"  ... and {len(subdomains) - 20} more")
    sorted_urls = sorted(discovered_urls)
    print(f"URLs discovered:")
    for u in sorted_urls[:30]:
        print(f"  {u}")
    if len(sorted_urls) > 30:
        print(f"  ... and {len(sorted_urls) - 30} more")
    os.makedirs('output', exist_ok=True)
    safe_domain = domain.replace('.', '_')
    urls_file = os.path.join('output', f"{safe_domain}_vt_discovered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(urls_file, 'w', encoding='utf-8') as f:
        for u in sorted_urls:
            f.write(u + '\n')
    print(f"\n[+] Discovered URLs saved: {urls_file}")
    return sorted_urls, subdomains, urls_file


# ============================================================
# CLI
# ============================================================

def main():
    banner = """
============================================================
   Multi-Source Web Change Detector
   Wayback + CommonCrawl + urlscan.io + VirusTotal
============================================================
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description='Multi-source web change detector with archive-only mode for dead URLs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Phase 1 inputs (Wayback + CommonCrawl + urlscan):
  -u URL             Single URL
  -l FILE            URL list file (one per line)

Phase 2 inputs (VirusTotal):
  --vt-url URL       Single URL for VT analysis
  --vt-list FILE     URL list file for VT analysis
  -d DOMAIN          Discover URLs from VT v2 domain/report, then analyze

Dead URL handling:
  --archive-only     Skip live fetch entirely. Always use newest archived
                     snapshot as baseline and compare older ones against it.

  (default)          Try to fetch live URL first. If dead/unreachable,
                     automatically fallback to archived baseline.

Reports:
  -r / --report      Generate styled HTML report (includes full VT data)
                     plus text reports per phase.
  --diff             Also generate individual HTML diff files.

Pause/Resume:
  Press ENTER at any time to pause. Press ENTER again to resume.

Resume:
  --resume           Resume interrupted run - skip already processed URLs
        """
    )

    p1_group = parser.add_argument_group('Phase 1: Wayback + CommonCrawl + urlscan')
    p1_input = p1_group.add_mutually_exclusive_group()
    p1_input.add_argument('-u', '--url', help='Single URL for Phase 1')
    p1_input.add_argument('-l', '--list', help='URL list file for Phase 1')

    p2_group = parser.add_argument_group('Phase 2: VirusTotal')
    p2_input = p2_group.add_mutually_exclusive_group()
    p2_input.add_argument('--vt-url', help='Single URL for Phase 2 (VirusTotal)')
    p2_input.add_argument('--vt-list', help='URL list file for Phase 2')
    p2_input.add_argument('-d', '--domain', help='Domain discovery via VT')

    parser.add_argument('-s', '--snapshots', type=int, default=10,
                       help='Max snapshots per source (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=None,
                       help='Timeout per request in seconds')
    parser.add_argument('--diff', action='store_true', help='Save HTML diff files')
    parser.add_argument('-r', '--report', action='store_true', help='Save HTML + text reports')
    parser.add_argument('--vt-key', help='VirusTotal API key')
    parser.add_argument('--urlscan-key', help='urlscan.io API key')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--resume', action='store_true', help='Resume interrupted run')
    parser.add_argument('--archive-only', action='store_true',
                       help='Skip live URL fetch. Always use newest archived snapshot as '
                            'baseline. Use when analyzing URLs from archives that are '
                            'likely dead now.')

    args = parser.parse_args()

    if not args.url and not args.list and not args.vt_url and not args.vt_list and not args.domain:
        parser.error('At least one input is required: -u, -l, --vt-url, --vt-list, or -d')

    pause.start()
    if sys.stdin.isatty():
        print("[*] Press ENTER at any time to pause/resume\n")

    config = load_config(args.config)
    vt_key = resolve_key(args.vt_key, 'VT_API_KEY', config['api_keys'].get('virustotal', ''))
    urlscan_key = resolve_key(args.urlscan_key, 'URLSCAN_API_KEY', config['api_keys'].get('urlscan', ''))

    if args.timeout is not None:
        timeout = args.timeout
    elif config['settings'].get('timeout'):
        timeout = int(config['settings']['timeout'])
    else:
        timeout = 60

    proxy = args.proxy or config['settings'].get('proxy', '') or None
    session = create_session(proxy=proxy)

    vt_status = "[+]" if vt_key else "[-]"
    us_status = "[+]" if urlscan_key else "[-]"
    print(f"[*] API Keys: VT={vt_status}  urlscan={us_status}")
    print(f"[*] Timeout: {timeout}s")
    if args.archive_only:
        print(f"[*] Mode: ARCHIVE-ONLY (never fetch live URLs)")
    else:
        print(f"[*] Mode: AUTO (try live, fallback to archive if dead)")
    if proxy:
        print(f"[*] Proxy: {proxy}")

    p1_urls = []
    if args.url:
        p1_urls.append(args.url)
    elif args.list:
        p1_urls = load_urls_from_file(args.list)

    p2_urls = []
    p2_domain = None
    if args.vt_url:
        p2_urls.append(args.vt_url)
    elif args.vt_list:
        p2_urls = load_urls_from_file(args.vt_list)
    elif args.domain:
        p2_domain = args.domain.lower().strip().rstrip('/')
        if p2_domain.startswith('http://') or p2_domain.startswith('https://'):
            p2_domain = urlparse(p2_domain).netloc
        if ':' in p2_domain:
            p2_domain = p2_domain.split(':')[0]

    progress_path = get_progress_path(p1_urls, p2_urls, label="multi")
    p1_completed = set()
    p2_completed = set()

    if args.resume:
        resume_data = load_progress(progress_path)
        if resume_data:
            p1_completed = set(resume_data.get('p1_completed_urls', []))
            p2_completed = set(resume_data.get('p2_completed_urls', []))
            print(f"[*] RESUME: Phase 1 done: {len(p1_completed)}/{len(p1_urls)} URLs")
            print(f"[*] RESUME: Phase 2 done: {len(p2_completed)}/{len(p2_urls)} URLs")
        else:
            print(f"[*] RESUME: No previous progress, starting fresh")

    print(f"\n{'=' * 70}")
    print(f"EXECUTION PLAN")
    print(f"{'=' * 70}")
    if p1_urls:
        p1_skip = len(p1_completed.intersection(set(p1_urls)))
        print(f"Phase 1 (WB+CC+urlscan): {len(p1_urls)} URL(s)" + (f" ({p1_skip} already done)" if p1_skip else ""))
        for u in p1_urls[:5]:
            print(f"  {u}")
        if len(p1_urls) > 5:
            print(f"  ... and {len(p1_urls) - 5} more")
    else:
        print(f"Phase 1: SKIPPED")
    if p2_urls:
        p2_skip = len(p2_completed.intersection(set(p2_urls)))
        print(f"Phase 2 (VirusTotal):    {len(p2_urls)} URL(s)" + (f" ({p2_skip} already done)" if p2_skip else ""))
    elif p2_domain:
        print(f"Phase 2: Domain discovery: {p2_domain}")
    else:
        print(f"Phase 2: SKIPPED")
    if args.archive_only:
        print(f"Mode: ARCHIVE-ONLY")
    print(f"Resume: {'ON' if args.resume else 'OFF'}")
    print(f"HTML Report: {'ON' if args.report else 'OFF'}")
    print(f"{'=' * 70}")

    all_p1_results = {}
    all_p2_results = {}
    all_p1_source_counts = {}
    all_p2_source_counts = {}
    all_baseline_info = {}
    dead_urls = []
    alive_urls = []

    # ============================================================
    # PHASE 1
    # ============================================================
    if p1_urls:
        print(f"\n{'#' * 70}")
        print(f"# PHASE 1: Wayback + CommonCrawl + urlscan ({len(p1_urls)} URLs)")
        if args.archive_only:
            print(f"# MODE: ARCHIVE-ONLY (skipping live fetch for ALL URLs)")
        print(f"{'#' * 70}")

        p1_skipped = 0
        for i, url in enumerate(p1_urls, 1):
            if url in p1_completed:
                p1_skipped += 1
                if p1_skipped <= 3 or p1_skipped == len(p1_completed):
                    print(f"[SKIP] {url} (already processed)")
                elif p1_skipped == 4:
                    remaining_skip = len(p1_completed.intersection(set(p1_urls))) - 3
                    print(f"[SKIP] ... skipping {remaining_skip} more ...")
                continue

            pause.check()

            if len(p1_urls) > 1:
                remaining = len(p1_urls) - len(p1_completed) - (i - p1_skipped - 1)
                print(f"\n{'#' * 70}")
                print(f"# Phase 1 - URL {i}/{len(p1_urls)} ({remaining} remaining): {url}")
                print(f"{'#' * 70}")

            changed, counts, current, bl_info = analyze_url_phase1(
                session, url,
                max_snapshots=args.snapshots,
                timeout=timeout,
                save_diff=args.diff,
                save_report=args.report,
                urlscan_key=urlscan_key,
                archive_only=args.archive_only,
            )

            if changed:
                all_p1_results[url] = changed
            all_p1_source_counts[url] = counts
            all_baseline_info[url] = bl_info

            if current is None:
                dead_urls.append(url)
            else:
                alive_urls.append(url)

            p1_completed.add(url)
            save_progress(progress_path, {
                'p1_completed_urls': sorted(p1_completed),
                'p2_completed_urls': sorted(p2_completed),
                'p1_urls_with_changes': list(all_p1_results.keys()),
                'dead_urls': dead_urls,
                'alive_urls': alive_urls,
            })
            print(f"\n[*] Progress saved: P1 {len(p1_completed)}/{len(p1_urls)} done")

            if i < len(p1_urls):
                next_url = p1_urls[i] if i < len(p1_urls) else None
                if next_url and next_url not in p1_completed:
                    print(f"\n[*] Waiting 3 seconds before next URL...")
                    time.sleep(3)

        if len(p1_urls) > 1:
            print(f"\n{'=' * 70}")
            print(f"PHASE 1 BATCH SUMMARY")
            print(f"{'=' * 70}")
            print(f"Total URLs analyzed: {len(p1_urls)}")
            print(f"URLs with changes: {len(all_p1_results)}")
            if args.archive_only:
                print(f"Mode: ARCHIVE-ONLY (live fetch skipped)")
            if p1_skipped:
                print(f"URLs skipped (resumed): {p1_skipped}")
            if dead_urls:
                print(f"Dead/unreachable URLs: {len(dead_urls)} (used archived baseline)")
                for u in dead_urls[:10]:
                    print(f"  [DEAD] {u}")
                if len(dead_urls) > 10:
                    print(f"  ... and {len(dead_urls) - 10} more")
            if alive_urls and not args.archive_only:
                print(f"Alive URLs: {len(alive_urls)}")
            if all_p1_results:
                for url_k, results in all_p1_results.items():
                    src_set = set(r['source'] for r in results)
                    status = " [DEAD]" if url_k in dead_urls else ""
                    print(f"  - {url_k}{status} ({len(results)} changes from: {', '.join(src_set)})")
            print(f"{'=' * 70}")

        print(f"\n[+] Phase 1 complete. Results are saved.")

    # ============================================================
    # PHASE 2
    # ============================================================
    if p2_domain:
        discovered, subdomains, urls_file = discover_domain_urls(
            session, p2_domain, vt_key, timeout
        )
        if discovered:
            p2_urls = discovered

    if p2_urls:
        print(f"\n{'#' * 70}")
        print(f"# PHASE 2: VirusTotal ({len(p2_urls)} URLs)")
        print(f"{'#' * 70}")

        p2_skipped = 0
        for i, url in enumerate(p2_urls, 1):
            if url in p2_completed:
                p2_skipped += 1
                if p2_skipped <= 3 or p2_skipped == len(p2_completed):
                    print(f"[SKIP] {url} (already processed)")
                elif p2_skipped == 4:
                    remaining_skip = len(p2_completed.intersection(set(p2_urls))) - 3
                    print(f"[SKIP] ... skipping {remaining_skip} more ...")
                continue

            pause.check()

            if len(p2_urls) > 1:
                print(f"\n{'#' * 70}")
                print(f"# Phase 2 - URL {i}/{len(p2_urls)}: {url}")
                print(f"{'#' * 70}")

            changed, counts = analyze_url_phase2(
                session, url, timeout=timeout,
                save_diff=args.diff, save_report=args.report,
                vt_key=vt_key, archive_only=args.archive_only,
            )

            if changed:
                all_p2_results[url] = changed
            all_p2_source_counts[url] = counts

            p2_completed.add(url)
            save_progress(progress_path, {
                'p1_completed_urls': sorted(p1_completed),
                'p2_completed_urls': sorted(p2_completed),
                'p1_urls_with_changes': list(all_p1_results.keys()),
                'p2_urls_with_changes': list(all_p2_results.keys()),
                'dead_urls': dead_urls,
            })
            print(f"\n[*] Progress saved: P2 {len(p2_completed)}/{len(p2_urls)} done")

            if i < len(p2_urls):
                next_url = p2_urls[i] if i < len(p2_urls) else None
                if next_url and next_url not in p2_completed:
                    print(f"\n[*] Waiting 2 seconds before next URL...")
                    time.sleep(2)

        if len(p2_urls) > 1:
            print(f"\n{'=' * 70}")
            print(f"PHASE 2 BATCH SUMMARY")
            print(f"{'=' * 70}")
            print(f"Total URLs: {len(p2_urls)}")
            print(f"URLs with changes/flags: {len(all_p2_results)}")
            if p2_skipped:
                print(f"URLs skipped (resumed): {p2_skipped}")
            print(f"{'=' * 70}")

    # ============================================================
    # GENERATE HTML REPORTS (per URL)
    # ============================================================
    if args.report:
        print(f"\n[*] Generating HTML reports...")
        all_reported_urls = set(p1_urls) | set(p2_urls)
        for url in all_reported_urls:
            p1_changed = all_p1_results.get(url, [])
            p2_changed = all_p2_results.get(url, [])
            p1_sc = all_p1_source_counts.get(url, {})
            p2_sc = all_p2_source_counts.get(url, {})
            bl_info = all_baseline_info.get(url, "")

            if not p1_changed and not p2_changed and not p2_sc:
                continue

            html_path = generate_full_html_report(
                url,
                all_p1_changed=p1_changed,
                all_p2_changed=p2_changed,
                p1_source_counts=p1_sc,
                p2_source_counts=p2_sc,
                dead_urls=dead_urls,
                baseline_info=bl_info,
                archive_only=args.archive_only,
            )
            if html_path:
                print(f"[+] HTML report: {html_path}")

    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    total_p1 = sum(len(v) for v in all_p1_results.values())
    total_p2 = sum(len(v) for v in all_p2_results.values())

    print(f"\n{'=' * 70}")
    print(f"FINAL SUMMARY")
    print(f"{'=' * 70}")

    if p1_urls:
        print(f"\n  Phase 1 (WB + CC + urlscan):")
        print(f"    URLs analyzed:    {len(p1_urls)}")
        print(f"    URLs w/ changes:  {len(all_p1_results)}")
        print(f"    Total changes:    {total_p1}")
        if dead_urls:
            print(f"    Dead URLs:        {len(dead_urls)} (used archived baseline)")
        if args.archive_only:
            print(f"    Mode:             ARCHIVE-ONLY")

    if p2_urls or p2_domain:
        p2_count = len(p2_urls) if p2_urls else 0
        print(f"\n  Phase 2 (VirusTotal):")
        if p2_domain:
            print(f"    Domain:           {p2_domain}")
        print(f"    URLs analyzed:    {p2_count}")
        print(f"    URLs w/ changes:  {len(all_p2_results)}")
        print(f"    Total changes:    {total_p2}")

    if args.diff:
        print(f"\n  HTML diffs: html/ folder")
    if args.report:
        print(f"  Reports:   reports/ folder (HTML + text)")
    if dead_urls:
        print(f"  Baselines: output/ folder (archived content for dead URLs)")

    all_p1_done = len(p1_completed) >= len(p1_urls) if p1_urls else True
    all_p2_done = len(p2_completed) >= len(p2_urls) if p2_urls else True

    if all_p1_done and all_p2_done:
        cleanup_progress(progress_path)
        print(f"\n[+] All URLs processed. Progress file cleaned up.")
    else:
        remaining = 0
        if p1_urls:
            remaining += len(p1_urls) - len(p1_completed)
        if p2_urls:
            remaining += len(p2_urls) - len(p2_completed)
        print(f"\n[*] Run with --resume to continue ({remaining} URLs remaining)")

    print(f"\n{'=' * 70}")
    print(f"Done.")
    print(f"{'=' * 70}")

    pause.stop()


if __name__ == "__main__":
    main()
