#!/usr/bin/env python3
"""
Wayback Machine Auto-Discovery Version
Automatically finds all snapshots - NO manual timestamps needed!

Resume support:
  --resume flag reloads progress from previous interrupted run.
  Progress saved incrementally after each URL completes.

Pause/Resume:
  Press ENTER at any time to pause. Press ENTER again to resume.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse
from datetime import datetime
from difflib import unified_diff, HtmlDiff
from urllib.parse import urlparse
import time
import json
import hashlib
import threading
import sys
import os


# ============================================================
# PAUSE CONTROLLER (ffuf-style Enter to pause/resume)
# ============================================================

class PauseController:
    """
    ffuf-style pause/resume: press Enter to toggle pause.
    A background daemon thread monitors stdin for Enter presses.
    Call check() at checkpoints - it blocks while paused.
    """

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
# PROGRESS TRACKING
# ============================================================

def get_progress_path(urls, label="wayback"):
    os.makedirs('output', exist_ok=True)
    key = "|".join(sorted(urls[:20]))
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
# SESSION & FETCH
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
        total=3,
        backoff_factor=2,
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


def fetch_url(session, url, timeout=40):
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            return response.text
    except requests.exceptions.ConnectTimeout:
        print(f"    [!] Connection timeout (server not responding)")
    except requests.exceptions.ReadTimeout:
        print(f"    [!] Read timeout (server too slow)")
    except requests.exceptions.ConnectionError as e:
        print(f"    [!] Connection error: {e}")
    except requests.exceptions.RequestException as e:
        print(f"    [!] Request error: {e}")
    return None


# ============================================================
# SNAPSHOT DISCOVERY
# ============================================================

def get_snapshots_auto(session, url, max_snapshots=10, timeout=60):
    print(f"[*] Auto-discovering snapshots for: {url}")
    print(f"[*] Trying multiple methods...\n")

    timestamps = []

    print("[Method 1] CDX API (basic text)...")
    try:
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            'url': url,
            'matchType': 'exact',
            'limit': max_snapshots * 3
        }

        response = session.get(cdx_url, params=params, timeout=timeout)

        if response.status_code == 200 and response.text:
            lines = response.text.strip().split('\n')
            print(f"    Got {len(lines)} lines from CDX")

            for line in lines:
                parts = line.split()
                for part in parts:
                    if len(part) == 14 and part.isdigit():
                        if part not in timestamps:
                            timestamps.append(part)
                        break

            print(f"    [+] Found {len(timestamps)} timestamps")
    except requests.exceptions.ConnectTimeout:
        print(f"    [!] Connection timeout - server not reachable")
    except requests.exceptions.ReadTimeout:
        print(f"    [!] Read timeout - try increasing timeout with -t flag")
    except requests.exceptions.ConnectionError:
        print(f"    [!] Connection error - check your internet or try a proxy")
    except Exception as e:
        print(f"    [!] Failed: {e}")

    if not timestamps:
        print("\n[Method 2] Availability API (get one snapshot)...")
        try:
            avail_url = "https://archive.org/wayback/available"
            response = session.get(avail_url, params={'url': url}, timeout=timeout)

            if response.status_code == 200:
                data = response.json()
                if data.get('archived_snapshots', {}).get('closest', {}).get('available'):
                    ts = data['archived_snapshots']['closest']['timestamp']
                    timestamps.append(ts)
                    print(f"    [+] Found 1 timestamp: {ts}")
                else:
                    print(f"    [!] URL not found in archive")
        except requests.exceptions.ConnectTimeout:
            print(f"    [!] Connection timeout - server not reachable")
        except requests.exceptions.ReadTimeout:
            print(f"    [!] Read timeout - try increasing timeout with -t flag")
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection error - check your internet or try a proxy")
        except Exception as e:
            print(f"    [!] Failed: {e}")

    if not timestamps:
        print("\n[Method 3] Trying common timestamps...")
        current_year = datetime.now().year

        for year in [current_year, current_year - 1]:
            for month in [1, 3, 6, 9, 12]:
                ts = f"{year}{month:02d}15120000"
                timestamps.append(ts)

        print(f"    [+] Generated {len(timestamps)} candidate timestamps")

    timestamps = sorted(list(set(timestamps)), reverse=True)
    timestamps = timestamps[:max_snapshots]

    print(f"\n[+] Will check {len(timestamps)} snapshots\n")

    return timestamps


def get_archived_content(session, url, timestamp, timeout=40):
    wayback_url = f"https://web.archive.org/web/{timestamp}id_/{url}"
    content = fetch_url(session, wayback_url, timeout=timeout)

    if not content:
        wayback_url = f"https://web.archive.org/web/{timestamp}/{url}"
        content = fetch_url(session, wayback_url, timeout=timeout)

    return content


# ============================================================
# COMPARISON & REPORTING
# ============================================================

def compare_and_show(old_content, new_content):
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

    added = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    removed = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))

    return True, added, removed, changes


def generate_html_diff(old_content, new_content, timestamp, url):
    try:
        html_folder = "html"
        if not os.path.exists(html_folder):
            os.makedirs(html_folder)
            print(f"    [+] Created '{html_folder}/' folder")

        old_lines = old_content.split('\n')
        new_lines = new_content.split('\n')

        ts = timestamp.ljust(14, '0')
        formatted_date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"

        diff_maker = HtmlDiff()
        html_diff = diff_maker.make_file(
            old_lines, new_lines,
            fromdesc=f'Archived ({formatted_date})',
            todesc='Current Version',
            context=True, numlines=3
        )

        domain = urlparse(url).netloc.replace('.', '_')
        filename = f"diff_{domain}_{timestamp}.html"
        output_file = os.path.join(html_folder, filename)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_diff)

        return output_file
    except Exception as e:
        print(f"    [!] Error generating HTML diff: {e}")
        return None


def save_text_report(url, changed_snapshots):
    try:
        reports_folder = "reports"
        if not os.path.exists(reports_folder):
            os.makedirs(reports_folder)
            print(f"[+] Created '{reports_folder}/' folder")

        domain = urlparse(url).netloc.replace('.', '_')
        filename = f"wayback_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        output_path = os.path.join(reports_folder, filename)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"Wayback Machine Change Report\n")
            f.write(f"{'=' * 70}\n")
            f.write(f"URL: {url}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total versions with changes: {len(changed_snapshots)}\n")
            f.write(f"{'=' * 70}\n\n")

            for i, snap in enumerate(changed_snapshots, 1):
                f.write(f"\n{'=' * 70}\n")
                f.write(f"Version {i}: {snap['formatted_time']}\n")
                f.write(f"{'=' * 70}\n")
                f.write(f"Lines Added: +{snap['added']}\n")
                f.write(f"Lines Removed: -{snap['removed']}\n")
                f.write(f"Wayback URL: {snap['wayback_url']}\n\n")

                if snap['changes']:
                    f.write(f"Changes (first 50):\n")
                    f.write("-" * 70 + "\n")
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


# ============================================================
# ANALYZE SINGLE URL
# ============================================================

def analyze_url(session, url, max_snapshots=10, timeout=40, save_diff=False, save_report=False):
    print(f"\n{'='*70}")
    print(f"WAYBACK AUTO-DISCOVERY MODE")
    print(f"{'='*70}")
    print(f"URL: {url}")
    print(f"Max snapshots: {max_snapshots}")
    print(f"Timeout: {timeout}s per request")
    print(f"Save HTML diffs: {save_diff}")
    print(f"Save text report: {save_report}")
    print(f"{'='*70}\n")

    timestamps = get_snapshots_auto(session, url, max_snapshots, timeout=timeout)

    if not timestamps:
        print("[!] Could not find any snapshots")
        print("\n[*] Possible causes:")
        print("    - Wayback Machine may be temporarily down")
        print("    - Your network may be blocking connections to web.archive.org")
        print("    - Try using a VPN or proxy (--proxy flag)")
        print("    - Try increasing timeout (-t flag)")
        print(f"\n[*] Try manually checking at:")
        print(f"    https://web.archive.org/web/*/{url}")
        return []

    print("[*] Fetching current version...")
    current = fetch_url(session, url, timeout=timeout)

    if not current:
        print("[!] Could not fetch current version")
        print("[*] Will compare archived versions with each other instead\n")
    else:
        print("[+] Current version fetched\n")

    print("="*70)
    print("COMPARING SNAPSHOTS")
    print("="*70 + "\n")

    changes_found = 0
    archived_versions = {}
    changed_snapshots = []

    for i, ts in enumerate(timestamps, 1):
        pause.check()  # <-- pause checkpoint before each snapshot

        formatted = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}"

        print(f"[{i}/{len(timestamps)}] {formatted}")
        print(f"    URL: https://web.archive.org/web/{ts}/{url}")

        archived = get_archived_content(session, url, ts, timeout=timeout)

        if archived:
            archived_versions[ts] = archived

            if current:
                has_changes, added, removed, changes = compare_and_show(archived, current)

                if has_changes:
                    print(f"    [!] CHANGES: +{added} -{removed} lines")

                    if changes:
                        print(f"    [*] Sample (first 5):")
                        for change in changes[:5]:
                            prefix = change[0]
                            content = change[1:].strip()[:65]
                            print(f"        {prefix} {content}")

                    changes_found += 1

                    snap_data = {
                        'timestamp': ts,
                        'formatted_time': formatted,
                        'wayback_url': f"https://web.archive.org/web/{ts}/{url}",
                        'added': added,
                        'removed': removed,
                        'changes': changes,
                        'content': archived
                    }
                    changed_snapshots.append(snap_data)

                    if save_diff:
                        diff_file = generate_html_diff(archived, current, ts, url)
                        if diff_file:
                            print(f"    [+] Diff saved: {diff_file}")
                else:
                    print(f"    [=] No changes from current")
            else:
                print(f"    [+] Archived version fetched")
        else:
            print(f"    [!] Could not fetch (may not exist or timed out)")

        print()
        time.sleep(1)

    if len(archived_versions) > 1 and not current:
        print("\n" + "="*70)
        print("COMPARING ARCHIVED VERSIONS WITH EACH OTHER")
        print("="*70 + "\n")

        ts_sorted = sorted(archived_versions.keys())

        for i in range(len(ts_sorted) - 1):
            ts1 = ts_sorted[i]
            ts2 = ts_sorted[i + 1]

            fmt1 = f"{ts1[:4]}-{ts1[4:6]}-{ts1[6:8]}"
            fmt2 = f"{ts2[:4]}-{ts2[4:6]}-{ts2[6:8]}"

            has_changes, added, removed, changes = compare_and_show(
                archived_versions[ts1],
                archived_versions[ts2]
            )

            if has_changes:
                print(f"[!] Changes between {fmt1} and {fmt2}")
                print(f"    +{added} -{removed} lines")

                if changes:
                    for change in changes[:3]:
                        print(f"    {change[:70]}")

                print()

    if save_report and changed_snapshots:
        print("\n[*] Saving text report...")
        report_file = save_text_report(url, changed_snapshots)
        if report_file:
            print(f"[+] Report saved: {report_file}")

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Snapshots checked: {len(timestamps)}")
    print(f"Successfully fetched: {len(archived_versions)}")
    if current:
        print(f"Changes from current: {changes_found}")
    if save_diff and changed_snapshots:
        print(f"HTML diffs saved: {len(changed_snapshots)} files in html/")
    if save_report and changed_snapshots:
        print(f"Text report saved: reports/")
    print("="*70)

    return changed_snapshots


# ============================================================
# MAIN
# ============================================================

def main():
    print("""
============================================================
   Wayback AUTO-DISCOVERY - No Timestamps Needed
   Automatically finds and compares ALL snapshots
============================================================
    """)

    parser = argparse.ArgumentParser(
        description='Auto-discover snapshots - NO timestamps needed!'
    )
    parser.add_argument('-u', '--url',
                       help='Single URL to analyze')
    parser.add_argument('-l', '--list',
                       help='File containing list of URLs (one per line)')
    parser.add_argument('-s', '--snapshots', type=int, default=10,
                       help='Maximum snapshots to check per URL (default: 10)')
    parser.add_argument('-a', '--all', action='store_true',
                       help='Check ALL available snapshots (no limit)')
    parser.add_argument('-t', '--timeout', type=int, default=60,
                       help='Timeout in seconds per request (default: 60)')
    parser.add_argument('-d', '--diff', action='store_true',
                       help='Save HTML diff files showing exact changes')
    parser.add_argument('-r', '--report', action='store_true',
                       help='Save detailed text change report')
    parser.add_argument('--proxy',
                       help='Proxy URL (e.g. socks5h://127.0.0.1:9050 or http://127.0.0.1:8080)')
    parser.add_argument('--resume', action='store_true',
                       help='Resume interrupted run - skip already processed URLs')

    args = parser.parse_args()

    # Start pause controller
    pause.start()
    if sys.stdin.isatty():
        print("[*] Press ENTER at any time to pause/resume\n")

    session = create_session(proxy=args.proxy)

    max_snapshots = args.snapshots
    if args.all:
        max_snapshots = 1000
        print("[!] ALL SNAPSHOTS MODE - This may take a while!\n")

    urls = []

    if args.url:
        urls.append(args.url)

    if args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
            print(f"[+] Loaded {len(urls)} URLs from {args.list}\n")
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return

    if not urls:
        print("[!] No URLs provided")
        print("\nUsage:")
        print("  Single URL:")
        print("    python3 wayback.py -u 'https://example.com/api/config'")
        print("\n  Multiple URLs from file:")
        print("    python3 wayback.py -l urls.txt -s 10")
        print("\n  Resume interrupted run:")
        print("    python3 wayback.py -l urls.txt -s 10 --resume")
        print("\n  Check ALL snapshots:")
        print("    python3 wayback.py -u 'https://example.com' -a")
        print("\n  With HTML diff output:")
        print("    python3 wayback.py -u 'https://example.com' -d")
        print("\n  With text report:")
        print("    python3 wayback.py -u 'https://example.com' -r")
        print("\n  Full options:")
        print("    python3 wayback.py -u 'https://example.com' -s 20 -d -r -t 90")
        print("\n  Through a proxy:")
        print("    python3 wayback.py -u 'https://example.com' --proxy socks5h://127.0.0.1:9050")
        return

    # Resume handling
    progress_path = get_progress_path(urls, label="wayback")
    completed_urls = set()

    if args.resume:
        resume_data = load_progress(progress_path)
        if resume_data:
            completed_urls = set(resume_data.get('completed_urls', []))
            prev_results = resume_data.get('urls_with_changes', [])
            print(f"[*] RESUME MODE: Found previous progress")
            print(f"[*] RESUME: {len(completed_urls)}/{len(urls)} URLs already processed")
            print(f"[*] RESUME: {len(prev_results)} URLs had changes")
            print(f"[*] RESUME: Last updated: {resume_data.get('updated_at', 'unknown')}")
            remaining = len(urls) - len(completed_urls)
            print(f"[*] RESUME: {remaining} URLs remaining\n")
        else:
            print(f"[*] RESUME: No previous progress found, starting fresh\n")

    all_results = {}
    skipped = 0

    for i, url in enumerate(urls, 1):
        if url in completed_urls:
            skipped += 1
            if skipped <= 5 or skipped == len(completed_urls):
                print(f"[SKIP] {url} (already processed)")
            elif skipped == 6:
                print(f"[SKIP] ... skipping {len(completed_urls) - 5} more ...")
            continue

        pause.check()  # <-- pause checkpoint before each URL

        if len(urls) > 1:
            remaining = len(urls) - len(completed_urls) - len(all_results)
            print(f"\n{'#'*70}")
            print(f"# URL {i}/{len(urls)} ({remaining} remaining): {url}")
            print(f"{'#'*70}")

        results = analyze_url(
            session, url,
            max_snapshots=max_snapshots,
            timeout=args.timeout,
            save_diff=args.diff,
            save_report=args.report
        )

        if results:
            all_results[url] = results

        completed_urls.add(url)

        if len(urls) > 1:
            save_progress(progress_path, {
                'total_urls': len(urls),
                'completed_urls': sorted(completed_urls),
                'urls_with_changes': list(all_results.keys()),
            })
            print(f"\n[*] Progress saved: {len(completed_urls)}/{len(urls)} URLs done")

        if i < len(urls):
            next_url = urls[i] if i < len(urls) else None
            if next_url and next_url not in completed_urls:
                print(f"\n[*] Waiting 3 seconds before next URL...")
                time.sleep(3)

    if len(urls) > 1:
        print(f"\n{'='*70}")
        print("BATCH SUMMARY")
        print(f"{'='*70}")
        print(f"Total URLs in list: {len(urls)}")
        print(f"URLs processed: {len(completed_urls)}")
        print(f"URLs with changes: {len(all_results)}")
        if skipped:
            print(f"URLs skipped (resumed): {skipped}")
        if args.diff:
            print(f"HTML diffs: html/ folder")
        if args.report:
            print(f"Text reports: reports/ folder")
        print(f"{'='*70}")

    if len(completed_urls) >= len(urls):
        cleanup_progress(progress_path)
        print(f"\n[+] All URLs processed. Progress file cleaned up.")
    else:
        print(f"\n[*] Run with --resume to continue ({len(urls) - len(completed_urls)} URLs remaining)")

    pause.stop()


if __name__ == "__main__":
    main()
