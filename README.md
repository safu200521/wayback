# 
db\u0009 JS Recon & Vulnerability Toolkit

A suite of Python tools for **web reconnaissance**, **URL discovery from archives**, **endpoint filtering**, and **JavaScript vulnerability scanning** \u2014 designed for bug-bounty hunters, pentesters, and security researchers.

> \u26a0\ufe0f **Legal Disclaimer**: These tools are for authorized security testing and educational purposes only. Only run them against targets you own or have explicit permission to test. The author is not responsible for misuse.

---

## 
d6\u0009 Tools Included

| Tool | Purpose |
|------|---------|
| **`url_grabber.py`** | Discover URLs from Wayback Machine, Common Crawl, and urlscan.io |
| **`grep_endpoints.py`** | Filter JS / JSON / XML endpoints from a URL list (fast + optional Content-Type verification) |
| **`js_vuln_scanner.py`** | Scan JS files for DOM XSS, prototype pollution, open redirects, postMessage flaws, and more |
| **`multi_source.py`** | Detect content changes across Wayback + CommonCrawl + urlscan + VirusTotal |
| **`wayback.py`** | Wayback-only change detection with auto snapshot discovery |

---

## 
9e\u0009 Quick Start

### Install
```bash
git clone https://github.com/<your-user>/js-recon-toolkit.git
cd js-recon-toolkit
pip install -r requirements.txt
```

### Typical Workflow
```bash
# 1. Discover URLs for a target
python url_grabber.py -d example.com --check-alive

# 2. Extract JS endpoints
python grep_endpoints.py -i output/example_com_alive.txt --ext js -o js_urls.txt

# 3. Scan JS for vulnerabilities
python js_vuln_scanner.py --urls js_urls.txt -o report.html

# 4. Check archived versions of dead URLs
python multi_source.py -l output/example_com_dead.txt --archive-only -r
```

---

## 
dd\u0009 Tool Details

### 1. `url_grabber.py`
Multi-source URL discovery from public web archives.

**Features:**
- 3 sources: **Wayback Machine + Common Crawl + urlscan.io**
- Domain mode (subdomains included) or host mode (exact host)
- Liveness checking (`--check-alive`)
- URL categorization (JS, CSS, API, config, etc.)
- Pause/resume with `ENTER` key
- Progress saved across runs (`--resume`)

```bash
# Discover all URLs for domain + subdomains
python url_grabber.py -d example.com

# Only exact host
python url_grabber.py -u https://api.example.com

# With liveness check
python url_grabber.py -d example.com --check-alive

# Filter by extension
python url_grabber.py -d example.com --filter js,json,xml
```

### 2. `grep_endpoints.py`
Filter JS/JSON/XML endpoints from a URL list.

**Two modes:**
- **Fast** (default): path-based extension filtering
- **Verified** (`--verify`): HEAD requests check Content-Type

```bash
# Filter from file
python grep_endpoints.py -i urls.txt --ext js,json,xml -o filtered.txt

# Pipe from url_grabber
python url_grabber.py -d example.com -q | python grep_endpoints.py --ext js

# With Content-Type verification
python grep_endpoints.py -i urls.txt --verify --threads 30
```

### 3. `js_vuln_scanner.py`
Scans JavaScript files for security-relevant patterns.

**Detects:**
- DOM XSS sinks (`innerHTML`, `eval`, `document.write`, jQuery `.html`)
- DOM XSS sources (`location.hash`, `postMessage`, `window.name`)
- Prototype pollution (`__proto__`, deep merge, Lodash)
- Open redirects, CORS misconfigs, JSONP issues
- Insecure storage (tokens in localStorage)
- Template injection (React `dangerouslySetInnerHTML`, Vue `v-html`)
- Insecure crypto (Math.random, MD5/SHA1)
- Supply-chain risks (dynamic script src, service workers)

```bash
# Scan local JS files
python js_vuln_scanner.py --js-dir js_files/

# Download and scan from URLs
python js_vuln_scanner.py --urls js_urls.txt -o report.html -v
```

Produces a rich **HTML report** with severity, exploitation steps, and remediation.

### 4. `multi_source.py`
Full change-detection pipeline across multiple archive sources.

```bash
# Full analysis
python multi_source.py -u https://example.com/page -r

# Batch from URL list
python multi_source.py -l urls.txt -r -d

# Archive-only mode (for dead URLs)
python multi_source.py -l dead_urls.txt --archive-only -r
```

### 5. `wayback.py`
Lightweight, Wayback-only auto-discovery and change detection.

```bash
python wayback.py -u https://example.com -d -r
python wayback.py -l urls.txt -s 20 --resume
```

---

## 
9d\u0009 Configuration

Copy `config.example.json` to `config.json` and fill in API keys (optional):

```json
{
  "api_keys": {
    "urlscan": "your-urlscan-key",
    "virustotal": "your-vt-key"
  },
  "settings": {
    "timeout": 60,
    "proxy": ""
  }
}
```

API keys can also be supplied via environment variables:
- `URLSCAN_API_KEY`
- `VIRUSTOTAL_API_KEY`

Or CLI flags (`--urlscan-key`, `--vt-key`).

---

## 
ce\u0009 Output Structure

```
output/
\u251c\u2500\u2500 <target>_urls_<timestamp>.txt    # Grabbed URLs
\u251c\u2500\u2500 <target>_alive.txt                # Alive URLs
\u251c\u2500\u2500 <target>_dead.txt                 # Dead URLs
\u2514\u2500\u2500 .progress_*.json                  # Resume state

reports/
\u2514\u2500\u2500 *.html / *.txt                    # Scan reports

html/
\u2514\u2500\u2500 diff_*.html                       # Side-by-side diffs

js_downloads/
\u2514\u2500\u2500 *.js                              # Downloaded JS files
```

---

## 
d1\u0009 Requirements

- **Python 3.7+**
- `requests`
- `urllib3`

See [`requirements.txt`](requirements.txt).

---

## 
d9\u0009 Tips

- Use `--proxy socks5h://127.0.0.1:9050` to route through Tor if your IP is rate-limited.
- The Wayback CDX API can return **403** under heavy use \u2014 the tool automatically retries with smaller limits and falls back to the timemap API.
- For long scans, you can **press ENTER to pause**, press ENTER again to resume.
- Use `--resume` to continue after interruption.

---

## 
d4\u0009 Inspiration & Credits

- [kpwn.de \u2013 JavaScript Analysis for Pentesters](https://kpwn.de/blog/javascript-analysis-for-pentesters/)
- [PortSwigger \u2013 Server-side Prototype Pollution](https://portswigger.net/research/server-side-prototype-pollution)
- [PortSwigger \u2013 DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)

---

## 
4c\u0009 License

MIT \u2014 see [LICENSE](LICENSE).

---

## 
d6\u0009 Contributing

Issues and pull requests welcome. Please ensure any contributions:
- Don't include real API keys or sensitive data
- Add appropriate error handling
- Follow the existing style
