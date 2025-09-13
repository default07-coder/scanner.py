
---

### scanner.py
```python
#!/usr/bin/env python3
"""
Web-Vuln-Scanner (ethical, passive)
Usage: python scanner.py https://example.com
"""
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import ssl, socket
from datetime import datetime
import json

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "x-xss-protection"
]

def fetch_url(url, timeout=12):
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"AnonSec-Scanner/1.0"})
        return resp
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return None

def check_security_headers(headers):
    found = {}
    lower = {k.lower(): v for k,v in headers.items()}
    for h in SECURITY_HEADERS:
        found[h] = lower.get(h)
    return found

def parse_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        frm = {
            "action": urljoin(base_url, f.get("action") or ""),
            "method": (f.get("method") or "GET").upper(),
            "inputs": []
        }
        for i in f.find_all(["input","textarea","select"]):
            frm["inputs"].append({
                "name": i.get("name"),
                "type": i.get("type")
            })
        forms.append(frm)
    return forms

def check_ssl_expiry(hostname, port=443, timeout=5):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                notAfter = cert.get('notAfter')
                if notAfter:
                    expires = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires - datetime.utcnow()).days
                    return {"expires": notAfter, "days_left": days_left}
    except Exception as e:
        return {"error": str(e)}
    return {"error":"no-cert-info"}

def fetch_robots(base_url):
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        r = requests.get(robots_url, timeout=6)
        return {"url": robots_url, "status_code": r.status_code, "content": r.text if r.status_code==200 else ""}
    except Exception as e:
        return {"url": robots_url, "error": str(e)}

def summarize(url):
    out = {"target": url, "fetched": {}, "security_headers": {}, "forms": [], "robots": {}, "ssl": {}}
    resp = fetch_url(url)
    if not resp:
        return out
    out["fetched"]["status_code"] = resp.status_code
    out["fetched"]["final_url"] = resp.url
    out["fetched"]["server"] = resp.headers.get("Server")
    out["security_headers"] = check_security_headers(resp.headers)
    out["forms"] = parse_forms(resp.text, resp.url)
    out["robots"] = fetch_robots(url)
    parsed = urlparse(resp.url)
    if parsed.scheme == "https":
        out["ssl"] = check_ssl_expiry(parsed.netloc.split(":")[0])
    return out

def pretty_print(data):
    print("="*60)
    print(f"Target: {data.get('target')}")
    print(f"Final URL: {data.get('fetched',{}).get('final_url')}")
    print(f"Status: {data.get('fetched',{}).get('status_code')}")
    print(f"Server header: {data.get('fetched',{}).get('server')}")
    print("\n-- Security Headers --")
    for k,v in data.get("security_headers",{}).items():
        print(f"{k}: {v}")
    print("\n-- SSL --")
    print(data.get("ssl"))
    print("\n-- robots.txt --")
    r = data.get("robots",{})
    print(f"{r.get('url')} (status {r.get('status_code')})")
    print("\n-- Forms Found --")
    for i,frm in enumerate(data.get("forms",[]),1):
        print(f"[{i}] action={frm['action']} method={frm['method']} inputs={len(frm['inputs'])}")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py https://example.com")
        sys.exit(1)
    target = sys.argv[1]
    print("[*] Running passive scan (ethical only) ...")
    result = summarize(target)
    pretty_print(result)
    # Save JSON report
    with open("scan_report.json","w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print("[*] JSON report written to scan_report.json")
