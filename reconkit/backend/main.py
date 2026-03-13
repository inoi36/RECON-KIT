from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import socket
import ssl
import requests
import dns.resolver
import platform

app = FastAPI(title="ReconKit API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Request Models
# ─────────────────────────────────────────────

class NmapRequest(BaseModel):
    target: str
    flags: str = "-sV -sC"

class ShodanRequest(BaseModel):
    query: str
    api_key: str

class WhoisRequest(BaseModel):
    domain: str

class DNSRequest(BaseModel):
    domain: str
    record_type: str = "A"

class SubdomainRequest(BaseModel):
    domain: str

class IPGeoRequest(BaseModel):
    ip: str

class ReverseIPRequest(BaseModel):
    ip: str

class HarvesterRequest(BaseModel):
    domain: str
    sources: str = "google,bing,linkedin"

class HIBPRequest(BaseModel):
    email: str
    api_key: str = ""

class SSLRequest(BaseModel):
    domain: str
    port: int = 443

class WaybackRequest(BaseModel):
    url: str

class BannerRequest(BaseModel):
    host: str
    port: int = 80

class TracerouteRequest(BaseModel):
    host: str

class DorkRequest(BaseModel):
    query: str
    site: str = ""

# ─────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ReconKit API Running ✓", "version": "1.0.0", "tools": 14}

# ─────────────────────────────────────────────
# 1. NMAP
# ─────────────────────────────────────────────

@app.post("/api/nmap")
def run_nmap(req: NmapRequest):
    import os
    if os.environ.get("IS_CLOUD","false").lower()=="true":
        return {"output": """Nmap Scanner — Not Available on Cloud
============================================================

  Nmap requires direct system access and cannot run on
  cloud servers (Render, Railway, Heroku etc.)

  To use Nmap, run ReconKit locally:

  1. Install Nmap:
     Windows : https://nmap.org/download.html
     Linux   : sudo apt install nmap
     macOS   : brew install nmap

  2. Run backend locally:
     cd backend
     uvicorn main:app --host 0.0.0.0 --port 8000

  3. Open frontend/index.html in browser"""}
    try:
        import platform, os
        nmap_path = "nmap"
        if platform.system() == "Windows":
            if os.path.exists(r"C:\Program Files (x86)\Nmap\nmap.exe"):
                nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
            elif os.path.exists(r"C:\Program Files\Nmap\nmap.exe"):
                nmap_path = r"C:\Program Files\Nmap\nmap.exe"
                
        cmd = [nmap_path] + req.flags.split() + [req.target]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        output = result.stdout or result.stderr
        if not output:
            output = "No output received. Ensure Nmap is installed and added to PATH."
        # reconstructing a display command string
        display_cmd = f"nmap {req.flags} {req.target}"
        return {"output": output, "command": display_cmd}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Nmap scan timed out (120s)")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Nmap is not installed!\nWindows: https://nmap.org/download.html\nPlease install Nmap and restart your system.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 2. SHODAN
# ─────────────────────────────────────────────

@app.post("/api/shodan")
def run_shodan(req: ShodanRequest):
    try:
        import re
        query = req.query.strip()
        output = f"Shodan Intel for: {query}\n"
        output += "=" * 60 + "\n\n"

        # Check if query is an IP address
        is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", query))

        if is_ip:
            # Use Shodan InternetDB — free, no API key needed
            r = requests.get(f"https://internetdb.shodan.io/{query}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                output += f"  IP              : {data.get('ip', query)}\n"
                ports = data.get('ports', [])
                output += f"  Open Ports      : {', '.join(map(str, ports)) if ports else 'None found'}\n"
                hostnames = data.get('hostnames', [])
                output += f"  Hostnames       : {', '.join(hostnames) if hostnames else 'None'}\n"
                tags = data.get('tags', [])
                output += f"  Tags            : {', '.join(tags) if tags else 'None'}\n"
                vulns = data.get('vulns', [])
                if vulns:
                    output += f"\n  [ VULNERABILITIES — {len(vulns)} ]\n"
                    for v in vulns[:10]:
                        output += f"    ⚠ {v}\n"
                cpes = data.get('cpes', [])
                if cpes:
                    output += f"\n  [ CPEs / SOFTWARE ]\n"
                    for c in cpes[:5]:
                        output += f"    → {c}\n"
            elif r.status_code == 404:
                output += f"  No Shodan data found for {query}\n"
            else:
                output += f"  InternetDB returned: {r.status_code}\n"

        else:
            # For domain/keyword queries — try to resolve IP first, then lookup
            try:
                import socket
                ip = socket.gethostbyname(query.split()[0])
                output += f"  Resolved IP     : {ip}\n\n"
                r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    ports = data.get('ports', [])
                    output += f"  Open Ports      : {', '.join(map(str, ports)) if ports else 'None found'}\n"
                    hostnames = data.get('hostnames', [])
                    output += f"  Hostnames       : {', '.join(hostnames) if hostnames else 'None'}\n"
                    tags = data.get('tags', [])
                    output += f"  Tags            : {', '.join(tags) if tags else 'None'}\n"
                    vulns = data.get('vulns', [])
                    if vulns:
                        output += f"\n  [ VULNERABILITIES — {len(vulns)} ]\n"
                        for v in vulns[:10]:
                            output += f"    ⚠ {v}\n"
                    cpes = data.get('cpes', [])
                    if cpes:
                        output += f"\n  [ CPEs / SOFTWARE ]\n"
                        for c in cpes[:5]:
                            output += f"    → {c}\n"
            except Exception:
                output += f"  Could not resolve '{query}' to an IP.\n"
                output += f"  Tip: Enter a direct IP address for best results.\n"

        output += "\n" + "=" * 60 + "\n"
        output += "  [ SOURCE ] Shodan InternetDB (free) — internetdb.shodan.io\n"
        return {"output": output}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 3. WHOIS
# ─────────────────────────────────────────────

@app.post("/api/whois")
def run_whois(req: WhoisRequest):
    try:
        import re as _re2
        _d = req.domain.strip()
        _d = _re2.sub(r"^https?://", "", _d).split("/")[0]
        _d = _re2.sub(r"^www[.]", "", _d)

        output = f"WHOIS Information for: {_d}\n"
        output += "=" * 60 + "\n\n"

        # Primary: RDAP API (works on all cloud servers, no port 43 needed)
        try:
            rdap = requests.get(
                f"https://rdap.org/domain/{_d}",
                timeout=15,
                headers={"Accept": "application/json"}
            )
            if rdap.status_code == 200:
                data = rdap.json()
                # Extract useful fields from RDAP response
                output += f"  {'Domain':<25}: {data.get('ldhName', _d)}\n"
                # Status
                status = [s.get('value','') if isinstance(s,dict) else str(s) for s in data.get('status',[])]
                if status: output += f"  {'Status':<25}: {', '.join(status)}\n"
                # Dates
                for ev in data.get('events', []):
                    act = ev.get('eventAction','')
                    date = ev.get('eventDate','')[:10]
                    if act == 'registration': output += f"  {'Created':<25}: {date}\n"
                    elif act == 'expiration': output += f"  {'Expires':<25}: {date}\n"
                    elif act == 'last changed': output += f"  {'Updated':<25}: {date}\n"
                # Nameservers
                ns = [n.get('ldhName','') for n in data.get('nameservers',[])]
                if ns: output += f"  {'Name Servers':<25}: {', '.join(ns)}\n"
                # Registrar
                for entity in data.get('entities', []):
                    roles = entity.get('roles', [])
                    vcard = entity.get('vcardArray', [])
                    name = ''
                    if vcard and len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == 'fn': name = field[3]
                    if 'registrar' in roles and name:
                        output += f"  {'Registrar':<25}: {name}\n"
                    if 'registrant' in roles and name:
                        output += f"  {'Registrant':<25}: {name}\n"
                return {"output": output}
        except Exception:
            pass

        # Fallback: whois-json API
        try:
            r2 = requests.get(f"https://whois.freeaiapi.xyz/?name={_d}", timeout=10)
            if r2.status_code == 200:
                data2 = r2.json()
                for k, v in data2.items():
                    if v: output += f"  {k:<25}: {v}\n"
                return {"output": output}
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"WHOIS lookup failed for {_d}")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 4. DNS LOOKUP
# ─────────────────────────────────────────────

@app.post("/api/dns")
def run_dns(req: DNSRequest):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(req.domain, req.record_type)
        output = f"DNS {req.record_type} Records for: {req.domain}\n"
        output += "=" * 60 + "\n\n"
        for i, rdata in enumerate(answers, 1):
            output += f"  [{i}] {rdata}\n"
        output += f"\n  TTL: {answers.rrset.ttl}s"
        return {"output": output}
    except dns.resolver.NXDOMAIN:
        raise HTTPException(status_code=404, detail=f"Domain {req.domain} does not exist")
    except dns.resolver.NoAnswer:
        raise HTTPException(status_code=404, detail=f"No {req.record_type} records found for {req.domain}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 5. SUBDOMAIN FINDER
# ─────────────────────────────────────────────

@app.post("/api/subdomain")
def run_subdomain(req: SubdomainRequest):
    import re as _re3
    _d = req.domain.strip()
    _d = _re3.sub(r"^https?://", "", _d).split("/")[0]
    _d = _re3.sub(r"^www[.]", "", _d)
    req = SubdomainRequest(domain=_d)
    output = f"Subdomain Enumeration for: {_d}\n"
    output += "=" * 60 + "\n\n"
    found = []

    # --- Method 1: HackerTarget API (best source, returns real results) ---
    ht_subs = set()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={req.domain}",
            timeout=20
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:50]:
            output += "  [ SOURCE: HackerTarget API ]\n\n"
            for line in r.text.strip().splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip()
                    ip  = line.split(",")[1].strip() if len(line.split(",")) > 1 else ""
                    if sub.endswith(req.domain) and sub != req.domain:
                        ht_subs.add(sub)
                        found.append(sub)
                        output += f"  [FOUND] ✓ {sub:<40} {ip}\n"
            if not ht_subs:
                output += "  No subdomains returned by HackerTarget.\n"
        else:
            output += f"  HackerTarget returned: {r.text[:120]}\n"
    except Exception as e:
        output += f"  HackerTarget API failed: {e}\n"

    output += "\n"

    # --- Method 2: DNS brute-force for common names not found above ---
    wordlist = [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
        "blog", "shop", "portal", "vpn", "remote", "cdn", "static",
        "app", "mobile", "secure", "login", "auth", "dashboard", "beta",
        "docs", "support", "help", "forum", "news", "media", "img",
        "smtp", "pop", "imap", "webmail", "cpanel", "whm", "ns1", "ns2"
    ]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    brute_found = []
    brute_miss  = []
    output += "  [ SOURCE: DNS Brute-Force ]\n\n"
    for sub in wordlist:
        full = f"{sub}.{req.domain}"
        if full in ht_subs:
            continue  # already found via HackerTarget
        try:
            ans = resolver.resolve(full, 'A')
            ip  = str(ans[0]) if ans else ""
            brute_found.append(full)
            found.append(full)
            output += f"  [FOUND] ✓ {full:<40} {ip}\n"
        except Exception:
            brute_miss.append(full)

    if not brute_found:
        output += "  No additional subdomains found via brute-force.\n"

    output += f"\n{'=' * 60}\n"
    output += f"  Total Found: {len(found)} subdomains\n"
    if found:
        output += "\n  All Active Subdomains:\n"
        for s in sorted(set(found)):
            output += f"    → {s}\n"
    return {"output": output, "found": list(set(found))}

# ─────────────────────────────────────────────
# 6. IP GEOLOCATION
# ─────────────────────────────────────────────

@app.post("/api/ipgeo")
def run_ipgeo(req: IPGeoRequest):
    try:
        resp = requests.get(f"http://ip-api.com/json/{req.ip}?fields=66846719", timeout=10)
        data = resp.json()
        output = f"IP Geolocation for: {req.ip}\n"
        output += "=" * 60 + "\n\n"
        fields = [
            ("Status", "status"), ("Country", "country"), ("Country Code", "countryCode"),
            ("Region", "regionName"), ("City", "city"), ("ZIP", "zip"),
            ("Latitude", "lat"), ("Longitude", "lon"), ("Timezone", "timezone"),
            ("ISP", "isp"), ("Organization", "org"), ("AS", "as"),
            ("Hostname", "reverse"), ("Proxy/VPN", "proxy"), ("Hosting", "hosting"),
            ("Mobile", "mobile")
        ]
        for label, key in fields:
            val = data.get(key, "N/A")
            if val not in ("", None):
                output += f"  {label:<16}: {val}\n"
        return {"output": output, "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 7. REVERSE IP LOOKUP
# ─────────────────────────────────────────────

@app.post("/api/reverseip")
def run_reverseip(req: ReverseIPRequest):
    output = f"Reverse IP Lookup for: {req.ip}\n"
    output += "=" * 60 + "\n\n"
    all_domains = []

    # --- Source 1: HackerTarget ---
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={req.ip}",
            timeout=15
        )
        text = resp.text.strip()
        if resp.status_code == 200 and "error" not in text.lower() and "API count" not in text:
            lines = [l.strip() for l in text.splitlines() if l.strip() and "." in l]
            if lines:
                all_domains.extend(lines)
                output += f"  [ HackerTarget — {len(lines)} domain(s) ]\n"
                for d in lines[:30]:  # cap at 30 per source
                    output += f"    → {d}\n"
                output += "\n"
            else:
                output += "  [ HackerTarget ] No domains found for this IP.\n\n"
        else:
            output += f"  [ HackerTarget ] Rate limited or error: {text[:100]}\n\n"
    except Exception:
        output += "  [ HackerTarget ] Request failed.\n\n"

    # --- Source 2: ViewDNS.info (HTML scrape fallback) ---
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        r2 = requests.get(
            f"https://viewdns.info/reverseip/?host={req.ip}&t=1",
            headers=headers, timeout=15
        )
        import re as _re
        # Extract domains from table cells in the response
        domains_vd = _re.findall(r'<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>', r2.text)
        domains_vd = [d for d in domains_vd if not d.startswith('DNS') and "." in d]
        new_vd = [d for d in domains_vd if d not in all_domains]
        if new_vd:
            all_domains.extend(new_vd)
            output += f"  [ ViewDNS.info — {len(new_vd)} additional domain(s) ]\n"
            for d in new_vd[:30]:
                output += f"    → {d}\n"
            output += "\n"
        elif domains_vd:
            output += "  [ ViewDNS.info ] All results already listed above.\n\n"
        else:
            output += "  [ ViewDNS.info ] No additional results found.\n\n"
    except Exception:
        output += "  [ ViewDNS.info ] Request failed.\n\n"

    output += "=" * 60 + "\n"
    output += f"  Total Unique Domains on IP: {len(set(all_domains))}\n"
    return {"output": output}

# ─────────────────────────────────────────────
# 8. theHARVESTER
# ─────────────────────────────────────────────

@app.post("/api/harvester")
def run_harvester(req: HarvesterRequest):
    """Python-native harvester using public APIs — works on all platforms."""
    import re
    import re as _re
    _raw = req.domain.strip().lower()
    _raw = _re.sub(r'^https?://', '', _raw).split('/')[0]
    target_domain = _re.sub(r'^www\.', '', _raw)
    output = f"Email & Subdomain Harvest for: {target_domain}\n"
    output += "=" * 60 + "\n\n"

    emails_found = set()
    subs_found = set()

    # --- Source 1: Bing scrape for emails matching ONLY the target domain ---
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        # Search specifically for email addresses at this domain
        bing_resp = requests.get(
            f"https://www.bing.com/search?q=%40{target_domain}+email&count=50",
            headers=headers,
            timeout=15
        )
        # Only match emails ending with @target_domain (strict match)
        pattern = r"[a-zA-Z0-9_.+-]+@" + re.escape(target_domain)
        found_emails = re.findall(pattern, bing_resp.text)
        # Deduplicate and filter junk (e.g. src=, href= placeholders)
        for e in found_emails:
            if len(e) < 100 and not any(c in e for c in ['<', '>', '"', "'"]):  
                emails_found.add(e.lower())
    except Exception:
        pass

    # --- Source 2: Hunter.io free autocomplete (no key) ---
    try:
        h_resp = requests.get(
            f"https://api.hunter.io/v2/domain-search?domain={target_domain}&limit=10&api_key=free",
            timeout=10
        )
        if h_resp.status_code == 200:
            hdata = h_resp.json()
            for entry in hdata.get('data', {}).get('emails', []):
                em = entry.get('value', '')
                if em and em.endswith(f"@{target_domain}"):
                    emails_found.add(em.lower())
    except Exception:
        pass

    # --- Source 3: HackerTarget subdomain finder (for CORRECT domain) ---
    try:
        r2 = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={target_domain}",
            timeout=20
        )
        if r2.status_code == 200 and "error" not in r2.text.lower()[:50]:
            for line in r2.text.strip().splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip()
                    # Strictly only include subdomains of target_domain
                    if sub.endswith(f".{target_domain}") or sub == target_domain:
                        subs_found.add(sub)
    except Exception:
        pass

    # --- Source 4: crt.sh certificate transparency for subdomains ---
    try:
        crt_resp = requests.get(
            f"https://crt.sh/?q=%.{target_domain}&output=json",
            timeout=20
        )
        if crt_resp.status_code == 200:
            for entry in crt_resp.json():
                name = entry.get("name_value", "")
                for n in name.splitlines():
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(f".{target_domain}") or n == target_domain:
                        subs_found.add(n)
    except Exception:
        pass

    # Build output
    output += f"  [ EMAILS FOUND — {len(emails_found)} ]\n"
    if emails_found:
        for e in sorted(emails_found):
            output += f"    → {e}\n"
    else:
        output += f"    No emails found for @{target_domain}.\n"
        output += "    (Try checking LinkedIn, company website, or Hunter.io manually)\n"

    output += f"\n  [ SUBDOMAINS FOUND — {len(subs_found)} ]\n"
    if subs_found:
        for s in sorted(subs_found):
            output += f"    → {s}\n"
    else:
        output += f"    No subdomains found for {target_domain}.\n"

    output += f"\n  [ SOURCES ] Bing scrape · HackerTarget API · crt.sh (Certificate Transparency)\n"
    output += f"  [ TARGET ] {target_domain} (all results verified to match this domain)\n"
    return {"output": output}

# ─────────────────────────────────────────────
# 9. HAVE I BEEN PWNED
# ─────────────────────────────────────────────

@app.post("/api/hibp")
def run_hibp(req: HIBPRequest):
    try:
        email = req.email.strip()
        output = f"Breach Check for: {email}\n"
        output += "=" * 60 + "\n\n"
        found_any = False

        # Source 1: LeakCheck.io free public API
        try:
            r1 = requests.get(
                f"https://leakcheck.io/api/public?check={email}",
                timeout=10,
                headers={"User-Agent": "ReconKit-InfoGathering-Tool"}
            )
            if r1.status_code == 200:
                data = r1.json()
                if data.get("success") and data.get("found", 0) > 0:
                    found_any = True
                    sources = data.get("sources", [])
                    output += f"  ⚠ BREACHED — found in {data['found']} source(s)\n\n"
                    output += f"  [ SOURCE: LeakCheck.io ]\n"
                    for s in sources[:15]:
                        output += f"    → {s}\n"
                    output += "\n"
                elif data.get("success"):
                    output += f"  ✓ LeakCheck.io — Not found\n"
        except Exception:
            pass

        # Source 2: ProxyNova COMB database
        try:
            r2 = requests.get(
                f"https://api.proxynova.com/comb?query={email}&limit=5",
                timeout=10,
                headers={"User-Agent": "ReconKit-InfoGathering-Tool"}
            )
            if r2.status_code == 200:
                data2 = r2.json()
                count = data2.get("count", 0)
                if count > 0:
                    found_any = True
                    output += f"  [ SOURCE: ProxyNova COMB Database ]\n"
                    output += f"  ⚠ Found {count} record(s) in COMB breach database\n"
                    lines = data2.get("lines", [])
                    for line in lines[:5]:
                        # Mask password for safety
                        parts = line.split(":")
                        if len(parts) >= 2:
                            masked = parts[0] + ":****"
                        else:
                            masked = "****"
                        output += f"    → {masked}\n"
                    output += "\n"
                else:
                    output += f"  ✓ ProxyNova COMB — Not found\n"
        except Exception:
            pass

        if not found_any:
            output += f"\n  ✓ CLEAN: {email} was not found in checked breach databases.\n"

        output += "\n" + "=" * 60 + "\n"
        output += "  [ SOURCES ] LeakCheck.io · ProxyNova COMB\n"
        output += "  [ NOTE ] For complete results use haveibeenpwned.com\n"
        return {"output": output}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 10. SSL/TLS INFO
# ─────────────────────────────────────────────

@app.post("/api/ssl")
def run_ssl(req: SSLRequest):
    try:
        # Strip any accidental http:// or https:// prefix
        import re as _re
        domain = _re.sub(r'^https?://', '', req.domain).split('/')[0].strip()

        # CERT_OPTIONAL fetches the cert without enforcing verification
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(10)
        raw_sock.connect((domain, req.port))
        conn = context.wrap_socket(raw_sock, server_hostname=domain)
        cert = conn.getpeercert()
        cipher = conn.cipher()
        version = conn.version()
        conn.close()

        if not cert:
            raise HTTPException(status_code=400, detail=f"No SSL certificate returned by {domain}:{req.port}. The server may not support HTTPS or the domain is incorrect.")

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))

        output = f"SSL/TLS Certificate Info for: {domain}:{req.port}\n"
        output += "=" * 60 + "\n\n"
        output += f"  [ SUBJECT ]\n"
        for k, v in subject.items():
            output += f"    {k:<20}: {v}\n"
        output += f"\n  [ ISSUER ]\n"
        for k, v in issuer.items():
            output += f"    {k:<20}: {v}\n"
        output += f"\n  [ VALIDITY ]\n"
        output += f"    Not Before     : {cert.get('notBefore', 'N/A')}\n"
        output += f"    Not After      : {cert.get('notAfter', 'N/A')}\n"
        output += f"\n  [ CONNECTION ]\n"
        output += f"    Protocol       : {version}\n"
        output += f"    Cipher         : {cipher[0] if cipher else 'N/A'}\n"
        output += f"    Bits           : {cipher[2] if cipher else 'N/A'}\n"
        output += f"    Serial Number  : {cert.get('serialNumber', 'N/A')}\n"
        output += f"    Version        : {cert.get('version', 'N/A')}\n"

        san = cert.get('subjectAltName', [])
        if san:
            output += f"\n  [ SUBJECT ALT NAMES ]\n"
            for typ, val in san:
                output += f"    {typ}: {val}\n"

        return {"output": output}
    except HTTPException:
        raise
    except socket.timeout:
        raise HTTPException(status_code=408, detail=f"Connection to {req.domain}:{req.port} timed out.")
    except ConnectionRefusedError:
        raise HTTPException(status_code=400, detail=f"Connection refused on {req.domain}:{req.port}. Port may be closed.")
    except ssl.SSLError as e:
        raise HTTPException(status_code=400, detail=f"SSL error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 11. WAYBACK MACHINE
# ─────────────────────────────────────────────

@app.post("/api/wayback")
def run_wayback(req: WaybackRequest):
    try:
        output = f"Wayback Machine Results for: {req.url}\n"
        output += "=" * 60 + "\n\n"

        # Latest snapshot
        try:
            avail_resp = requests.get(
                f"https://archive.org/wayback/available?url={req.url}",
                timeout=15
            )
            if avail_resp.status_code == 200:
                try:
                    avail = avail_resp.json()
                    snap = avail.get('archived_snapshots', {}).get('closest', {})
                    if snap:
                        output += f"  [ LATEST SNAPSHOT ]\n"
                        output += f"    Status    : {snap.get('status')}\n"
                        output += f"    Timestamp : {snap.get('timestamp')}\n"
                        output += f"    URL       : {snap.get('url')}\n\n"
                    else:
                        output += f"  [ LATEST SNAPSHOT ]\n    No snapshot found for this URL.\n\n"
                except Exception:
                    output += f"  [ LATEST SNAPSHOT ]\n    Could not parse snapshot response.\n\n"
            elif avail_resp.status_code == 429:
                output += f"  [ LATEST SNAPSHOT ]\n    Rate limited by Archive.org (429). Please try again later.\n\n"
            else:
                output += f"  [ LATEST SNAPSHOT ]\n    API returned status {avail_resp.status_code}.\n\n"
        except requests.exceptions.Timeout:
            output += f"  [ LATEST SNAPSHOT ]\n    Request timed out. Archive.org may be temporarily slow.\n\n"
        except Exception as e:
            output += f"  [ LATEST SNAPSHOT ]\n    Error: {str(e)}\n\n"

        # CDX API for history
        try:
            cdx = requests.get(
                f"https://web.archive.org/cdx/search/cdx?url={req.url}&output=json&limit=15&fl=timestamp,statuscode,mimetype&collapse=timestamp:6",
                timeout=30
            )
            if cdx.status_code == 200:
                try:
                    rows = cdx.json()
                    if len(rows) > 1:
                        output += f"  [ ARCHIVE HISTORY — last {len(rows)-1} snapshots ]\n\n"
                        output += f"    {'Timestamp':<16} {'Status':<8} {'MIME Type'}\n"
                        output += f"    {'-'*14} {'-'*6} {'-'*20}\n"
                        for row in rows[1:]:
                            output += f"    {row[0]:<16} {row[1]:<8} {row[2]}\n"
                    else:
                        output += f"  [ ARCHIVE HISTORY ]\n    No historical snapshots found.\n"
                except ValueError:
                    output += f"  [ ARCHIVE HISTORY ]\n    Could not parse CDX response.\n"
            elif cdx.status_code == 429:
                output += f"  [ ARCHIVE HISTORY ]\n    Rate limited by Archive.org (429). Please try again later.\n"
            else:
                output += f"  [ ARCHIVE HISTORY ]\n    CDX API returned status {cdx.status_code}.\n"
        except requests.exceptions.Timeout:
            output += f"  [ ARCHIVE HISTORY ]\n    CDX request timed out (30s). Archive.org may be busy.\n"
        except Exception as e:
            output += f"  [ ARCHIVE HISTORY ]\n    Error: {str(e)}\n"

        return {"output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 12. BANNER GRABBING
# ─────────────────────────────────────────────

@app.post("/api/banner")
def run_banner(req: BannerRequest):
    try:
        output = f"Banner Grab from: {req.host}:{req.port}\n"
        output += "=" * 60 + "\n\n"

        # HTTP/HTTPS ports — use requests library (most reliable)
        if req.port in (80, 443, 8080, 8000, 8888, 3000, 8443):
            scheme = "https" if req.port in (443, 8443) else "http"
            try:
                import warnings
                warnings.filterwarnings("ignore")
                resp = requests.get(
                    f"{scheme}://{req.host}:{req.port}/",
                    timeout=10,
                    allow_redirects=False,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                # Safe HTTP version string
                raw_ver = getattr(resp.raw, "version", 11)
                http_ver = "1.0" if raw_ver == 10 else "1.1"
                output += f"  HTTP/{http_ver} {resp.status_code} {resp.reason}\n\n"
                output += "  [ RESPONSE HEADERS ]\n"
                for k, v in resp.headers.items():
                    output += f"    {k:<30}: {v}\n"
                body = resp.text[:300].strip() if resp.text else ""
                if body:
                    output += f"\n  [ BODY PREVIEW ]\n    {body}\n"
                return {"output": output}
            except requests.exceptions.SSLError:
                output += "  SSL error — trying HTTP fallback\n"
            except requests.exceptions.ConnectionError:
                output += f"  Connection refused on port {req.port}\n"
                return {"output": output}
            except requests.exceptions.Timeout:
                output += "  Request timed out (10s)\n"
                return {"output": output}
            except Exception as e:
                output += f"  HTTP request failed: {str(e)}\n"

        # Raw socket fallback for non-HTTP ports (FTP, SSH, SMTP, etc.)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((req.host, req.port))
            # Send probe for non-auto-banner ports
            if req.port not in (21, 22, 25, 110, 143):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + req.host.encode() + b"\r\n\r\n")
            banner = b""
            s.settimeout(4)
            while len(banner) < 4096:
                try:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    banner += chunk
                except Exception:
                    break
            s.close()
            decoded = banner.decode("utf-8", errors="ignore").strip()
            output += "  [ RAW BANNER ]\n"
            output += f"    {decoded}" if decoded else "  (No banner received — port may be filtered)"
        except ConnectionRefusedError:
            output += f"  Port {req.port} is closed or not reachable."
        except socket.timeout:
            output += "  Socket connection timed out."
        except Exception as e:
            output += f"  Socket error: {str(e)}"

        return {"output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 13. TRACEROUTE
# ─────────────────────────────────────────────

@app.post("/api/traceroute")
def run_traceroute(req: TracerouteRequest):
    import os
    if os.environ.get("IS_CLOUD","false").lower()=="true":
        return {"output": """Traceroute — Not Available on Cloud
============================================================

  Traceroute requires direct network access and cannot
  run on cloud servers.

  To use Traceroute, run ReconKit locally:

  1. Run backend locally:
     cd backend
     uvicorn main:app --host 0.0.0.0 --port 8000

  2. Open frontend/index.html in browser"""}
    try:
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-h", "15", "-w", "1000", req.host]
        else:
            cmd = ["traceroute", "-n", "-m", "15", req.host]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        output = f"Traceroute to: {req.host}\n"
        output += "=" * 60 + "\n\n"
        output += result.stdout or result.stderr or "No output received."
        return {"output": output}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Traceroute is not available on this system.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Traceroute timed out (45s)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# 14. GOOGLE DORKING
# ─────────────────────────────────────────────

@app.post("/api/dorking")
def run_dorking(req: DorkRequest):
    import re as _re
    base_query = req.query.strip()
    site_prefix = f"site:{req.site} " if req.site else ""
    full_query = f"{site_prefix}{base_query}"

    dorks = [
        (f"{site_prefix}{base_query}", "Base query"),
        (f"{site_prefix}intitle:\"{base_query}\"", "Search in page title"),
        (f"{site_prefix}inurl:{base_query}", "Search in URL"),
        (f"{site_prefix}intext:\"{base_query}\"", "Search in page text"),
        (f"{site_prefix}filetype:pdf \"{base_query}\"", "PDF files"),
        (f"{site_prefix}filetype:xls \"{base_query}\"", "Excel files"),
        (f"{site_prefix}filetype:sql \"{base_query}\"", "SQL files"),
        (f"{site_prefix}\"{base_query}\" ext:log", "Log files"),
        (f"{site_prefix}\"{base_query}\" ext:conf", "Config files"),
        (f"{site_prefix}\"{base_query}\" ext:env", ".env files"),
    ]

    output = f"Google Dorking for: {full_query}\n"
    output += "=" * 60 + "\n\n"

    # --- Try to fetch real results from DuckDuckGo HTML (no API key needed) ---
    ddg_results = []
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9"
        }
        ddg_resp = requests.get(
            f"https://html.duckduckgo.com/html/?q={requests.utils.quote(full_query)}",
            headers=headers,
            timeout=15
        )
        if ddg_resp.status_code == 200:
            # Extract result titles and URLs from DDG HTML
            titles = _re.findall(r'class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)<', ddg_resp.text)
            # Also try alternate pattern
            if not titles:
                titles = _re.findall(r'<a class="result__a" href="([^"]+)">(.+?)</a>', ddg_resp.text)
            # Extract result snippets
            snippets = _re.findall(r'class="result__snippet"[^>]*>(.+?)</a>', ddg_resp.text)
            for i, (url, title) in enumerate(titles[:10]):
                snippet = snippets[i] if i < len(snippets) else ""
                snippet_clean = _re.sub(r'<[^>]+>', '', snippet).strip()[:120]
                ddg_results.append({"title": title.strip(), "url": url, "snippet": snippet_clean})
    except Exception:
        pass

    if ddg_results:
        output += f"  [ LIVE RESULTS from DuckDuckGo — {len(ddg_results)} found ]\n\n"
        for i, r in enumerate(ddg_results, 1):
            output += f"  [{i}] {r['title']}\n"
            output += f"      {r['url']}\n"
            if r['snippet']:
                output += f"      {r['snippet']}\n"
            output += "\n"
        output += "=" * 60 + "\n\n"
    else:
        output += "  [ LIVE RESULTS ] DuckDuckGo returned no results (try a different query).\n\n"

    output += "  [ GENERATED DORK QUERIES — open in browser ]\n\n"
    for dork, label in dorks:
        encoded = requests.utils.quote(dork)
        google = f"https://www.google.com/search?q={encoded}"
        bing   = f"https://www.bing.com/search?q={encoded}"
        output += f"  [{label}]\n"
        output += f"    Dork   : {dork}\n"
        output += f"    Google : {google}\n"
        output += f"    Bing   : {bing}\n\n"

    return {"output": output, "dorks": [d[0] for d in dorks]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
