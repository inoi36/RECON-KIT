# ReconKit — Information Gathering Toolkit

> **For educational purposes only. Use on authorized targets only.**

A full-stack OSINT and network reconnaissance toolkit built with React + FastAPI. Features 14 recon modules in a clean, military-style interface.

---

## Tools Included

| Module | Description |
|--------|-------------|
| Nmap Scanner | Port scanning and service detection |
| Banner Grabber | Grab service banners from open ports |
| Traceroute | Trace network path to a host |
| Shodan Intel | Search internet-connected devices |
| theHarvester | Harvest emails and subdomains |
| HIBP Breach | Email breach check (Have I Been Pwned) |
| Wayback Machine | View archived snapshots |
| Google Dorking | Generate advanced dork queries |
| Subdomain Finder | DNS subdomain enumeration |
| SSL/TLS Info | SSL certificate analysis |
| WHOIS Lookup | Domain registration info |
| DNS Lookup | Query DNS records |
| IP Geolocation | Geolocate an IP address |
| Reverse IP | Find all domains hosted on an IP |

---

## Quick Start (Local)

### Requirements
- Python 3.8+
- Nmap (for Nmap Scanner module)

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/reconkit.git
cd reconkit
```

### 2. Install dependencies

**Windows — run once:**
```
install.bat (right-click → Run as Administrator)
```

**Linux / macOS:**
```bash
pip install fastapi uvicorn requests dnspython python-whois shodan
sudo apt install nmap   # Linux
brew install nmap       # macOS
```

### 3. Start the backend

**Windows:**
```
start.bat (right-click → Run as Administrator)
```

**Linux / macOS:**
```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 4. Open the frontend
Double-click `frontend/index.html` in your browser.

---

## API Keys

| Service | Where to get |
|---------|-------------|
| Shodan | https://account.shodan.io |
| HIBP | https://haveibeenpwned.com/API/Key |

---

## Architecture

```
reconkit/
├── frontend/
│   └── index.html       # Single-file React app
├── backend/
│   ├── main.py          # FastAPI server (14 endpoints)
│   └── requirements.txt
├── install.bat          # Windows: one-time setup
└── start.bat            # Windows: launch backend + frontend
```

---

## Cloud Deployment

| Component | Platform |
|-----------|----------|
| Frontend | Vercel (free) |
| Backend | Render (free) |

> **Note:** Nmap and Traceroute require direct system access and are not available on cloud-hosted deployments.

---

## Disclaimer

This tool is built strictly for **educational purposes** and **authorized security testing**.
Unauthorized scanning of systems you do not own is illegal. The developer assumes no liability for misuse.
