# 🔐 AI-Based Web Vulnerability Scanner

A Django-powered web vulnerability scanner using **scikit-learn Random Forest** classification combined with rule-based detection to identify 5 categories of web vulnerabilities, with professional PDF reporting.

---

## Features

- 🔍 **5 Vulnerability Types**: XSS, SQL Injection, CSRF, Open Redirect, Sensitive Data Exposure
- 🤖 **ML-Powered**: Random Forest classifier trained on 2000+ synthetic vulnerability patterns (90%+ accuracy)
- 📊 **Real-time Scanning**: Live progress feedback with step-by-step scanning stages
- 📄 **Professional PDF Reports**: Dark-themed, multi-page security reports with ReportLab
- 📈 **Risk Scoring**: 0–100 risk score with severity levels (Critical / High / Medium / Low)
- 🕒 **Scan History**: Full history with filtering, sorting, and report download
- 🎨 **Modern UI**: Dark cybersecurity-themed interface

---

## Quick Start

```bash
# 1. Clone the repository
git clone <your-repo>
cd vuln_scanner

# 2. Create and activate virtual environment (recommended)
python -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate        # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Apply database migrations
python manage.py migrate

# 5. (Optional) Create admin superuser
python manage.py createsuperuser

# 6. Start the development server
python manage.py runserver
```

Then open **http://localhost:8000** in your browser.

---

## Usage

1. Open **http://localhost:8000**
2. Enter a target URL in the scanner input
3. Click **Start Scan**
4. View real-time progress as the scanner runs
5. Review the vulnerability report on-screen
6. Download the **PDF report** for sharing

### Quick Test URLs (legal, intentionally vulnerable sites)

| URL | Purpose |
|-----|---------|
| `http://testphp.vulnweb.com` | PHP-based vulnerable test site |
| `http://demo.testfire.net` | IBM AltoroMutual demo bank |
| `https://example.com` | Clean baseline (minimal findings) |

> ⚠️ **Only scan systems you own or have explicit written permission to test.**

---

## Project Structure

```
vuln_scanner/
├── manage.py
├── requirements.txt
├── README.md
├── db.sqlite3              # Created after migrate
│
├── vuln_scanner/           # Django project config
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── scanner/                # Main Django app
│   ├── models.py           # ScanResult model
│   ├── views.py            # HTTP views + API endpoints
│   ├── urls.py             # URL routing
│   ├── ml_scanner.py       # ML engine + detection logic
│   ├── pdf_report.py       # ReportLab PDF generator
│   └── admin.py            # Django admin registration
│
├── templates/
│   ├── base.html           # Base layout
│   └── scanner/
│       ├── index.html      # Main scanner dashboard
│       ├── scan_detail.html # Individual scan report
│       └── history.html    # Scan history list
│
├── static/
│   ├── css/main.css        # Dark cybersecurity stylesheet
│   └── js/main.js          # Async scan + UI logic
│
└── media/
    └── reports/            # Generated PDF reports
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend Framework | Django 4.2.7 |
| ML Classification | scikit-learn (Random Forest) |
| PDF Generation | ReportLab 4.0.7 |
| HTML Parsing | BeautifulSoup4 |
| HTTP Requests | Requests 2.31.0 |
| Database | SQLite (built-in) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Font | Space Mono + Inter (Google Fonts) |

---

## Detected Vulnerability Types

### 1. Cross-Site Scripting (XSS) — HIGH
Detects inline event handlers, unsafe DOM APIs (`innerHTML`, `document.write`), missing CSP, and reflected URL parameters.

### 2. SQL Injection — CRITICAL
Identifies SQL error signatures in responses, exposed database technology info, and numeric URL parameters.

### 3. CSRF — MEDIUM
Scans POST forms for missing CSRF tokens and unprotected state-changing requests.

### 4. Open Redirect — MEDIUM
Detects redirect-related URL parameters (`redirect`, `url`, `next`, `goto`, etc.) that could redirect to attacker-controlled domains.

### 5. Sensitive Data Exposure — HIGH
Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.), API key leakage, unencrypted HTTP, and server version disclosure.

---

## API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| `GET` | `/` | Main scanner dashboard |
| `POST` | `/scan/` | Start a new scan (JSON body: `{"url": "..."}`) |
| `GET` | `/scan/<id>/` | View scan detail |
| `GET` | `/scan/<id>/download/` | Download PDF report |
| `GET` | `/history/` | Scan history page |
| `GET` | `/api/history/` | JSON API — recent scans |
| `GET` | `/admin/` | Django admin panel |

---

## Risk Scoring

| Score | Level | Description |
|-------|-------|-------------|
| 75–100 | 🔴 Critical | Immediate action required |
| 50–74 | 🟠 High | Urgent remediation needed |
| 25–49 | 🟡 Medium | Should be addressed soon |
| 1–24 | 🟢 Low | Minor issues present |
| 0 | ℹ Info | No issues detected |

---

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Unauthorized scanning of systems you do not own or have explicit written permission to test is **illegal** and may violate computer crime laws. The authors assume no liability for misuse.

---

## License

MIT License — See LICENSE file for details.
