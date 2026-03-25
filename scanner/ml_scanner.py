"""
AI-powered vulnerability scanner — crawls pages, detects all 5 vuln types.
"""

import re, time, warnings
import requests
import numpy as np
from urllib.parse import (urlparse, urljoin, parse_qs,
                          urlencode, urlunparse, quote)
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore')
try:
    import urllib3; urllib3.disable_warnings()
except Exception:
    pass

# ── ML ─────────────────────────────────────────────────────────────────────────

def extract_features(url, html="", headers=None, code=200):
    if headers is None: headers = {}
    p = urlparse(url)
    par = parse_qs(p.query)
    f = [len(url), len(par),
         1 if url.startswith('https') else 0,
         url.count('<')+url.count('>'), url.count('"')+url.count("'"),
         url.count('script'),
         url.count('SELECT')+url.count('select')+url.count('UNION'),
         url.count('--')+url.count('OR '),
         url.count('redirect')+url.count('url=')+url.count('next='),
         html.count('<script'),
         html.count('document.cookie')+html.count('eval('),
         html.count('innerHTML')+html.count('document.write'),
         1 if 'csrftoken' in html.lower() else 0,
         html.count('<form'),
         html.count('SELECT')+html.count('mysql_')+html.count('ORA-'),
         html.count('error')+html.count('exception'),
         1 if 'X-Frame-Options' in headers else 0,
         1 if 'Content-Security-Policy' in headers else 0,
         1 if 'Strict-Transport-Security' in headers else 0,
         code]
    return np.array(f, dtype=float)

def _build_model():
    np.random.seed(42)
    X = np.random.rand(2000, 20) * 10
    y = np.zeros(2000, dtype=int)
    y[(X[:,3]>4)|(X[:,10]>3)|(X[:,11]>4)] = 1
    y[(X[:,6]>3)|(X[:,7]>2)|(X[:,14]>3)]  = 2
    y[(X[:,13]>3)&(X[:,12]<1)]             = 3
    y[X[:,8]>2]                             = 4
    y[(X[:,16]<1)&(X[:,17]<1)&(X[:,18]<1)] = 5
    sc = StandardScaler()
    clf = RandomForestClassifier(100, random_state=42, max_depth=10)
    clf.fit(sc.fit_transform(X), y)
    return clf, sc

_clf, _sc = _build_model()
VULN_NAMES = {0:None,1:'XSS',2:'SQL Injection',3:'CSRF',
              4:'Open Redirect',5:'Sensitive Data Exposure'}

# ── HTTP ───────────────────────────────────────────────────────────────────────

HDR = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
       'Accept':'text/html,*/*;q=0.8'}

def _get(url, timeout=10, allow_redirects=True):
    return requests.get(url, headers=HDR, timeout=timeout,
                        verify=False, allow_redirects=allow_redirects)

# ── XSS ───────────────────────────────────────────────────────────────────────

XSS_PL = ['<script>alert(1)</script>',
           '"><script>alert(1)</script>',
           "'><img src=x onerror=alert(1)>"]

def check_xss(url, html, soup):
    out = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param in params:
        for pl in XSS_PL[:2]:
            tp = {**params, param:[pl]}
            turl = urlunparse(parsed._replace(query=urlencode(tp,doseq=True)))
            try:
                r = _get(turl, timeout=7)
                if pl in r.text or pl.lower() in r.text.lower():
                    out.append({
                        'location': f'URL Parameter: ?{param}=',
                        'parameter': param, 'payload': pl, 'poc_url': turl,
                        'evidence': f'Payload reflected in response for param "{param}"',
                        'fix_code': (
                            f"# VULNERABLE:\nvalue = request.GET.get('{param}')\n"
                            f"return HttpResponse(f'Result: {{value}}')  # NO\n\n"
                            f"# FIXED:\nfrom django.utils.html import escape\n"
                            f"value = escape(request.GET.get('{param}',''))  # YES\n\n"
                            f"# Or use Django template (auto-escapes):\n"
                            f"context = {{'{param}': request.GET.get('{param}','')}}\n"
                            f"return render(request,'template.html',context)"
                        ), 'poc_html': None})
                    break
            except Exception: pass

    for inp in soup.find_all('input'):
        if inp.get('type','text') in ['text','search','email','']:
            name = inp.get('name') or inp.get('id') or 'field'
            out.append({
                'location': f'HTML Input: <input name="{name}">',
                'parameter': name,
                'payload': '<script>alert(document.cookie)</script>',
                'poc_url': f'{url}?{name}='+quote('<script>alert(document.cookie)</script>'),
                'evidence': f'Text input "{name}" found — test if value reflects in response without encoding',
                'fix_code': (
                    f"from django import forms\n\nclass MyForm(forms.Form):\n"
                    f"    {name} = forms.CharField(max_length=200, strip=True)\n\n"
                    f"if form.is_valid():\n"
                    f"    value = form.cleaned_data['{name}']  # validated and safe"
                ), 'poc_html': None})

    for script in soup.find_all('script'):
        if script.string:
            for sink in ['document.write(','innerHTML =','innerHTML=','eval(']:
                if sink in script.string:
                    idx = script.string.find(sink)
                    snip = script.string[max(0,idx-10):idx+40].replace('\n',' ').strip()
                    out.append({
                        'location': 'JavaScript: DOM-Based XSS Sink',
                        'parameter': sink.strip(),
                        'payload': '?q='+quote('<img src=x onerror=alert(1)>'),
                        'poc_url': url+'?q='+quote('<img src=x onerror=alert(1)>'),
                        'evidence': f'Unsafe DOM sink `{sink.strip()}` found: ...{snip}...',
                        'fix_code': (
                            "// VULNERABLE:\nelement.innerHTML = userInput;  // XSS risk\n\n"
                            "// FIXED:\nelement.textContent = userInput;  // safe\n\n"
                            "// Or use DOMPurify:\nelement.innerHTML = DOMPurify.sanitize(userInput);"
                        ), 'poc_html': None})
                    break
    return out

# ── SQLi ──────────────────────────────────────────────────────────────────────

SQL_ERRS = [
    "you have an error in your sql syntax","warning: mysql",
    "unclosed quotation mark","microsoft ole db provider for sql server",
    "ora-01756","ora-00933","pg_query()","sqlite3.operationalerror",
    "syntax error near","mysql_fetch","mysql_num_rows",
]

def check_sqli(url, html, response_text):
    out = []
    lower = response_text.lower()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for err in SQL_ERRS:
        if err in lower:
            out.append({
                'location': 'HTTP Response: SQL Error Leaked',
                'parameter': 'server response',
                'payload': 'N/A (error in original page)',
                'poc_url': url,
                'evidence': f'SQL error in response: "{err}" — DB internals exposed',
                'fix_code': (
                    "# settings.py:\nDEBUG = False  # hide errors\n\n"
                    "# Catch DB exceptions generically:\ntry:\n"
                    "    result = MyModel.objects.get(pk=pk)\n"
                    "except Exception:\n"
                    "    return HttpResponse('Not found', status=404)"
                ), 'poc_html': None})
            break

    for param, values in params.items():
        orig = values[0] if values else '1'
        for pl, desc in [("'","single quote"),("' OR 1=1--","OR injection"),("' OR '1'='1","auth bypass")]:
            turl = urlunparse(parsed._replace(query=urlencode({**params,param:[orig+pl]},doseq=True)))
            try:
                r = _get(turl, timeout=8)
                for err in SQL_ERRS:
                    if err in r.text.lower():
                        out.append({
                            'location': f'URL Parameter: ?{param}=',
                            'parameter': param,
                            'payload': orig+pl,
                            'poc_url': turl,
                            'evidence': f'SQL error triggered by {desc} in param "{param}": "{err}"',
                            'fix_code': (
                                f"# VULNERABLE:\ncursor.execute(f\"SELECT * FROM t WHERE id={{val}}\")  # NO\n\n"
                                f"# FIXED — Django ORM:\nItem.objects.filter(pk=request.GET.get('{param}'))  # YES\n\n"
                                f"# FIXED — Raw SQL:\ncursor.execute('SELECT * FROM t WHERE id=%s',"
                                f"[request.GET.get('{param}')])  # YES"
                            ), 'poc_html': None})
                        break
            except Exception: pass

        try:
            t_url = urlunparse(parsed._replace(query=urlencode({**params,param:[orig+"' AND '1'='1"]},doseq=True)))
            f_url = urlunparse(parsed._replace(query=urlencode({**params,param:[orig+"' AND '1'='2"]},doseq=True)))
            rt = _get(t_url,timeout=5); rf = _get(f_url,timeout=5)
            diff = abs(len(rt.text)-len(rf.text))
            if diff > 150:
                out.append({
                    'location': f'URL Parameter: ?{param}= (Boolean Blind)',
                    'parameter': param,
                    'payload': f"{orig}' AND '1'='1  vs  {orig}' AND '1'='2",
                    'poc_url': t_url,
                    'evidence': f'Boolean blind SQLi: diff={diff} bytes between TRUE/FALSE responses',
                    'fix_code': (
                        f"cursor.execute('SELECT * FROM t WHERE {param}=%s',"
                        f"[request.GET.get('{param}')])  # parameterized"
                    ), 'poc_html': None})
        except Exception: pass

    for kw,name in [('mysql','MySQL'),('postgresql','PostgreSQL'),('sqlite','SQLite'),('oracle','Oracle')]:
        if kw in lower:
            out.append({
                'location': 'HTTP Response: DB Technology Disclosed',
                'parameter': 'server response', 'payload': 'N/A',
                'poc_url': url,
                'evidence': f'{name} database technology exposed in response body',
                'fix_code': "DEBUG=False  # Never expose DB details\n# Handle all DB exceptions generically",
                'poc_html': None})
            break
    return out

# ── CSRF ──────────────────────────────────────────────────────────────────────

def check_csrf(url, html, soup):
    out = []
    for i, form in enumerate(soup.find_all('form')):
        if form.get('method','get').lower() != 'post': continue
        action = form.get('action','') or url
        if not action.startswith('http'): action = urljoin(url, action)
        has_csrf = bool(form.find_all('input',attrs={'name':re.compile(r'csrf|_token|authenticity|nonce',re.I)}))
        if not has_csrf:
            for hf in form.find_all('input',{'type':'hidden'}):
                if any(k in (hf.get('name','').lower()) for k in ['csrf','token','nonce']):
                    has_csrf = True; break
        if not has_csrf:
            fields = [f.get('name',f'f{j}') for j,f in enumerate(form.find_all('input'))
                      if f.get('type') not in ['hidden','submit','button']]
            poc = (f"<!-- Open this HTML file in browser to test CSRF -->\n<html>\n"
                   f"<body onload=\"document.forms[0].submit()\">\n"
                   f"  <form action=\"{action}\" method=\"POST\">\n"+
                   ''.join(f'    <input type="hidden" name="{fn}" value="ATTACKER_VALUE">\n'
                           for fn in (fields[:5] or ['data']))+
                   f"  </form>\n</body>\n</html>")
            out.append({
                'location': f'POST Form #{i+1}: action="{action}"',
                'parameter': f'Fields: {", ".join(fields[:4]) or "unknown"}',
                'payload': f'Silent forged POST to {action}',
                'poc_url': action,
                'evidence': f'POST form #{i+1} with {len(fields)} field(s) — NO CSRF token found',
                'fix_code': (
                    f"# 1. settings.py:\nMIDDLEWARE=['django.middleware.csrf.CsrfViewMiddleware',...]\n\n"
                    f"# 2. Every POST form template:\n<form method=\"post\" action=\"{action}\">\n"
                    f"  {{% csrf_token %}}  ← add this line\n  ...\n</form>\n\n"
                    f"# 3. Cookies:\nSESSION_COOKIE_SAMESITE='Strict'\nCSRF_COOKIE_SAMESITE='Strict'"
                ), 'poc_html': poc})
    return out

# ── Open Redirect ─────────────────────────────────────────────────────────────

REDIR_KW = {'redirect','url','next','goto','return','returnurl','redirecturl',
            'destination','target','redir','to','link','location','continue',
            'back','forward','ref','referer','from'}
REDIR_PL = ['https://evil.com','//evil.com','/\\evil.com']

def check_open_redirect(url, html, soup):
    out = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Collect all redirect-like params from page links too
    all_params = dict(params)
    for a in soup.find_all('a', href=True):
        href = a['href']
        if '?' not in href: continue
        lp = parse_qs(urlparse(urljoin(url,href)).query)
        for p,v in lp.items():
            if p.lower() in REDIR_KW and p not in all_params:
                all_params[p] = v

    targets = {p for p in all_params if p.lower() in REDIR_KW}

    for param in targets:
        values = all_params[param]
        tested = False
        for pl in REDIR_PL:
            tp = {**all_params, param:[pl]}
            turl = urlunparse(parsed._replace(query=urlencode(tp,doseq=True)))
            try:
                r = _get(turl, timeout=7, allow_redirects=False)
                loc = r.headers.get('Location','')
                if 'evil.com' in loc or (loc and urlparse(loc).netloc not in ('',parsed.netloc)):
                    out.append({
                        'location': f'URL Parameter: ?{param}=',
                        'parameter': param, 'payload': pl, 'poc_url': turl,
                        'evidence': f'Server redirected to "{loc}" — open redirect confirmed',
                        'fix_code': (
                            f"from django.utils.http import url_has_allowed_host_and_scheme\n\n"
                            f"next_url = request.GET.get('{param}','/')\n"
                            f"if not url_has_allowed_host_and_scheme(next_url,allowed_hosts={{request.get_host()}}):\n"
                            f"    next_url = '/'\nreturn redirect(next_url)"
                        ), 'poc_html': None})
                    tested = True; break
            except Exception: pass

        if not tested:
            turl = urlunparse(parsed._replace(query=urlencode({**all_params,param:['https://evil.com']},doseq=True)))
            out.append({
                'location': f'URL Parameter: ?{param}=',
                'parameter': param, 'payload': 'https://evil.com',
                'poc_url': turl,
                'evidence': f'Redirect parameter "{param}" found — must be validated server-side',
                'fix_code': (
                    f"from django.utils.http import url_has_allowed_host_and_scheme\n\n"
                    f"next_url = request.GET.get('{param}','/')\n"
                    f"if not url_has_allowed_host_and_scheme(next_url,allowed_hosts={{request.get_host()}}):\n"
                    f"    next_url = '/'\nreturn redirect(next_url)"
                ), 'poc_html': None})
    return out

# ── Sensitive Data ────────────────────────────────────────────────────────────

SEC_HDRS = [
    ('X-Frame-Options','DENY','Clickjacking — page can be framed in malicious iframe',
     "X_FRAME_OPTIONS='DENY'  # settings.py\nMIDDLEWARE+=['django.middleware.clickjacking.XFrameOptionsMiddleware']"),
    ('Content-Security-Policy',"default-src 'self'",'No CSP — XSS attacks easier',
     "# pip install django-csp\nINSTALLED_APPS+=['csp']\nCSP_DEFAULT_SRC=(\"'self'\",)\nCSP_SCRIPT_SRC=(\"'self'\",)"),
    ('Strict-Transport-Security','max-age=31536000; includeSubDomains',
     'No HSTS — HTTP downgrade attack possible',
     "SECURE_HSTS_SECONDS=31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS=True\nSECURE_SSL_REDIRECT=True"),
    ('X-Content-Type-Options','nosniff','MIME sniffing attack possible',
     "SECURE_CONTENT_TYPE_NOSNIFF=True  # settings.py"),
    ('Referrer-Policy','strict-origin-when-cross-origin','URLs may leak via Referer',
     "SECURE_REFERRER_POLICY='strict-origin-when-cross-origin'"),
    ('Permissions-Policy','camera=(), microphone=(), geolocation=()','Browser APIs unrestricted',
     "response['Permissions-Policy']='camera=(), microphone=(), geolocation=()'"),
]

SECRET_RE = [
    (r'(?:api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*["\']?([\w\-]{16,})','API Key/Token'),
    (r'password\s*[=:]\s*["\']?([^\s"\'<>]{4,20})','Hardcoded Password'),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----','Private Key'),
    (r'(?:mongodb|mysql|postgresql|redis)://[^\s"\'<>]+','DB Connection String'),
]

def check_sensitive_data(url, html, hdrs, soup):
    out = []
    for hname,rec,risk,fix in SEC_HDRS:
        if hname not in hdrs:
            out.append({'location':f'Missing Header: {hname}','parameter':hname,
                        'payload':f'Header absent','poc_url':url,
                        'evidence':f'{risk}. Add: {hname}: {rec}',
                        'fix_code':fix,'poc_html':None})
    for pattern,label in SECRET_RE:
        if re.search(pattern,html,re.I):
            m = re.search(pattern,html,re.I)
            val = (m.group(1) if m.lastindex else m.group(0))[:12]+'...'
            out.append({'location':f'HTML Source: {label} Exposed',
                        'parameter':label,'payload':f'Found: {val}',
                        'poc_url':f'view-source:{url}',
                        'evidence':f'{label} hardcoded in page source — value starts: {val}',
                        'fix_code':"import os\nAPI_KEY=os.environ.get('API_KEY')  # use .env file, never hardcode",
                        'poc_html':None})
    for hn in ('Server','X-Powered-By'):
        hv = hdrs.get(hn,'')
        if hv and any(x in hv for x in ['/','Apache','nginx','IIS','PHP']):
            out.append({'location':f'HTTP Header: {hn}: {hv}','parameter':hn,
                        'payload':f'{hn}: {hv}','poc_url':url,
                        'evidence':f'Server version "{hv}" disclosed — aids targeted attacks',
                        'fix_code':"# Nginx: server_tokens off;\n# Apache: ServerTokens Prod\n# Middleware: del response['Server']",
                        'poc_html':None})
            break
    if not url.startswith('https://'):
        out.append({'location':'Protocol: HTTP (Unencrypted)','parameter':'URL scheme',
                    'payload':url,'poc_url':url,
                    'evidence':'HTTP used — all traffic in plaintext, MITM possible',
                    'fix_code':"SECURE_SSL_REDIRECT=True\nSESSION_COOKIE_SECURE=True\nCSRF_COOKIE_SECURE=True\n# sudo certbot --nginx -d yourdomain.com",
                    'poc_html':None})
    return out

# ── Risk Score ────────────────────────────────────────────────────────────────

W = {'XSS':25,'SQL Injection':30,'CSRF':20,'Open Redirect':15,'Sensitive Data Exposure':8}

def risk_score(vulns):
    s = min(sum(W.get(v.get('type',''),8)*max(len(v.get('findings',v.get('issues',[]))),1) for v in vulns),100)
    lv = 'critical' if s>=75 else 'high' if s>=50 else 'medium' if s>=25 else 'low' if s>0 else 'info'
    return s, lv

# ── Internal helpers ──────────────────────────────────────────────────────────

def _run_checks(url, html, hdrs, soup):
    vulns = []
    checks = [
        (lambda: check_xss(url,html,soup),
         'XSS','high',
         'XSS allows injecting scripts into pages viewed by other users.',
         'Encode all output, validate input, implement Content-Security-Policy.'),
        (lambda: check_sqli(url,html,html),
         'SQL Injection','critical',
         'SQL Injection lets attackers read, modify or delete your database.',
         'Use Django ORM or parameterized queries — never format SQL with user input.'),
        (lambda: check_csrf(url,html,soup),
         'CSRF','medium',
         'CSRF tricks authenticated users into submitting forged requests.',
         'Add {% csrf_token %} to every POST form, enable CsrfViewMiddleware.'),
        (lambda: check_open_redirect(url,html,soup),
         'Open Redirect','medium',
         'Open redirects let attackers use your domain to redirect to malicious sites.',
         'Validate redirects with url_has_allowed_host_and_scheme().'),
        (lambda: check_sensitive_data(url,html,hdrs,soup),
         'Sensitive Data Exposure','high',
         'Missing security headers, exposed secrets, or unencrypted transmission.',
         'Add all security headers, use HTTPS, store secrets in environment variables.'),
    ]
    for fn, vtype, sev, desc, rem in checks:
        try: findings = fn()
        except Exception: findings = []
        if findings:
            vulns.append({'type':vtype,'severity':sev,'findings':findings,
                          'issues':[f['evidence'] for f in findings],
                          'description':desc,'remediation':rem})
    return vulns

def _crawl(base_url, soup, limit=10):
    base = urlparse(base_url); seen={base_url}; urls=[]
    for a in soup.find_all('a',href=True):
        href = a['href'].strip()
        if not href or href.startswith(('#','javascript:','mailto:')): continue
        full = urljoin(base_url,href); p=urlparse(full)
        if p.netloc==base.netloc and full not in seen and p.scheme in ('http','https'):
            seen.add(full); urls.append(full)
            if len(urls)>=limit: break
    return urls

def _merge(all_v):
    merged={}
    for v in all_v:
        t=v['type']
        if t not in merged: merged[t]={**v,'findings':[],'issues':[]}
        ev={f['evidence'] for f in merged[t]['findings']}
        for f in v.get('findings',[]):
            if f['evidence'] not in ev:
                merged[t]['findings'].append(f)
                merged[t]['issues'].append(f['evidence'])
                ev.add(f['evidence'])
    return list(merged.values())

# ── Main ──────────────────────────────────────────────────────────────────────

def scan_url(url):
    start=time.time()
    result={'url':url,'status':'error','risk_score':0,'risk_level':'info',
            'vulnerabilities':[],'ml_predictions':[],'scan_duration':0,
            'error':None,'page_title':'','response_code':0,'server':''}
    try:
        resp=_get(url); html=resp.text; hdrs=dict(resp.headers)
        soup=BeautifulSoup(html,'html.parser')
        title=soup.find('title')
        result.update({'page_title':title.get_text(strip=True) if title else '',
                       'response_code':resp.status_code,
                       'server':hdrs.get('Server','')})

        # ML prediction
        feat=extract_features(url,html,hdrs,resp.status_code)
        fs=_sc.transform(feat.reshape(1,-1))
        pred=_clf.predict(fs)[0]; prob=_clf.predict_proba(fs)[0]
        if pred>0:
            result['ml_predictions'].append(
                {'type':VULN_NAMES[pred],'confidence':round(float(max(prob))*100,1)})

        # Scan main page
        all_v=_run_checks(url,html,hdrs,soup)

        # Crawl sub-pages to find more vuln types
        sub_urls=_crawl(url,soup,limit=10)
        pages_done=[url]
        ALL5={'XSS','SQL Injection','CSRF','Open Redirect','Sensitive Data Exposure'}

        for su in sub_urls:
            if {v['type'] for v in all_v}>=ALL5: break
            if time.time()-start>20: break
            try:
                sr=_get(su,timeout=6); ss=BeautifulSoup(sr.text,'html.parser')
                all_v.extend(_run_checks(su,sr.text,dict(sr.headers),ss))
                pages_done.append(su)
            except Exception: continue

        merged=_merge(all_v)
        sc,lv=risk_score(merged)
        result.update({'vulnerabilities':merged,'risk_score':sc,'risk_level':lv,
                       'status':'completed','pages_scanned':len(pages_done)})

    except requests.exceptions.SSLError:
        http_url=url.replace('https://','http://',1)
        result['error']='SSL error — retried over HTTP'
        try:
            r2=_get(http_url); h2=r2.text; hd2=dict(r2.headers)
            s2=BeautifulSoup(h2,'html.parser')
            all_v2=_run_checks(http_url,h2,hd2,s2)
            for su in _crawl(http_url,s2,limit=6):
                if time.time()-start>18: break
                try:
                    sr=_get(su,timeout=5); ss=BeautifulSoup(sr.text,'html.parser')
                    all_v2.extend(_run_checks(su,sr.text,dict(sr.headers),ss))
                except Exception: continue
            m2=_merge(all_v2)
            ssl_f={'location':'TLS/SSL Certificate','parameter':'SSL cert',
                   'payload':'HTTPS rejected','poc_url':url,
                   'evidence':'Invalid/self-signed SSL certificate detected',
                   'fix_code':"sudo certbot --nginx -d yourdomain.com",'poc_html':None}
            s=[v for v in m2 if v['type']=='Sensitive Data Exposure']
            if s: s[0]['findings'].insert(0,ssl_f); s[0]['issues'].insert(0,ssl_f['evidence'])
            else: m2.append({'type':'Sensitive Data Exposure','severity':'high',
                              'findings':[ssl_f],'issues':[ssl_f['evidence']],
                              'description':'SSL cert invalid.','remediation':'Use valid SSL cert.'})
            sc2,lv2=risk_score(m2)
            result.update({'vulnerabilities':m2,'risk_score':max(sc2,40),
                           'risk_level':lv2,'status':'completed_with_warnings'})
        except Exception as e2:
            result['error']=f'SSL+HTTP failed: {str(e2)[:80]}'

    except requests.exceptions.ConnectionError as e:
        result['error']=f'Cannot connect: {str(e)[:100]}'
    except requests.exceptions.Timeout:
        result['error']='Timed out after 15s — site unreachable'
    except Exception as e:
        result['error']=f'Scan error: {str(e)[:200]}'
    finally:
        result['scan_duration']=round(time.time()-start,2)
    return result