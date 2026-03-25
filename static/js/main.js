'use strict';

/* ── Utilities ─────────────────────────────── */
function getCookie(name) {
    const val = `; ${document.cookie}`;
    const parts = val.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return '';
}

function setUrl(url) {
    const inp = document.getElementById('targetUrl');
    if (inp) { inp.value = url.replace(/^https?:\/\//, ''); inp.focus(); }
}

function show(el) { if (el) el.classList.remove('hidden'); }
function hide(el) { if (el) el.classList.add('hidden'); }

function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function riskColor(level) {
    return {critical:'#FF3B30',high:'#FF6B35',medium:'#FFB800',low:'#2ECC71',info:'#00B4FF'}[level] || '#888';
}

function sevColor(sev) {
    return {critical:'#FF3B30',high:'#FF6B35',medium:'#FFB800',low:'#2ECC71',info:'#00B4FF'}[sev] || '#888';
}

/* ── Progress ──────────────────────────────── */
const STEPS = ['step1','step2','step3','step4','step5'];
let _progTimer = null, _stepIdx = 0;

function startProgress(url) {
    show(document.getElementById('scanProgress'));
    hide(document.getElementById('scanResults'));
    hide(document.getElementById('scanError'));
    const pu = document.getElementById('progressUrl');
    if (pu) pu.textContent = url;
    const bar = document.getElementById('progressBar');
    if (bar) bar.style.width = '5%';
    _stepIdx = 0;
    STEPS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove('active','done');
    });
    activateStep(0);
    _progTimer = setInterval(() => {
        _stepIdx++;
        if (_stepIdx < STEPS.length) {
            const prev = document.getElementById(STEPS[_stepIdx-1]);
            if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
            activateStep(_stepIdx);
            const pct = Math.min(10 + (_stepIdx / STEPS.length)*80, 88);
            if (bar) bar.style.width = pct + '%';
        }
    }, 1800);
}

function activateStep(i) {
    if (i < STEPS.length) {
        const el = document.getElementById(STEPS[i]);
        if (el) el.classList.add('active');
    }
}

function stopProgress() {
    clearInterval(_progTimer);
    STEPS.forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.classList.remove('active'); el.classList.add('done'); }
    });
    const bar = document.getElementById('progressBar');
    if (bar) bar.style.width = '100%';
    setTimeout(() => hide(document.getElementById('scanProgress')), 500);
}

/* ── Render results ────────────────────────── */
function renderResults(data) {
    const container = document.getElementById('scanResults');
    if (!container) return;

    const rc = riskColor(data.risk_level);
    const status = data.status || 'completed';

    // Error banner
    let errHtml = '';
    if (data.error) {
        errHtml = `<div style="padding:10px 20px;background:rgba(255,184,0,.08);
            border-bottom:1px solid rgba(255,184,0,.2);font-size:12px;
            color:#FFB800;font-family:monospace;">
            ⚠ ${escHtml(data.error)}
        </div>`;
    }

    // Vulnerability list
    let vulnHtml = '';
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        data.vulnerabilities.forEach(v => {
            const sc = sevColor(v.severity);
            const findings = v.findings || [];
            let issuesList = '';
            if (findings.length > 0) {
                findings.slice(0,3).forEach(f => {
                    issuesList += `<div style="font-size:11px;color:var(--text2);
                        padding:2px 0 2px 12px;position:relative;">
                        <span style="position:absolute;left:0;color:var(--text3);">→</span>
                        ${escHtml(f.evidence)}
                    </div>`;
                });
                if (findings.length > 3) {
                    issuesList += `<div style="font-size:11px;color:var(--text3);
                        padding:2px 0 2px 12px;">+${findings.length-3} more findings</div>`;
                }
            } else if (v.issues) {
                v.issues.slice(0,3).forEach(iss => {
                    issuesList += `<div style="font-size:11px;color:var(--text2);
                        padding:2px 0 2px 12px;position:relative;">
                        <span style="position:absolute;left:0;color:var(--text3);">→</span>
                        ${escHtml(iss)}
                    </div>`;
                });
            }
            vulnHtml += `
            <div style="border-left:3px solid ${sc};padding:10px 14px;margin-top:10px;
                background:var(--bg);border-radius:0 6px 6px 0;">
                <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                    <span style="font-weight:600;font-size:13px;">${escHtml(v.type)}</span>
                    <span style="font-family:monospace;font-size:10px;font-weight:700;
                        background:${sc}22;color:${sc};padding:2px 8px;border-radius:4px;">
                        ${escHtml((v.severity||'').toUpperCase())}
                    </span>
                </div>
                ${issuesList}
            </div>`;
        });
    } else {
        if (status === 'error' || data.error) {
            vulnHtml = `<div style="padding:16px;text-align:center;color:var(--medium);font-size:13px;">
                ⚠ Could not complete scan — ${escHtml(data.error || 'site unreachable')}
            </div>`;
        } else {
            vulnHtml = `<div style="padding:16px;text-align:center;color:var(--low);font-weight:600;">
                ✅ No vulnerabilities detected
            </div>`;
        }
    }

    // ML badge
    let mlHtml = '';
    if (data.ml_predictions && data.ml_predictions.length > 0) {
        const p = data.ml_predictions[0];
        mlHtml = `<div style="padding:10px 20px;border-top:1px solid var(--border);">
            <span style="display:inline-flex;align-items:center;gap:6px;
                background:rgba(0,180,255,.1);border:1px solid rgba(0,180,255,.3);
                border-radius:5px;padding:4px 10px;font-family:monospace;
                font-size:11px;color:var(--accent2);">
                🤖 ML: ${escHtml(p.type)} — ${p.confidence}% confidence
            </span>
        </div>`;
    }

    // Action buttons
    let btnHtml = '';
    if (data.pdf_url) {
        btnHtml += `<a href="${escHtml(data.pdf_url)}" download
            style="display:inline-flex;align-items:center;gap:6px;
            background:var(--accent);color:var(--bg);font-family:monospace;
            font-size:11px;font-weight:700;padding:8px 14px;border-radius:5px;
            text-decoration:none;">⬇ PDF</a>`;
    }
    if (data.scan_id) {
        btnHtml += `<a href="/scan/${data.scan_id}/"
            style="display:inline-flex;align-items:center;gap:6px;
            background:rgba(0,180,255,.1);border:1px solid rgba(0,180,255,.3);
            color:var(--accent2);font-family:monospace;font-size:11px;
            padding:8px 14px;border-radius:5px;text-decoration:none;">
            View Full Report →</a>`;
    }

    container.innerHTML = `
    <div style="background:var(--bg2);border:2px solid ${rc};border-radius:10px;overflow:hidden;margin-top:16px;">
        ${errHtml}
        <div style="display:flex;align-items:center;justify-content:space-between;
            padding:18px 20px;flex-wrap:wrap;gap:12px;border-bottom:1px solid var(--border);">
            <div style="display:flex;align-items:center;gap:16px;">
                <div>
                    <span style="font-family:monospace;font-size:48px;font-weight:700;
                        line-height:1;color:${rc};">${data.risk_score}</span>
                    <span style="font-size:11px;color:var(--text2);">/100</span>
                </div>
                <div>
                    <div style="font-family:monospace;font-size:11px;color:${rc};font-weight:700;">
                        ${(data.risk_level||'INFO').toUpperCase()} RISK
                    </div>
                    <div style="font-family:monospace;font-size:11px;color:var(--accent2);margin-top:2px;">
                        ${escHtml(data.url || '')}
                    </div>
                    <div style="font-size:11px;color:var(--text2);margin-top:2px;">
                        ${data.vulnerabilities_found} vuln${data.vulnerabilities_found !== 1 ? 's' : ''}
                        &middot; ${data.scan_duration}s
                        ${data.response_code ? '&middot; HTTP ' + data.response_code : ''}
                    </div>
                </div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">${btnHtml}</div>
        </div>
        <div style="padding:4px 16px 10px;">${vulnHtml}</div>
        ${mlHtml}
    </div>`;

    show(container);
}

/* ── Main scan function ────────────────────── */
async function startScan() {
    const inp   = document.getElementById('targetUrl');
    const btn   = document.getElementById('scanBtn');
    const errEl = document.getElementById('scanError');
    if (!inp) return;

    let url = inp.value.trim();
    if (!url) { showErr('Please enter a target URL.'); return; }
    if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;

    if (btn) { btn.disabled = true; btn.querySelector('.btn-text').textContent = 'SCANNING...'; }
    hide(errEl);
    startProgress(url);

    try {
        const resp = await fetch('/scan/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
            body: JSON.stringify({ url }),
        });
        const data = await resp.json();
        stopProgress();
        data.url = data.url || url;
        renderResults(data);
    } catch (err) {
        stopProgress();
        showErr('Network error: ' + err.message);
    } finally {
        if (btn) { btn.disabled = false; btn.querySelector('.btn-text').textContent = 'START SCAN'; }
    }
}

function showErr(msg) {
    const el = document.getElementById('scanError');
    if (el) { el.textContent = '✗ ' + msg; show(el); }
}

/* ── Enter key ─────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
    const inp = document.getElementById('targetUrl');
    if (inp) inp.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
    // Animate risk bars on detail page
    document.querySelectorAll('.risk-bar-fill').forEach(bar => {
        const w = bar.style.width;
        bar.style.width = '0%';
        setTimeout(() => { bar.style.width = w; }, 100);
    });
});