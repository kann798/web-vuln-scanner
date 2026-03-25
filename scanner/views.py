import json
import os
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.core.files.base import ContentFile
from django.utils import timezone

from .models import ScanResult
from .ml_scanner import scan_url
from .pdf_report import generate_pdf_report


def index(request):
    """Main dashboard view."""
    recent_scans = ScanResult.objects.all()[:10]
    
    # Stats for dashboard
    total_scans = ScanResult.objects.count()
    critical_scans = ScanResult.objects.filter(risk_level__in=['critical', 'high']).count()
    
    context = {
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'critical_scans': critical_scans,
    }
    return render(request, 'scanner/index.html', context)


def dashboard(request):
    """Vulnerability Distribution Dashboard — pie + bar charts."""
    scans = ScanResult.objects.all()

    # ── Aggregate vulnerability type counts (OWASP categories) ──────────────
    vuln_counts = {
        'XSS': 0,
        'SQL Injection': 0,
        'CSRF': 0,
        'Open Redirect': 0,
        'Sensitive Data Exposure': 0,
    }

    # ── Severity level counts ────────────────────────────────────────────────
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
    }

    total_findings = 0

    for scan in scans:
        try:
            vulns = scan.vulnerabilities  # parsed from JSON
            for vuln in vulns:
                vtype = vuln.get('type', '')
                vsev  = vuln.get('severity', 'info')
                issues_count = len(vuln.get('findings', vuln.get('issues', [])))
                count = max(issues_count, 1)

                if vtype in vuln_counts:
                    vuln_counts[vtype] += count
                if vsev in severity_counts:
                    severity_counts[vsev] += count
                total_findings += count
        except Exception:
            pass

    # Risk level distribution across all scans
    risk_dist = {
        'critical': ScanResult.objects.filter(risk_level='critical').count(),
        'high':     ScanResult.objects.filter(risk_level='high').count(),
        'medium':   ScanResult.objects.filter(risk_level='medium').count(),
        'low':      ScanResult.objects.filter(risk_level='low').count(),
        'info':     ScanResult.objects.filter(risk_level='info').count(),
    }

    context = {
        'total_scans': scans.count(),
        'total_findings': total_findings,
        'vuln_counts': json.dumps(vuln_counts),
        'severity_counts': json.dumps(severity_counts),
        'risk_dist': json.dumps(risk_dist),
    }
    return render(request, 'scanner/dashboard.html', context)


@csrf_exempt
@require_POST
def start_scan(request):
    """Initiate a vulnerability scan."""
    try:
        data = json.loads(request.body)
        url = data.get('url', '').strip()
    except (json.JSONDecodeError, AttributeError):
        url = request.POST.get('url', '').strip()

    if not url:
        return JsonResponse({'error': 'URL is required'}, status=400)

    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Run scan
    scan_data = scan_url(url)

    # Save to DB
    scan_obj = ScanResult(
        url=url,
        risk_score=scan_data['risk_score'],
        risk_level=scan_data['risk_level'],
        vulnerabilities_found=len(scan_data['vulnerabilities']),
        scan_duration=scan_data['scan_duration'],
        status=scan_data['status'],
    )
    scan_obj.vulnerabilities = scan_data['vulnerabilities']
    scan_obj.save()

    # Generate PDF
    try:
        pdf_buffer = generate_pdf_report(scan_obj)
        filename = f'report_{scan_obj.pk}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        scan_obj.pdf_report.save(filename, ContentFile(pdf_buffer.read()), save=True)
    except Exception as e:
        print(f"PDF generation error: {e}")

    return JsonResponse({
        'success': True,
        'scan_id': scan_obj.pk,
        'risk_score': scan_obj.risk_score,
        'risk_level': scan_obj.risk_level,
        'vulnerabilities_found': scan_obj.vulnerabilities_found,
        'scan_duration': scan_obj.scan_duration,
        'vulnerabilities': scan_data['vulnerabilities'],
        'ml_predictions': scan_data.get('ml_predictions', []),
        'page_title': scan_data.get('page_title', ''),
        'response_code': scan_data.get('response_code', 0),
        'error': scan_data.get('error'),
        'pdf_url': scan_obj.pdf_report.url if scan_obj.pdf_report else None,
    })


def scan_detail(request, scan_id):
    """View for a specific scan result."""
    scan = get_object_or_404(ScanResult, pk=scan_id)
    return render(request, 'scanner/scan_detail.html', {'scan': scan})


def download_report(request, scan_id):
    """Download PDF report for a scan."""
    scan = get_object_or_404(ScanResult, pk=scan_id)
    
    if not scan.pdf_report:
        # Regenerate if missing
        try:
            pdf_buffer = generate_pdf_report(scan)
            from django.utils import timezone
            filename = f'report_{scan.pk}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            scan.pdf_report.save(filename, ContentFile(pdf_buffer.read()), save=True)
            pdf_buffer.seek(0)
        except Exception as e:
            return HttpResponse(f'PDF generation failed: {e}', status=500)
    
    response = FileResponse(
        scan.pdf_report.open('rb'),
        content_type='application/pdf',
    )
    response['Content-Disposition'] = f'attachment; filename="security_report_{scan.pk}.pdf"'
    return response


def scan_history(request):
    """View all past scans."""
    scans = ScanResult.objects.all()
    return render(request, 'scanner/history.html', {'scans': scans})


@csrf_exempt
@require_POST
def delete_scan(request, scan_id):
    """Delete a single scan record and its PDF."""
    scan = get_object_or_404(ScanResult, pk=scan_id)
    # Delete the PDF file from disk if it exists
    if scan.pdf_report:
        try:
            scan.pdf_report.delete(save=False)
        except Exception:
            pass
    scan.delete()
    return JsonResponse({'success': True, 'message': f'Scan #{scan_id} deleted.'})


@csrf_exempt
@require_POST
def clear_history(request):
    """Delete ALL scan records and their PDFs."""
    scans = ScanResult.objects.all()
    count = scans.count()
    for scan in scans:
        if scan.pdf_report:
            try:
                scan.pdf_report.delete(save=False)
            except Exception:
                pass
    scans.delete()
    return JsonResponse({'success': True, 'message': f'{count} scan(s) deleted.', 'count': count})


@require_GET
def api_history(request):
    """JSON API for scan history."""
    scans = ScanResult.objects.all()[:20]
    data = []
    for s in scans:
        data.append({
            'id': s.pk,
            'url': s.url,
            'risk_score': s.risk_score,
            'risk_level': s.risk_level,
            'vulnerabilities_found': s.vulnerabilities_found,
            'scan_date': s.scan_date.isoformat(),
            'scan_duration': s.scan_duration,
        })
    return JsonResponse({'scans': data})