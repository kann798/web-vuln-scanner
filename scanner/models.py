from django.db import models
import json


class ScanResult(models.Model):
    RISK_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    url = models.URLField(max_length=2048)
    scan_date = models.DateTimeField(auto_now_add=True)
    risk_score = models.IntegerField(default=0)  # 0-100
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS, default='info')
    vulnerabilities_found = models.IntegerField(default=0)
    scan_duration = models.FloatField(default=0.0)  # seconds
    status = models.CharField(max_length=20, default='completed')
    vulnerabilities_json = models.TextField(default='[]')
    pdf_report = models.FileField(upload_to='reports/', blank=True, null=True)

    class Meta:
        ordering = ['-scan_date']

    def __str__(self):
        return f"Scan of {self.url} on {self.scan_date.strftime('%Y-%m-%d %H:%M')}"

    @property
    def vulnerabilities(self):
        return json.loads(self.vulnerabilities_json)

    @vulnerabilities.setter
    def vulnerabilities(self, value):
        self.vulnerabilities_json = json.dumps(value)

    def get_risk_color(self):
        colors = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFAA00',
            'low': '#00AA00',
            'info': '#0088CC',
        }
        return colors.get(self.risk_level, '#666666')
