from django.core.management.base import BaseCommand
from scanner.models import ScanResult
import os

class Command(BaseCommand):
    help = 'Delete all scan records and their PDF files'

    def handle(self, *args, **options):
        scans = ScanResult.objects.all()
        count = scans.count()
        for scan in scans:
            if scan.pdf_report:
                try:
                    scan.pdf_report.delete(save=False)
                except Exception:
                    pass
        scans.delete()
        self.stdout.write(self.style.SUCCESS(f'Deleted {count} scan record(s).'))