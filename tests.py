from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch

from detector.models import ScanRecord


class ScanHistoryTests(TestCase):
    def test_email_scan_is_recorded_without_raw_content(self):
        message = "Congratulations, claim your free prize now!"
        response = self.client.post(reverse("home"), {"text": message, "email_check": ""})

        self.assertEqual(response.status_code, 200)
        record = ScanRecord.objects.get()
        self.assertEqual(record.scan_type, ScanRecord.ScanType.EMAIL)
        self.assertEqual(record.input_length, len(message))
        self.assertNotIn("Congratulations", record.summary)

    def test_pdf_scan_is_recorded_with_indicators(self):
        uploaded = SimpleUploadedFile(
            "notice.pdf",
            b"%PDF-1.4\n1 0 obj\n<<>>\nstream\npowershell disable antivirus\nendstream\n%%EOF",
            content_type="application/pdf",
        )

        with patch("detector.views.extract_pdf_text", return_value="powershell disable antivirus"):
            response = self.client.post(reverse("home"), {"pdf_file": uploaded, "pdf_check": ""})

        self.assertEqual(response.status_code, 200)
        record = ScanRecord.objects.get()
        self.assertEqual(record.scan_type, ScanRecord.ScanType.PDF)
        self.assertEqual(record.verdict, ScanRecord.Verdict.MALICIOUS)
        self.assertIn("powershell", record.indicators)

    def test_history_and_csv_export_are_available(self):
        ScanRecord.objects.create(
            scan_type=ScanRecord.ScanType.EMAIL,
            verdict=ScanRecord.Verdict.HAM,
            input_length=12,
        )

        history = self.client.get(reverse("history"))
        export = self.client.get(reverse("export_history"))

        self.assertContains(history, "Ham")
        self.assertEqual(export.status_code, 200)
        self.assertIn("text/csv", export["Content-Type"])
        self.assertIn("scan_type", export.content.decode())
