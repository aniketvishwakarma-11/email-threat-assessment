from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from views import analyze_email, analyze_pdf_text, rule_based_pdf_check


class ThreatAnalysisTests(TestCase):
    def test_malicious_pdf_indicators_produce_explainable_critical_report(self):
        report = analyze_pdf_text(
            "Run PowerShell to download payload.exe and disable antivirus."
        )

        self.assertEqual(report["verdict"], "malicious")
        self.assertEqual(report["severity"], "critical")
        self.assertGreaterEqual(report["risk_score"], 80)
        self.assertEqual(report["analysis_source"], "local_rules")
        self.assertTrue({"payload_execution", "command_execution", "security_bypass"}.issubset(
            {reason["code"] for reason in report["reasons"]}
        ))

    def test_suspicious_email_contains_reasons_and_recommendation(self):
        report = analyze_email(
            "Your account is suspended. Verify your credentials immediately."
        )

        self.assertIn(report["verdict"], {"suspicious", "malicious"})
        self.assertGreater(report["risk_score"], 0)
        self.assertTrue(report["reasons"])
        self.assertIn("Do not", report["recommendation"])

    def test_empty_email_is_unknown_instead_of_ham(self):
        report = analyze_email("   ")

        self.assertEqual(report["verdict"], "unknown")
        self.assertTrue(report["fallback"])
        self.assertEqual(report["risk_score"], 0)

    def test_unreviewed_benign_pdf_is_not_marked_safe_without_ai(self):
        report = analyze_pdf_text("A normal project status report with no threat indicators.")

        self.assertEqual(report["verdict"], "unknown")
        self.assertTrue(report["fallback"])
        self.assertEqual(report["analysis_source"], "local_rules")

    def test_malicious_rule_has_priority_over_suspicious_rule(self):
        self.assertEqual(
            rule_based_pdf_check("Please enter your password, then run PowerShell."),
            "malicious",
        )

    def test_malicious_score_breakdown_reconciles_to_final_score(self):
        report = analyze_pdf_text("This document references ransomware.")

        self.assertEqual(report["verdict"], "malicious")
        self.assertEqual(report["risk_score"], 80)
        self.assertEqual(
            sum(item["points"] for item in report["score_breakdown"]),
            report["risk_score"],
        )
        self.assertTrue(report["score_note"])

    def test_malicious_score_breakdown_reports_cap(self):
        report = analyze_pdf_text(
            "Run PowerShell to download payload.exe and disable antivirus."
        )

        self.assertEqual(report["risk_score"], 100)
        self.assertGreater(report["raw_score"], 100)
        self.assertIn("capped", report["score_note"])

    def test_home_page_renders(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Email Threat Assessment")
        self.assertContains(response, "Demo samples")

    @patch("views._model_prediction", return_value="spam")
    def test_email_report_includes_legacy_comparison_and_score_breakdown(
        self, model_prediction
    ):
        response = self.client.post(
            "/",
            {
                "email_check": "1",
                "text": "URGENT: Your account is suspended. Verify your credentials immediately.",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Original prototype")
        self.assertContains(response, "Improved assessment")
        self.assertContains(response, "Score breakdown")
        self.assertContains(response, "email-preview")
        self.assertContains(response, "email-text-data")
        self.assertEqual(response.context["email_legacy_label"], "Spam")
        self.assertTrue(response.context["email_report"]["score_breakdown"])
        self.assertEqual(
            sum(
                item["points"]
                for item in response.context["email_report"]["score_breakdown"]
            ),
            response.context["email_report"]["risk_score"],
        )
        self.assertTrue(response.context["email_pipeline"])

    def test_email_form_returns_report(self):
        response = self.client.post(
            "/",
            {
                "email_check": "1",
                "text": "Urgent payment request: click here to verify your account.",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Email threat report")
        self.assertContains(response, "Recommendation")

    def test_invalid_pdf_is_rejected_before_extraction(self):
        upload = SimpleUploadedFile(
            "not-a-pdf.pdf",
            b"not a real pdf",
            content_type="application/pdf",
        )
        response = self.client.post("/", {"pdf_check": "1", "pdf_file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "does not appear to be a valid PDF")

    @patch("views.extract_pdf_text", return_value="PowerShell can download payload.exe")
    def test_valid_pdf_upload_returns_threat_report(self, extract_pdf_text):
        upload = SimpleUploadedFile(
            "threat.pdf",
            b"%PDF-1.7\nvalid test fixture",
            content_type="application/pdf",
        )
        response = self.client.post("/", {"pdf_check": "1", "pdf_file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "PDF threat report")
        self.assertContains(response, "MALICIOUS")
        extract_pdf_text.assert_called_once()

    @patch(
        "views.extract_pdf_text",
        return_value="A normal project status report with no threat indicators.",
    )
    def test_benign_pdf_compares_legacy_safe_with_unknown(self, extract_pdf_text):
        upload = SimpleUploadedFile(
            "report.pdf",
            b"%PDF-1.7\nvalid test fixture",
            content_type="application/pdf",
        )
        response = self.client.post("/", {"pdf_check": "1", "pdf_file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["pdf_report"]["verdict"], "unknown")
        self.assertEqual(response.context["pdf_legacy_label"], "Safe")
        self.assertEqual(response.context["pdf_pipeline"][3]["status"], "skipped")
        self.assertContains(response, "pdf-preview")
        self.assertContains(response, "Why unknown?")
        extract_pdf_text.assert_called_once()

    def test_pdf_upload_limit_is_enforced(self):
        upload = SimpleUploadedFile(
            "large.pdf",
            b"%PDF-" + b"x" * 20,
            content_type="application/pdf",
        )
        with self.settings(MAX_UPLOAD_SIZE=10):
            response = self.client.post("/", {"pdf_check": "1", "pdf_file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "exceeds the maximum upload size")
