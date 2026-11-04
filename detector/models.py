from django.db import models


class ScanRecord(models.Model):
    class ScanType(models.TextChoices):
        EMAIL = "email", "Email"
        PDF = "pdf", "PDF"

    class Verdict(models.TextChoices):
        HAM = "ham", "Ham"
        SPAM = "spam", "Spam"
        SAFE = "safe", "Safe"
        SUSPICIOUS = "suspicious", "Suspicious"
        MALICIOUS = "malicious", "Malicious"

    scan_type = models.CharField(max_length=10, choices=ScanType.choices)
    verdict = models.CharField(max_length=12, choices=Verdict.choices)
    confidence = models.FloatField(null=True, blank=True)
    input_length = models.PositiveIntegerField(default=0)
    indicators = models.JSONField(default=list, blank=True)
    summary = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "detector"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.get_scan_type_display()} - {self.get_verdict_display()}"
