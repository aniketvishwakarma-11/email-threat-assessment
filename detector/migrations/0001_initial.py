from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ScanRecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("scan_type", models.CharField(choices=[("email", "Email"), ("pdf", "PDF")], max_length=10)),
                ("verdict", models.CharField(choices=[("ham", "Ham"), ("spam", "Spam"), ("safe", "Safe"), ("suspicious", "Suspicious"), ("malicious", "Malicious")], max_length=12)),
                ("confidence", models.FloatField(blank=True, null=True)),
                ("input_length", models.PositiveIntegerField(default=0)),
                ("indicators", models.JSONField(blank=True, default=list)),
                ("summary", models.CharField(blank=True, max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"app_label": "detector", "ordering": ["-created_at"]},
        ),
    ]
