from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("detector", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scanrecord",
            name="verdict",
            field=models.CharField(
                choices=[
                    ("ham", "Ham"),
                    ("spam", "Spam"),
                    ("safe", "Safe"),
                    ("suspicious", "Suspicious"),
                    ("malicious", "Malicious"),
                    ("unknown", "Unknown"),
                ],
                max_length=12,
            ),
        ),
    ]
