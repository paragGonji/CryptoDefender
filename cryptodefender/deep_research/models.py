from django.db import models

class ScanResult(models.Model):

    STATUS_CHOICES = [
        ("SAFE", "Safe"),
        ("SUSPICIOUS", "Suspicious"),
        ("MINING", "Mining"),
    ]

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES
    )

    result = models.TextField()

    detected_processes = models.JSONField(
        default=list
    )

    risk_score = models.FloatField(
        default=0
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    prevention_unlocked = models.BooleanField(
        default=False
    )

    def __str__(self):

        return (
            f"{self.status} - "
            f"{self.created_at}"
        )