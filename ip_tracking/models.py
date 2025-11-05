from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.ip_address} – {self.path} at {self.timestamp} ( {self.city}, {self.country} )"
    
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __str__(self):
        return self.ip_address


class SuspiciousIP(models.Model):
    """
    Model to store suspicious IP addresses flagged by anomaly detection.
    """
    ip_address = models.GenericIPAddressField()
    reason = models.TextField(help_text="Reason why this IP is flagged as suspicious")
    timestamp = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False, help_text="Whether this suspicious activity has been reviewed")

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['is_resolved']),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]} at {self.timestamp}"
    
