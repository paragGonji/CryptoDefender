from django.db import models
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.utils import timezone


class SystemLog(models.Model):
    """Store system logs with network and process information"""
    
    STATUS_CHOICES = [
        ('safe', 'Safe - No Mining Detected'),
        ('suspicious', 'Suspicious - Mining Activity Detected'),
        ('pending_review', 'Pending Review'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='system_logs')
    hostname = models.CharField(max_length=255)
    fqdn = models.CharField(max_length=255, verbose_name='FQDN (Domain)')
    ip_addresses = ArrayField(models.CharField(max_length=45), blank=True, default=list)
    
    # Network info
    bytes_sent = models.BigIntegerField(default=0)
    bytes_recv = models.BigIntegerField(default=0)
    packets_sent = models.BigIntegerField(default=0)
    packets_recv = models.BigIntegerField(default=0)
    
    # Raw log capture from Windows / system
    system_event_log = models.TextField(blank=True, default='')
    security_event_log = models.TextField(blank=True, default='')
    application_event_log = models.TextField(blank=True, default='')
    process_snapshot = models.TextField(blank=True, default='')
    network_snapshot = models.TextField(blank=True, default='')
    detection_summary = models.TextField(blank=True, default='')
    
    # Mining detection
    mining_detected = models.BooleanField(default=False)
    detection_status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='safe'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'System Logs'
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['mining_detected']),
            models.Index(fields=['user', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.hostname} - {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"


class SuspiciousConnection(models.Model):
    """Store suspicious network connections detected during log collection"""
    
    CONNECTION_STATUS = [
        ('ESTABLISHED', 'Established'),
        ('LISTEN', 'Listening'),
        ('TIME_WAIT', 'Time Wait'),
        ('CLOSE_WAIT', 'Close Wait'),
        ('SYN_SENT', 'SYN Sent'),
        ('OTHER', 'Other'),
    ]
    
    log = models.ForeignKey(SystemLog, on_delete=models.CASCADE, related_name='suspicious_connections')
    status = models.CharField(max_length=20, choices=CONNECTION_STATUS, default='OTHER')
    local_ip = models.GenericIPAddressField()
    local_port = models.IntegerField()
    remote_ip = models.GenericIPAddressField(null=True, blank=True)
    remote_port = models.IntegerField(null=True, blank=True)
    process_id = models.IntegerField(null=True, blank=True)
    
    is_mining_port = models.BooleanField(default=False)
    severity = models.CharField(
        max_length=10,
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')],
        default='medium'
    )
    
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-detected_at']
        verbose_name_plural = 'Suspicious Connections'
        indexes = [
            models.Index(fields=['log', '-detected_at']),
            models.Index(fields=['is_mining_port']),
        ]
    
    def __str__(self):
        return f"{self.local_ip}:{self.local_port} -> {self.remote_ip}:{self.remote_port}"


class MinerProcess(models.Model):
    """Store detected miner processes"""
    
    log = models.ForeignKey(SystemLog, on_delete=models.CASCADE, related_name='miner_processes')
    process_id = models.IntegerField()
    process_name = models.CharField(max_length=255)
    command_line = models.TextField()
    
    confidence_score = models.FloatField(
        default=0.9,
        help_text='Confidence level (0-1) that this is a miner process'
    )
    
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['log', '-detected_at']),
            models.Index(fields=['process_name']),
        ]
    
    def __str__(self):
        return f"{self.process_name} (PID: {self.process_id})"


class LogAnalytics(models.Model):
    """Store analytics and summaries for quick dashboard access"""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='log_analytics')
    
    total_logs_collected = models.IntegerField(default=0)
    total_mining_detections = models.IntegerField(default=0)
    total_suspicious_connections = models.IntegerField(default=0)
    total_miner_processes = models.IntegerField(default=0)
    
    last_detection = models.DateTimeField(null=True, blank=True)
    last_safe_scan = models.DateTimeField(null=True, blank=True)
    
    # Statistics for past 7 days
    detections_past_7_days = models.IntegerField(default=0)
    detections_past_30_days = models.IntegerField(default=0)
    
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Analytics for {self.user.username}"
