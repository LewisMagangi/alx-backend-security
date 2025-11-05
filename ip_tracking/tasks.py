"""
Celery tasks for IP tracking and anomaly detection.
"""
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP


@shared_task
def detect_anomalies():
    """
    Celery task to detect anomalous IP behavior.
    Runs hourly to flag IPs that:
    1. Exceed 100 requests per hour
    2. Access sensitive paths (e.g., /admin, /login)
    
    Returns:
        dict: Summary of detected anomalies
    """
    # Calculate time window (last hour)
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Sensitive paths to monitor
    sensitive_paths = ['/admin', '/login', '/admin/', '/login/']
    
    flagged_count = 0
    
    # 1. Detect IPs with excessive requests (>100 per hour)
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        reason = f"Excessive requests: {request_count} requests in the last hour (threshold: 100)"
        
        # Check if this IP was already flagged recently (within last hour)
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            timestamp__gte=one_hour_ago,
            reason__contains="Excessive requests"
        ).exists()
        
        if not recent_flag:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=reason
            )
            flagged_count += 1
    
    # 2. Detect IPs accessing sensitive paths
    for sensitive_path in sensitive_paths:
        sensitive_accesses = (
            RequestLog.objects
            .filter(
                timestamp__gte=one_hour_ago,
                path__icontains=sensitive_path
            )
            .values('ip_address')
            .annotate(access_count=Count('id'))
        )
        
        for ip_data in sensitive_accesses:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            reason = f"Suspicious activity: {access_count} access(es) to sensitive path '{sensitive_path}' in the last hour"
            
            # Check if this IP was already flagged recently for this path
            recent_flag = SuspiciousIP.objects.filter(
                ip_address=ip_address,
                timestamp__gte=one_hour_ago,
                reason__contains=sensitive_path
            ).exists()
            
            if not recent_flag:
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=reason
                )
                flagged_count += 1
    
    # Return summary
    result = {
        'status': 'completed',
        'timestamp': timezone.now().isoformat(),
        'flagged_ips': flagged_count,
        'time_window': 'last_1_hour'
    }
    
    return result


@shared_task
def cleanup_old_logs(days=30):
    """
    Optional task to clean up old request logs.
    
    Args:
        days (int): Number of days to retain logs (default: 30)
    
    Returns:
        dict: Summary of cleanup operation
    """
    cutoff_date = timezone.now() - timedelta(days=days)
    deleted_count, _ = RequestLog.objects.filter(timestamp__lt=cutoff_date).delete()
    
    return {
        'status': 'completed',
        'deleted_logs': deleted_count,
        'cutoff_date': cutoff_date.isoformat()
    }
