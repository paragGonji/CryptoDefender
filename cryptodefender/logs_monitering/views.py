import json
import os
import socket
import subprocess
from datetime import timedelta

import psutil
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils import timezone

from .models import LogAnalytics, MinerProcess, SuspiciousConnection, SystemLog


MINING_PORTS = {
    3333, 4444, 5555, 6666, 7777, 8888, 9999,
    14444, 14433, 15555, 18888, 19999, 21111,
    22222, 33333, 44444, 55555, 66666, 77777,
    88888, 99999, 13333, 16666, 17777,
}

KNOWN_MINER_NAMES = (
    'xmrig', 'xmr-stak', 'cgminer', 'bfgminer', 'ccminer',
    'ethminer', 'claymore', 'phoenixminer', 'nbminer',
    't-rex', 'teamredminer', 'lolminer', 'gminer',
    'miner', 'minerd', 'cryptodredge'
)


def _clean_ip(ip):
    if not ip:
        return None

    ip = ip.strip()
    if '%' in ip:
        ip = ip.split('%', 1)[0]

    if ip in {'127.0.0.1', '::1', '0.0.0.0'}:
        return None

    if ip.startswith('169.254.') or ip.startswith('fe80:'):
        return None

    if ip.startswith('::'):
        return None

    return ip


def _collect_windows_event_logs():
    """Collect Windows Event Viewer logs if running on Windows."""
    if os.name != 'nt':
        return {
            'system': [],
            'security': [],
            'application': [],
        }

    logs = {
        'system': [],
        'security': [],
        'application': [],
    }

    for log_name in ('System', 'Security', 'Application'):
        command = (
            "Get-WinEvent -LogName \"{log}\" -MaxEvents 50 | "
            "Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | "
            "ConvertTo-Json -Compress -Depth 10"
        ).format(log=log_name)

        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if result.stdout.strip():
                try:
                    parsed = json.loads(result.stdout)
                    if isinstance(parsed, list):
                        logs[log_name.lower()] = parsed
                except json.JSONDecodeError:
                    logs[log_name.lower()] = [{
                        'raw_output': result.stdout.strip()[:2000],
                        'source': log_name,
                    }]
        except (OSError, subprocess.TimeoutExpired):
            logs[log_name.lower()] = []

    return logs


def _collect_system_logs():
    hostname = socket.gethostname()
    fqdn = socket.getfqdn(hostname)

    ips = set()
    try:
        _, _, host_ips = socket.gethostbyname_ex(hostname)
        for ip in host_ips:
            cleaned = _clean_ip(ip)
            if cleaned:
                ips.add(cleaned)
    except (socket.gaierror, OSError):
        pass

    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                cleaned = _clean_ip(addr.address)
                if cleaned:
                    ips.add(cleaned)

    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr:
                local_ip, local_port = conn.laddr
                remote_ip = ''
                remote_port = None
                if conn.raddr:
                    remote_ip, remote_port = conn.raddr

                entry = {
                    'status': str(conn.status),
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'pid': conn.pid,
                }
                connections.append(entry)
    except (PermissionError, OSError):
        connections = []

    net_io = psutil.net_io_counters()
    processes = []
    try:
        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = (process.info.get('name') or '').lower()
                cmdline = ' '.join(process.info.get('cmdline') or []).lower()
                if any(miner in proc_name or miner in cmdline for miner in KNOWN_MINER_NAMES):
                    processes.append({
                        'pid': process.info.get('pid'),
                        'name': process.info.get('name'),
                        'cmdline': ' '.join(process.info.get('cmdline') or []),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        processes = []

    suspicious_connections = []
    for conn in connections:
        # TIME_WAIT/CLOSE_WAIT sockets are remnants of closed connections,
        # not active mining traffic.
        if conn.get('status') in {'TIME_WAIT', 'CLOSE_WAIT', 'LAST_ACK', 'CLOSING'}:
            continue

        local_port = conn.get('local_port')
        remote_port = conn.get('remote_port')
        if local_port in MINING_PORTS or remote_port in MINING_PORTS:
            suspicious_connections.append(conn)

    windows_event_logs = _collect_windows_event_logs()
    event_messages = []
    for section in windows_event_logs.values():
        for item in section:
            message = item.get('Message') or item.get('raw_output') or ''
            event_messages.append(message)

    mining_detected = bool(processes or suspicious_connections)
    detection_reasons = []

    if processes:
        names = ', '.join(sorted({proc['name'] for proc in processes if proc.get('name')}))
        detection_reasons.append(f"Miner process detected: {names}")

    if suspicious_connections:
        ports = sorted({
            conn.get('local_port')
            for conn in suspicious_connections
            if conn.get('local_port') is not None
        } | {
            conn.get('remote_port')
            for conn in suspicious_connections
            if conn.get('remote_port') is not None
        })
        detection_reasons.append(f"Suspicious mining ports found: {ports}")

    if not mining_detected:
        mining_keywords = tuple(miner.lower() for miner in KNOWN_MINER_NAMES)
        for message in event_messages:
            if any(keyword in str(message).lower() for keyword in mining_keywords):
                mining_detected = True
                detection_reasons.append("Windows event log showed mining-related activity")
                break

    if not detection_reasons and mining_detected:
        detection_reasons.append("System scan flag marked the host as suspicious for crypto-mining activity")

    return {
        'hostname': hostname,
        'domain': fqdn,
        'ips': sorted(ips),
        'network': {
            'bytes_sent': getattr(net_io, 'bytes_sent', 0),
            'bytes_recv': getattr(net_io, 'bytes_recv', 0),
            'packets_sent': getattr(net_io, 'packets_sent', 0),
            'packets_recv': getattr(net_io, 'packets_recv', 0),
        },
        'connections': connections,
        'processes': processes,
        'suspicious_connections': suspicious_connections,
        'mining_detected': mining_detected,
        'windows_logs': windows_event_logs,
        'detection_reasons': detection_reasons,
    }


def _save_logs_to_database(user, logs_data):
    """Save collected logs to database"""
    
    # Create SystemLog record
    status = 'suspicious' if logs_data['mining_detected'] else 'safe'
    
    windows_logs = logs_data.get('windows_logs', {})
    detection_summary = []
    if logs_data['mining_detected']:
        detection_summary.append('Mining indicators detected from process and/or port analysis.')
        if logs_data.get('detection_reasons'):
            detection_summary.extend(logs_data['detection_reasons'])
    else:
        detection_summary.append('No mining indicators detected in active process or network scan.')

    if windows_logs.get('system'):
        detection_summary.append(f"System log entries captured: {len(windows_logs['system'])}")
    if windows_logs.get('security'):
        detection_summary.append(f"Security log entries captured: {len(windows_logs['security'])}")
    if windows_logs.get('application'):
        detection_summary.append(f"Application log entries captured: {len(windows_logs['application'])}")

    system_log = SystemLog.objects.create(
        user=user,
        hostname=logs_data['hostname'],
        fqdn=logs_data['domain'],
        ip_addresses=logs_data['ips'],
        bytes_sent=logs_data['network']['bytes_sent'],
        bytes_recv=logs_data['network']['bytes_recv'],
        packets_sent=logs_data['network']['packets_sent'],
        packets_recv=logs_data['network']['packets_recv'],
        system_event_log=json.dumps(windows_logs.get('system', []), ensure_ascii=False),
        security_event_log=json.dumps(windows_logs.get('security', []), ensure_ascii=False),
        application_event_log=json.dumps(windows_logs.get('application', []), ensure_ascii=False),
        process_snapshot=json.dumps(logs_data.get('processes', []), ensure_ascii=False),
        network_snapshot=json.dumps(logs_data.get('connections', []), ensure_ascii=False),
        detection_summary=' | '.join(detection_summary),
        mining_detected=logs_data['mining_detected'],
        detection_status=status,
    )
    
    # Save suspicious connections
    for conn in logs_data['suspicious_connections']:
        is_mining = (
            conn.get('local_port') in MINING_PORTS or 
            conn.get('remote_port') in MINING_PORTS
        )
        
        SuspiciousConnection.objects.create(
            log=system_log,
            status=conn.get('status', 'OTHER'),
            local_ip=conn['local_ip'],
            local_port=conn['local_port'],
            remote_ip=conn.get('remote_ip'),
            remote_port=conn.get('remote_port'),
            process_id=conn.get('pid'),
            is_mining_port=is_mining,
            severity='high' if is_mining else 'medium',
        )
    
    # Save miner processes
    for proc in logs_data['processes']:
        MinerProcess.objects.create(
            log=system_log,
            process_id=proc['pid'],
            process_name=proc['name'],
            command_line=proc['cmdline'],
            confidence_score=0.95,
        )
    
    # Update analytics
    analytics, _ = LogAnalytics.objects.get_or_create(user=user)
    analytics.total_logs_collected = SystemLog.objects.filter(user=user).count()
    
    if logs_data['mining_detected']:
        analytics.last_detection = timezone.now()
        analytics.detections_past_7_days += 1
        analytics.detections_past_30_days += 1
    else:
        analytics.last_safe_scan = timezone.now()
    
    analytics.total_mining_detections = SystemLog.objects.filter(
        user=user,
        mining_detected=True,
    ).count()
    analytics.total_suspicious_connections = SuspiciousConnection.objects.filter(log__user=user).count()
    analytics.total_miner_processes = MinerProcess.objects.filter(log__user=user).count()
    analytics.save()
    
    return system_log


def _clear_expired_logs(user):
    """Delete this user's scan records after they have been stored for 24 hours."""
    cutoff = timezone.now() - timedelta(hours=24)
    SystemLog.objects.filter(
        user=user,
        created_at__lt=cutoff,
    ).delete()

    try:
        analytics = LogAnalytics.objects.get(user=user)
    except LogAnalytics.DoesNotExist:
        return

    remaining_logs = SystemLog.objects.filter(user=user)
    analytics.total_logs_collected = remaining_logs.count()
    analytics.total_mining_detections = remaining_logs.filter(
        mining_detected=True,
    ).count()
    analytics.total_suspicious_connections = SuspiciousConnection.objects.filter(
        log__user=user,
    ).count()
    analytics.total_miner_processes = MinerProcess.objects.filter(
        log__user=user,
    ).count()

    analytics.last_detection = remaining_logs.filter(
        mining_detected=True,
    ).order_by('-created_at').values_list('created_at', flat=True).first()
    analytics.last_safe_scan = remaining_logs.filter(
        mining_detected=False,
    ).order_by('-created_at').values_list('created_at', flat=True).first()

    seven_days_ago = timezone.now() - timedelta(days=7)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    analytics.detections_past_7_days = remaining_logs.filter(
        mining_detected=True,
        created_at__gte=seven_days_ago,
    ).count()
    analytics.detections_past_30_days = remaining_logs.filter(
        mining_detected=True,
        created_at__gte=thirty_days_ago,
    ).count()
    analytics.save()


@login_required
def logs_monitoring(request):
    _clear_expired_logs(request.user)

    context = {
        'logs_data': None,
        'mining_detected': False,
        'recent_logs': None,
        'analytics': None,
        'detection_history': None,
    }

    # Get analytics
    try:
        analytics = LogAnalytics.objects.get(user=request.user)
        context['analytics'] = analytics
    except LogAnalytics.DoesNotExist:
        pass

    # Show all historical logs (mining detections + safe scans)
    all_logs = SystemLog.objects.filter(
        user=request.user
    ).order_by('-created_at')
    context['detection_history'] = all_logs
    context['recent_logs'] = all_logs

    if request.method == 'POST':
        logs_data = _collect_system_logs()
        
        # Save to database
        system_log = _save_logs_to_database(request.user, logs_data)
        
        context['logs_data'] = logs_data
        context['mining_detected'] = logs_data.get('mining_detected', False)
        context['current_log_id'] = system_log.id

        # Reload data after saving so the current scan appears immediately.
        context['analytics'] = LogAnalytics.objects.get(user=request.user)
        all_logs = SystemLog.objects.filter(
            user=request.user
        ).order_by('-created_at')
        context['detection_history'] = all_logs
        context['recent_logs'] = all_logs

    return render(request, 'core/logs_monitoring.html', context)
