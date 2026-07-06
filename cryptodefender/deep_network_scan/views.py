from django.shortcuts import render
from django.http import JsonResponse
import psutil
import socket
import subprocess
import platform
import re
from datetime import datetime

def network_scan_view(request):
    """Main view for Deep Network Scan"""
    scan_results = None
    error_message = None
    
    print(f"=== Request Method: {request.method} ===")
    
    if request.method == 'POST':
        print("=== PROCESSING POST REQUEST ===")
        try:
            print("Starting scan...")
            scan_results = perform_network_scan()
            print(f"Scan completed. Results keys: {scan_results.keys()}")
        except Exception as e:
            error_message = f"Error during scan: {str(e)}"
            print(f"ERROR: {e}")
    else:
        print("=== GET REQUEST ===")
    
    context = {
        'scan_results': scan_results,
        'error_message': error_message,
    }
    return render(request, 'deep_network_scan/scan.html', context)

def perform_network_scan():
    """Perform comprehensive network scanning"""
    results = {}
    
    results['interfaces'] = get_network_interfaces()
    results['connections'] = get_active_connections()
    results['network_devices'] = scan_local_network()
    results['network_stats'] = get_network_statistics()
    results['open_ports'] = scan_common_ports()
    results['dns_info'] = get_dns_info()
    results['security_issues'] = check_security_issues()
    results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return results

def get_network_interfaces():
    """Get all network interfaces and their IP addresses"""
    interfaces = {}
    try:
        hostname = socket.gethostname()
        ip_addresses = []
        try:
            ip_list = socket.gethostbyname_ex(hostname)
            ip_addresses = ip_list[2]
        except:
            ip_addresses = [socket.gethostbyname(hostname)]
        
        if platform.system() == 'Windows':
            try:
                output = subprocess.check_output(['ipconfig'], text=True)
                current_interface = None
                for line in output.split('\n'):
                    if 'adapter' in line and ':' in line:
                        current_interface = line.split(':')[1].strip()
                        if current_interface not in interfaces:
                            interfaces[current_interface] = {'ipv4': [], 'ipv6': [], 'mac': 'N/A'}
                    elif 'IPv4 Address' in line and current_interface:
                        ip = line.split(':')[1].strip()
                        if ip not in interfaces[current_interface]['ipv4']:
                            interfaces[current_interface]['ipv4'].append(ip)
                    elif 'Physical Address' in line and current_interface:
                        mac = line.split(':')[1].strip()
                        interfaces[current_interface]['mac'] = mac
            except:
                interfaces['Default'] = {
                    'ipv4': ip_addresses,
                    'ipv6': [],
                    'mac': 'N/A'
                }
        else:
            interfaces['Default'] = {
                'ipv4': ip_addresses,
                'ipv6': [],
                'mac': 'N/A'
            }
    except:
        interfaces['Default'] = {
            'ipv4': ['127.0.0.1'],
            'ipv6': [],
            'mac': 'N/A'
        }
    
    return interfaces

def get_active_connections():
    """Get active network connections"""
    connections = []
    try:
        if platform.system() == 'Windows':
            output = subprocess.check_output(['netstat', '-an'], text=True)
        else:
            output = subprocess.check_output(['netstat', '-tun'], text=True)
        
        lines = output.split('\n')
        count = 0
        for line in lines:
            if count >= 20:
                break
            if 'ESTABLISHED' in line or 'LISTENING' in line or 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    connections.append({
                        'protocol': parts[0],
                        'local_address': parts[1] if len(parts) > 1 else 'N/A',
                        'foreign_address': parts[2] if len(parts) > 2 else 'N/A',
                        'state': parts[3] if len(parts) > 3 else 'N/A'
                    })
                    count += 1
    except Exception:
        pass
    
    return connections

def scan_local_network():
    """Scan local network for connected devices"""
    devices = []
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_parts = local_ip.split('.')
        
        if len(ip_parts) == 4:
            base_ip = '.'.join(ip_parts[:3]) + '.'
            for i in range(1, 6):
                ip = base_ip + str(i)
                try:
                    if platform.system() == 'Windows':
                        response = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                                capture_output=True, text=True, timeout=1)
                    else:
                        response = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                                capture_output=True, text=True, timeout=1)
                    
                    if response.returncode == 0:
                        try:
                            hostname_resolved = socket.gethostbyaddr(ip)[0]
                        except:
                            hostname_resolved = 'Unknown'
                        
                        devices.append({
                            'ip': ip,
                            'hostname': hostname_resolved,
                            'status': 'Active'
                        })
                except:
                    continue
    except Exception:
        pass
    
    return devices

def get_network_statistics():
    """Get network I/O statistics"""
    stats = {}
    try:
        net_io = psutil.net_io_counters()
        stats = {
            'bytes_sent': format_bytes(net_io.bytes_sent),
            'bytes_recv': format_bytes(net_io.bytes_recv),
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout,
        }
    except Exception:
        stats = {
            'bytes_sent': '0 B',
            'bytes_recv': '0 B',
            'packets_sent': 0,
            'packets_recv': 0,
            'errin': 0,
            'errout': 0,
            'dropin': 0,
            'dropout': 0,
        }
    
    return stats

def scan_common_ports():
    """Scan common ports to check if they're open"""
    common_ports = {
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-Alt'
    }
    
    open_ports = []
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append({
                    'port': port,
                    'service': service,
                    'status': 'OPEN'
                })
        except:
            pass
        finally:
            sock.close()
    
    return open_ports

def get_dns_info():
    """Get DNS information"""
    dns_info = {}
    try:
        hostname = socket.gethostname()
        dns_info['hostname'] = hostname
        dns_info['ip_address'] = socket.gethostbyname(hostname)
        
        if platform.system() == 'Windows':
            try:
                output = subprocess.check_output(['ipconfig', '/all'], text=True)
                dns_servers = re.findall(r'DNS Servers[ .]+: ([0-9.]+)', output)
                dns_info['dns_servers'] = dns_servers[:3] if dns_servers else ['Unable to retrieve']
            except:
                dns_info['dns_servers'] = ['Unable to retrieve']
        else:
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    dns_servers = re.findall(r'nameserver\s+([0-9.]+)', f.read())
                    dns_info['dns_servers'] = dns_servers[:3] if dns_servers else ['Unable to retrieve']
            except:
                dns_info['dns_servers'] = ['Unable to retrieve DNS servers']
    except Exception:
        dns_info['hostname'] = 'Unknown'
        dns_info['ip_address'] = 'Unknown'
        dns_info['dns_servers'] = ['Unable to retrieve DNS servers']
    
    return dns_info

def check_security_issues():
    """Check for common security issues"""
    issues = []
    
    try:
        open_ports = scan_common_ports()
        suspicious_ports = [p for p in open_ports if p['port'] in [135, 139, 445, 3389, 5900]]
        
        if suspicious_ports:
            for port_info in suspicious_ports:
                issues.append({
                    'severity': 'HIGH',
                    'issue': f'Suspicious port {port_info["port"]} ({port_info["service"]}) is open',
                    'recommendation': 'Close unnecessary ports or implement proper firewall rules'
                })
        
        try:
            net_io = psutil.net_io_counters()
            if net_io.errin > 100 or net_io.errout > 100:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'High number of network errors detected',
                    'recommendation': 'Check network cables, switches, and network drivers'
                })
            
            if net_io.dropin > 100 or net_io.dropout > 100:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'High number of dropped packets detected',
                    'recommendation': 'Check network congestion or potential network attacks'
                })
        except:
            pass
    except Exception:
        pass
    
    return issues

def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def api_scan(request):
    """API endpoint for scanning"""
    try:
        results = perform_network_scan()
        return JsonResponse({
            'success': True,
            'data': results
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })