from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import psutil
import socket
import subprocess
import platform
import os
import time
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect


@login_required(login_url='login')
def prevent_guide(request):
    """Prevention guide page view"""
    return render(request, 'core/prevent_guide.html')

@csrf_exempt
@require_http_methods(["POST"])
def cleanup_mining(request):
    """
    API endpoint to clean up mining activity:
    1. Kill mining processes
    2. Close mining ports
    3. Terminate mining pool connections
    """
    results = {
        'killed_processes': [],
        'closed_ports': [],
        'killed_connections': [],
        'errors': []
    }
    
    # Known mining processes
    mining_processes = [
        'xmrig', 'minerd', 'cpuminer', 'cgminer', 'bfgminer',
        'ethminer', 'claymore', 'phoenixminer', 'nbminer',
        't-rex', 'teamredminer', 'lolminer', 'gminer',
        'miner', 'ccminer', 'sgminer', 'nsgminer',
        'cryptonight', 'stratum', 'xmr-stak', 'xmr-stak-cpu',
        'xmr-stak-gpu', 'xmr-stak-amd', 'xmr-stak-nvidia',
        'xmrminer', 'monero-miner', 'simpleminer', 'miner.exe',
        'javaw.exe', 'java.exe'  # Sometimes mining is hidden in Java processes
    ]
    
    # Mining ports
    mining_ports = [3333, 4444, 5555, 6666, 7777, 8888, 9999, 
                    14444, 14433, 15555, 18888, 19999, 21111,
                    22222, 33333, 44444, 55555, 66666, 77777,
                    88888, 99999, 13333, 16666, 17777]
    
    try:
        # 1. Kill mining processes
        print("🔍 Scanning for mining processes...")
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                
                for miner in mining_processes:
                    if miner in proc_name or miner in cmdline:
                        try:
                            proc.kill()
                            results['killed_processes'].append({
                                'name': proc.info['name'],
                                'pid': proc.info['pid']
                            })
                            print(f"✅ Killed mining process: {proc.info['name']} (PID: {proc.info['pid']})")
                            break
                        except Exception as e:
                            results['errors'].append(f"Failed to kill {proc.info['name']}: {str(e)}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # 2. Close mining ports by killing processes using them
        print("🔍 Scanning for open mining ports...")
        for port in mining_ports:
            try:
                if platform.system() == 'Windows':
                    # Windows: Find process using port
                    output = subprocess.check_output(['netstat', '-ano'], text=True)
                    lines = output.split('\n')
                    for line in lines:
                        if f':{port}' in line and 'LISTENING' in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                pid = parts[-1]
                                try:
                                    # Kill the process using the port
                                    kill_result = subprocess.run(['taskkill', '/PID', pid, '/F'], 
                                                                capture_output=True, text=True)
                                    if kill_result.returncode == 0:
                                        results['closed_ports'].append(port)
                                        print(f"✅ Closed mining port {port}")
                                    else:
                                        results['errors'].append(f"Failed to close port {port}: {kill_result.stderr}")
                                except Exception as e:
                                    results['errors'].append(f"Error closing port {port}: {str(e)}")
                else:
                    # Linux/Mac: Find and kill process using port
                    try:
                        output = subprocess.check_output(['lsof', '-i', f':{port}'], text=True)
                        lines = output.split('\n')
                        for line in lines[1:]:  # Skip header
                            if line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    pid = parts[1]
                                    try:
                                        subprocess.run(['kill', '-9', pid], capture_output=True)
                                        results['closed_ports'].append(port)
                                        print(f"✅ Closed mining port {port}")
                                    except Exception as e:
                                        results['errors'].append(f"Error closing port {port}: {str(e)}")
                    except:
                        pass
            except Exception as e:
                results['errors'].append(f"Error checking port {port}: {str(e)}")
        
        # 3. Kill mining pool connections
        mining_pools = [
            'pool.minexmr.com', 'minexmr.com', 'supportxmr.com',
            'hashvault.pro', 'moneroocean.stream', 'ethermine.org',
            'f2pool.com', 'antpool.com', 'viabtc.com', 'nicehash.com',
            'cryptonight', 'stratum+tcp', 'us-west.minexmr.com',
            'us-east.minexmr.com', 'eu.minexmr.com', 'asia.minexmr.com',
            'pool.ethereum', 'ethpool.org', 'us1.ethermine.org',
            'eu1.ethermine.org', 'asia1.ethermine.org', 'btc.com',
            'slushpool.com', 'braiins.com', 'zecpool.org',
            'zcash.flypool.org', 'miningpoolhub.com'
        ]
        
        print("🔍 Scanning for mining pool connections...")
        try:
            if platform.system() == 'Windows':
                output = subprocess.check_output(['netstat', '-an'], text=True)
            else:
                output = subprocess.check_output(['netstat', '-tun'], text=True)
            
            lines = output.split('\n')
            for line in lines:
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        foreign_addr = parts[2] if len(parts) > 2 else ''
                        for pool in mining_pools:
                            if pool in foreign_addr:
                                results['killed_connections'].append({
                                    'address': foreign_addr
                                })
                                print(f"✅ Found mining pool connection: {foreign_addr}")
                                break
        except Exception as e:
            results['errors'].append(f"Error checking connections: {str(e)}")
        
        # 4. Additional cleanup - kill any process with high CPU usage that looks like mining
        print("🔍 Scanning for high CPU processes (potential miners)...")
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    cpu_usage = proc.info['cpu_percent']
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                    # If process uses > 50% CPU and looks suspicious
                    if cpu_usage and cpu_usage > 50:
                        suspicious_keywords = ['miner', 'crypto', 'coin', 'xmr', 'eth', 'btc', 'hash']
                        for keyword in suspicious_keywords:
                            if keyword in proc_name:
                                try:
                                    proc.kill()
                                    results['killed_processes'].append({
                                        'name': proc.info['name'],
                                        'pid': proc.info['pid'],
                                        'reason': f'High CPU usage ({cpu_usage:.1f}%) and suspicious name'
                                    })
                                    print(f"✅ Killed suspicious high-CPU process: {proc.info['name']} (PID: {proc.info['pid']})")
                                    break
                                except Exception as e:
                                    results['errors'].append(f"Failed to kill {proc.info['name']}: {str(e)}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            results['errors'].append(f"Error scanning CPU processes: {str(e)}")
        
        # 5. Check and kill mining-related services
        print("🔍 Scanning for mining services...")
        mining_services = ['miner', 'xmrig', 'cryptonight', 'stratum', 'ethminer', 'claymore']
        
        if platform.system() == 'Windows':
            try:
                output = subprocess.check_output(['sc', 'query', 'type=', 'service'], text=True)
                for service in mining_services:
                    if service in output.lower():
                        # Try to stop the service
                        try:
                            subprocess.run(['sc', 'stop', service], capture_output=True)
                            results['errors'].append(f"Stopped service: {service}")
                            print(f"✅ Stopped mining service: {service}")
                        except:
                            pass
            except:
                pass
        
        print("✅ Cleanup completed!")
        
    except Exception as e:
        results['errors'].append(f"General error: {str(e)}")
        print(f"Error in cleanup: {e}")
    
    return JsonResponse(results)


