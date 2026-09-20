import os
import psutil
import requests
import time

SERVER_URL = os.getenv(
    "CRYPTODEFENDER_SERVER_URL",
    "http://127.0.0.1:8000/api/scan/"
)

def detect():
    result = []

    fields = [
        "pid",
        "name",
        "exe",
        "create_time",
        "num_threads"
    ]

    cpu_count = psutil.cpu_count(logical=True) or 1

    # Give CPU time to calculate properly
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except:
            pass

    time.sleep(1)

    for proc in psutil.process_iter(fields):
        try:
            name = (proc.info['name'] or "").lower()
            if not name:
                continue

            create_time = proc.info.get('create_time') or time.time()

            result.append({
                "pid": proc.info['pid'],
                "name": name,
                "exe": proc.info.get('exe') or "",
                "cpu": float(proc.cpu_percent(None) / cpu_count),
                "memory": float(proc.memory_percent()),
                "threads": float(proc.info.get('num_threads') or 1),
                "process_age": max(0, time.time() - create_time),
                "known_miner": 0,
                "suspicious_path": 0,
                "unknown_exe": 0
            })

        except:
            pass

    return result


def send_data():
    data = detect()

    try:
        requests.post(
            SERVER_URL,
            json={"processes": data},
            timeout=10
        )
    except:
        pass


if __name__ == "__main__":
    send_data()