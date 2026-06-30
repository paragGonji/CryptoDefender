import psutil
import requests
import time

SERVER_URL = "http://127.0.0.1:8000/api/scan-result/"

def detect():
    suspicious = ["xmrig", "minerd", "cpuminer"]
    result = []

    # Give CPU time to calculate properly
    for proc in psutil.process_iter(['name']):
        try:
            proc.cpu_percent(interval=None)
        except:
            pass

    time.sleep(1)

    for proc in psutil.process_iter(['name', 'cpu_percent']):
        try:
            name = (proc.info['name'] or "").lower()
            cpu = proc.info['cpu_percent']

            if any(m in name for m in suspicious):
                result.append(f"⚠️ Miner Detected: {name}")

            elif cpu > 50:
                result.append(f"⚠️ High CPU: {name} ({cpu}%)")

        except:
            pass

    if not result:
        result.append("✅ SAFE - No mining detected")

    return result


def send_data():
    data = detect()

    try:
        requests.post(SERVER_URL, json={"result": data})
    except:
        pass


if __name__ == "__main__":
    send_data()