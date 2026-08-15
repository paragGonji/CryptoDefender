import os
import time
import psutil


MINER_NAMES = {
    "xmrig",
    "xmrig.exe",
    "minerd",
    "minerd.exe",
    "cpuminer",
    "cpuminer.exe",
    "cgminer",
    "cgminer.exe",
    "bfgminer",
    "bfgminer.exe",
    "t-rex",
    "t-rex.exe",
    "nbminer",
    "nbminer.exe",
    "lolminer",
    "lolminer.exe",
    "phoenixminer",
    "phoenixminer.exe",
    "ethminer",
    "ethminer.exe",
}


def is_known_miner(name):

    name = name.lower()

    return (
        name in MINER_NAMES
        or any(
            miner in name
            for miner in [
                "xmrig",
                "minerd",
                "cpuminer"
            ]
        )
    )


def collect_processes():

    processes = []

    cpu_count = psutil.cpu_count(
        logical=True
    ) or 1

    # Prime CPU counters
    for proc in psutil.process_iter():

        try:
            proc.cpu_percent(None)

        except Exception:
            pass

    time.sleep(1)

    for proc in psutil.process_iter(
        [
            "pid",
            "name",
            "exe",
            "create_time",
            "num_threads"
        ]
    ):

        try:

            name = (
                proc.info["name"]
                or ""
            ).lower()

            if not name:
                continue

            cpu = proc.cpu_percent(
                None
            )

            cpu = cpu / cpu_count

            memory = proc.memory_percent()

            threads = proc.num_threads()

            exe = proc.info["exe"] or ""

            create_time = (
                proc.info["create_time"]
                or time.time()
            )

            age = max(
                0,
                time.time() - create_time
            )

            suspicious_path = int(
                any(
                    path in exe.lower()
                    for path in [
                        "\\temp\\",
                        "\\appdata\\local\\temp\\",
                        "\\downloads\\"
                    ]
                )
            )

            known_miner = int(
                is_known_miner(name)
            )

            unknown_exe = int(
                name.endswith(".exe")
                and not os.path.exists(exe)
            )

            processes.append({

                "pid": proc.info["pid"],

                "name": name,

                "cpu": float(cpu),

                "memory": float(memory),

                "threads": float(threads),

                "process_age": float(age),

                "known_miner": known_miner,

                "suspicious_path": suspicious_path,

                "unknown_exe": unknown_exe
            })

        except Exception:
            continue

    return processes