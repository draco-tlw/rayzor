import csv
import json
import os
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from tqdm import tqdm

from models.v2ray_config import V2rayConfig
from services import parse_config_link
from services.read_configs import read_configs

CORE_PATH = Path("./v2ray_cores/sing-box-1.12.19-linux-amd64/sing-box")
CONFIGS_FILE = "unique-configs.txt"
MASS_CONFIG_FILE = "mass_config.json"
TEST_OUTPUT_FILE = "active_configs_latency_test_results.csv"
ACTIVE_CONFIGS_FILE = "active_configs.txt"

BASE_PORT = 11000  # Starting port for local listeners
TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
TIMEOUT = 5
BATCH_SIZE = 500  # Keep this under 500 to avoid 'Too many open files'
MAX_WORKERS = 250  # Threads for HTTP requests
MAX_RETRIES = 3


def wait_for_port(port, timeout=5):
    """Checks if a port is open. Returns True as soon as it opens."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return False


def generate_mass_config(v2ray_configs: list[V2rayConfig]):
    """Generates a single JSON config with N inbounds and N outbounds."""
    inbounds = []
    outbounds = []
    rules = []

    outbounds.append({"type": "direct", "tag": "direct"})

    for i, conf in enumerate(v2ray_configs):
        port = BASE_PORT + i
        tag = f"proxy-{i}"

        inbounds.append(
            {
                "type": "socks",
                "tag": f"in-{i}",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )

        conf.parsed_data["tag"] = tag
        outbounds.append(conf.parsed_data)
        rules.append({"inbound": f"in-{i}", "outbound": tag})

    return {
        "log": {"level": "panic"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "auto_detect_interface": True},
    }


def ping_proxy(args):
    """Performs the HTTP check."""
    index, link_original = args
    port = BASE_PORT + index

    proxies = {
        "http": f"socks5://127.0.0.1:{port}",
        "https": f"socks5://127.0.0.1:{port}",
    }

    try:
        start = time.time()
        with requests.Session() as s:
            resp = s.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)

        latency = (time.time() - start) * 1000

        if resp.status_code in [200, 204]:
            return {
                "config": link_original,
                "latency": round(latency),
                "status": "success",
                "msg": "OK",
            }
        else:
            return {
                "config": link_original,
                "latency": -1,
                "status": "fail",
                "msg": f"Status {resp.status_code}",
            }

    except requests.exceptions.Timeout:
        return {
            "config": link_original,
            "latency": -1,
            "status": "fail",
            "msg": "Timeout",
        }
    except Exception as e:
        return {
            "config": link_original,
            "latency": -1,
            "status": "fail",
            "msg": str(e)[:30],
        }


def filter_supported_v2ray_configs(configs: list[V2rayConfig]):
    valid_configs: list[V2rayConfig] = []

    for config in configs:
        try:
            p = config.parsed_data

            if p["type"] == "shadowsocks":
                method = p.get("method", "").lower()
                if method not in parse_config_link.VALID_SS_METHODS:
                    continue
                if p.get("password") == "":
                    continue

            if "transport" in p:
                t_type = p["transport"].get("type", "")
                if t_type in ["xhttp", "tcp", "raw", "none", ""]:
                    del p["transport"]
                if t_type == "xhttp":
                    continue

            if p.get("server") and p.get("server_port"):
                valid_configs.append(V2rayConfig(config.link, p))

        except Exception:
            pass

    return valid_configs


def run_batch(batch_v2ray_configs: list[V2rayConfig], batch_id):
    """Orchestrates the test for one batch of links."""

    # 2. Generate Config
    mass_conf = generate_mass_config(batch_v2ray_configs)
    with open(MASS_CONFIG_FILE, "w") as f:
        json.dump(mass_conf, f, indent=1)

    # 3. Run Core
    process = subprocess.Popen(
        [str(CORE_PATH), "run", "-c", MASS_CONFIG_FILE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    batch_results = []
    try:
        # Fast Start: Wait for the FIRST port in the batch to open
        first_port = BASE_PORT
        if not wait_for_port(first_port, timeout=5):
            # Check if process died
            if process.poll() is not None:
                _, stderr_data = process.communicate()
                print(f"\n [!] Batch {batch_id} FAILED!")
                print(f"     Core Error: {stderr_data.strip()[:300]}...")

                # OPTIONAL: Save the bad config for inspection
                shutil.copy(MASS_CONFIG_FILE, f"failed_batch_{batch_id}.json")
                print(f"     Saved bad config to failed_batch_{batch_id}.json")
            else:
                print(f" [!] Batch {batch_id}: Core start timeout (No error log).")

            # Fail all links in this batch
            return [
                {
                    "config": conf.link,
                    "latency": -1,
                    "status": "fail",
                    "msg": "Batch Failed",
                }
                for conf in batch_v2ray_configs
            ]

        tasks = [(i, conf.link) for i, conf in enumerate(batch_v2ray_configs)]

        # 4. Test Links
        desc = f"Batch {batch_id}"
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(ping_proxy, t) for t in tasks]
            for f in tqdm(
                as_completed(futures), total=len(tasks), desc=desc, leave=False
            ):
                batch_results.append(f.result())

    finally:
        process.terminate()
        process.wait()
        # Only remove config if it worked (keep failed ones for debugging)
        if os.path.exists(MASS_CONFIG_FILE) and process.poll() == 0:
            try:
                os.remove(MASS_CONFIG_FILE)
            except OSError:
                pass

    return batch_results


def test_latency(v2ray_configs: list[V2rayConfig]):
    total_configs = len(v2ray_configs)

    num_batches = (total_configs + BATCH_SIZE - 1) // BATCH_SIZE
    total_active_count = 0

    inactive_v2ray_configs = v2ray_configs.copy()

    for i in range(0, total_configs, BATCH_SIZE):
        batch_num = (i // BATCH_SIZE) + 1

        end_idx = min(i + BATCH_SIZE, total_configs)
        print(
            f"\nProcessing Batch {batch_num}/{num_batches} (Links {i} to {end_idx})..."
        )

        current_batch_v2ray_configs = v2ray_configs[i : i + BATCH_SIZE]
        results = run_batch(current_batch_v2ray_configs, batch_num)

        active_in_batch = [r for r in results if r["status"] == "success"]
        total_active_count += len(active_in_batch)

        with open(TEST_OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["config", "latency", "status", "msg"]
            )
            writer.writerows(active_in_batch)

        if active_in_batch:
            with open(ACTIVE_CONFIGS_FILE, "a", encoding="utf-8") as f:
                for res in active_in_batch:
                    f.write(res["config"].strip() + "\n")

        print(f"   Batch {batch_num} Done: {len(active_in_batch)} active.")

        active_links_set = {r["config"] for r in active_in_batch}

        inactive_v2ray_configs = [
            vc for vc in inactive_v2ray_configs if vc.link not in active_links_set
        ]

    return inactive_v2ray_configs


def main():
    if not CORE_PATH.exists():
        print(f"Core not found at: {CORE_PATH}")
        return

    print("Reading configs...")
    all_config_links = read_configs(CONFIGS_FILE)
    total_configs = len(all_config_links)

    print(f"Found {total_configs} configs. Filtering supported configs...")

    v2ray_configs = []
    for link in all_config_links:
        try:
            parsed_data = parse_config_link.parse_link(link)

            v2ray_configs.append(V2rayConfig(link, parsed_data))

        except Exception:
            continue
    supported_v2ray_configs = filter_supported_v2ray_configs(v2ray_configs)

    print(
        f"Found {len(supported_v2ray_configs)} supported configs. Splitting into batches of {BATCH_SIZE}..."
    )

    # Initialize Files (Clear old results)
    with open(TEST_OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["config", "latency", "status", "msg"])
        writer.writeheader()

    with open(ACTIVE_CONFIGS_FILE, "w", encoding="utf-8") as f:
        f.write("")  # Clear file

    for attempt in range(MAX_RETRIES):
        if not supported_v2ray_configs:
            print("\nAll configs verified active! Stopping retries early.")
            break

        # 2. Print Status Message
        print(f"\n--- ROUND {attempt + 1} / {MAX_RETRIES} ---")
        print(f"   Queued for testing: {len(supported_v2ray_configs)} configs")

        supported_v2ray_configs = test_latency(supported_v2ray_configs)

    print("\nFinalizing and sorting results...")

    final_rows = []
    with open(TEST_OUTPUT_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        final_rows = list(reader)

    for r in final_rows:
        r["latency"] = int(float(r["latency"]))

    final_rows.sort(key=lambda x: x["latency"])

    with open(TEST_OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["config", "latency", "status", "msg"])
        writer.writeheader()
        writer.writerows(final_rows)

    print("\n" + "=" * 40)
    print("Testing Complete.")
    print(f"   Total Tested: {total_configs}")
    print(f"   Total Active: {len(final_rows)}")
    print(f"   Saved to: {TEST_OUTPUT_FILE}")
    print(f"             {ACTIVE_CONFIGS_FILE}")
    print("=" * 40)


if __name__ == "__main__":
    main()
