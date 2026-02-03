import asyncio
import os
import random
import re

import socks
from dotenv import load_dotenv
from telethon import TelegramClient, errors

from services import fingerprint, parse_date, read_channels, renamer

load_dotenv()

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
SESSION_NAME = "my_collector_session"
TARGET_CHANNELS = "./channels.txt"

assert API_ID is not None
assert API_HASH is not None

API_ID = int(API_ID)

PROXY_CONF = (socks.SOCKS5, "127.0.0.1", 12334)

client = TelegramClient(SESSION_NAME, API_ID, API_HASH, proxy=PROXY_CONF)


CONFIG_PATTERN = r"(?:vmess|vless|trojan|ss|tuic|hysteria2?)://[a-zA-Z0-9\-_@.:?=&%#]+"
MAX_CONCURRENT_SCANS = 5


async def scan_channels(
    client: TelegramClient,
    channel: str,
    start_date,
    end_date,
    semaphore: asyncio.Semaphore,
):
    async with semaphore:
        delay = random.uniform(1.5, 4.5)
        await asyncio.sleep(delay)

        channel_configs = set()

        try:
            entity = await client.get_input_entity(channel)

            async for message in client.iter_messages(entity, offset_date=end_date):
                if message.date < start_date:
                    break

                if message.text:
                    found = re.findall(CONFIG_PATTERN, message.text)
                    for config in found:
                        renamed_config = renamer.rename_config(config, channel)
                        channel_configs.add(renamed_config)

            count = len(channel_configs)
            if count > 0:
                print(f"✓ {channel:<30} | Found: {count}")
            else:
                print(f"- {channel:<30} | Found: 0")

            return channel_configs

        except errors.FloodWaitError as e:
            # SAFETY: If ban is long (>2 mins), skip the channel
            print(f"! {channel:<30} | FloodWait {e.seconds}s detected.")
            if e.seconds > 120:
                print("   !! SKIPPING to avoid long ban.")
                return None

            # If short wait, we sleep and skip this turn
            await asyncio.sleep(e.seconds)
            return None

        except Exception as e:
            error_msg = str(e).split("(")[0]  # Shorten error message
            print(f"✗ {channel:<30} | Error: {error_msg}")
            return set()


async def collect(start_time_str: str, end_time_str: str):
    async with client:
        start_date, end_date = parse_date.parse_dates(start_time_str, end_time_str)
        print(f"--- Collecting Configs from {start_date} to {end_date} (UTC) ---")
        print("Scanning channels...")

        target_channels = read_channels.read_channels(TARGET_CHANNELS)

        sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

        tasks = []
        for channel in target_channels:
            task = scan_channels(client, channel, start_date, end_date, sem)
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        collected_configs = set()
        for channel_result in results:
            collected_configs.update(channel_result)

        print(f"\nScanning complete! Found {len(collected_configs)} configs.")
        return list(collected_configs)


def remove_duplicates(configs: list[str]):
    unique_configs = {}

    for config in configs:
        fgp = fingerprint.generate_fingerprint(config)

        if not fgp:
            continue  # Skip invalid configs

        # Check if this ID exists in our database
        if fgp not in unique_configs:
            unique_configs[fgp] = config

    # Calculate stats
    initial_count = len(configs)
    unique_count = len(unique_configs)
    duplicates_count = initial_count - unique_count

    print(
        f"➤ Deduplication Report: Processed {initial_count} configs. Kept {unique_count} unique. Removed {duplicates_count} duplicates."
    )

    return list(unique_configs.values())


async def main():
    print("Enter the time window (YYYY-MM-DD-HH:mm)")
    start_str = input("start time: ")
    end_str = input("end time: ")

    configs = await collect(start_str, end_str)

    clean_configs = remove_duplicates(configs)

    with open("configs.txt", "w", encoding="utf-8") as f:
        for config in clean_configs:
            f.write(config + "\n")

    print("saved to configs.txt")


if __name__ == "__main__":
    asyncio.run(main())
