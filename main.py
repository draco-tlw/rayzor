import asyncio
import os
import re

import socks
from dotenv import load_dotenv
from telethon import TelegramClient

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


async def collect(start_time_str: str, end_time_str: str):
    async with client:
        start_date, end_date = parse_date.parse_dates(start_time_str, end_time_str)
        print(f"--- Collecting Configs from {start_date} to {end_date} (UTC) ---")

        collected_configs = set()

        target_channels = read_channels.read_channels(TARGET_CHANNELS)

        for channel in target_channels:
            print(f"Scanning: {channel}...")

            try:
                # Get the channel entity
                entity = await client.get_input_entity(channel)

                channel_configs = set()

                # We start at the END date and walk backwards.
                async for message in client.iter_messages(entity, offset_date=end_date):
                    # STOP condition: If we go past the start date, stop checking this channel
                    if message.date < start_date:
                        break

                    if message.text:
                        # Find all matches in the message text
                        found = re.findall(CONFIG_PATTERN, message.text)
                        for config in found:
                            renamed_config = renamer.rename_config(config, channel)
                            channel_configs.add(renamed_config)

                total_found = len(channel_configs)
                new_configs = channel_configs - collected_configs
                count_new = len(new_configs)
                count_duplicates = total_found - count_new

                collected_configs.update(new_configs)

                if total_found > 0:
                    print(
                        f"   └── Found: {total_found} | New: {count_new} | Duplicates: {count_duplicates}"
                    )
                else:
                    print("   └── No configs found.")

            except Exception as e:
                print(f"Error scanning {channel}: {e}")

        print(f"\nScanning complete! Found {len(collected_configs)} unique configs.")

        # Save to file
        # with open("configs.txt", "w", encoding="utf-8") as f:
        #     for config in collected_configs:
        #         f.write(config + "\n")
        #
        # print("Saved to configs.txt")

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

    with open("clean-configs.txt", "w", encoding="utf-8") as f:
        for config in clean_configs:
            f.write(config + "\n")

    print("saved to clean-configs.txt")


if __name__ == "__main__":
    asyncio.run(main())
