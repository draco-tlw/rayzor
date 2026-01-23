import asyncio
import os
import re
from datetime import datetime, timezone

import socks
from dotenv import load_dotenv
from telethon import TelegramClient

from services import parse_date, read_channels

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

                # We start at the END date and walk backwards.
                async for message in client.iter_messages(entity, offset_date=end_date):
                    # STOP condition: If we go past the start date, stop checking this channel
                    if message.date < start_date:
                        break

                    if message.text:
                        # Find all matches in the message text
                        found = re.findall(CONFIG_PATTERN, message.text)
                        for config in found:
                            collected_configs.add(config)

            except Exception as e:
                print(f"Error scanning {channel}: {e}")

        print(f"\nScanning complete! Found {len(collected_configs)} unique configs.")

        # Save to file
        with open("configs.txt", "w", encoding="utf-8") as f:
            for config in collected_configs:
                f.write(config + "\n")

        print("Saved to configs.txt")


if __name__ == "__main__":
    print("Enter the time window (YYYY-MM-DD-HH:mm)")
    start_str = input("start time: ")
    end_str = input("end time: ")

    asyncio.run(collect(start_str, end_str))
