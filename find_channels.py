import asyncio
import os
import random
import re

import socks
from dotenv import load_dotenv
from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat

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
MAX_CONCURRENT_SCANS = 3


IGNORE_LIST = {
    "proxy",
    "share",
    "joinchat",
    "addstickers",
    "socks",
    "bot",
    "media",  # CSS code: @media
    "import",  # Python/Java code: @import
    "admin",  # Common text: "Contact @admin" (often not a real username)
    "support",  # Common text: "Contact @support"
    "gmail",
    "yahoo",
    "hotmail",
    "protonmail",  # Email domains
}

OUTPUT_FILE = "./found-v2ray-channels.txt"


async def scan_channel(
    client: TelegramClient,
    channel: str,
    start_date,
    end_date,
    semaphore: asyncio.Semaphore,
    v2ray_channels: set,
):
    async with semaphore:
        # 1. RANDOM SLEEP (The "Anti-Ban" Shield)
        # Randomly wait between 1.5 and 4.5 seconds before every request
        delay = random.uniform(1.5, 4.5)
        await asyncio.sleep(delay)

        found_channels = set()

        try:
            entity = await client.get_input_entity(channel)

            async for message in client.iter_messages(entity, offset_date=end_date):
                if message.date < start_date:
                    break

                if message.fwd_from:
                    try:
                        fwd_entity = await client.get_entity(message.fwd_from.from_id)

                        if isinstance(fwd_entity, (Channel, Chat)):
                            if hasattr(fwd_entity, "username") and fwd_entity.username:  # type: ignore
                                username = fwd_entity.username.lower()  # type: ignore
                                if username not in v2ray_channels:
                                    found_channels.add(username)  # type: ignore

                    except Exception:
                        pass

                if message.text:
                    # Regex explains:
                    # (?:t\.me\/|@)  -> Look for "t.me/" OR "@" (non-capturing group)
                    # ([a-zA-Z0-9_]{4,}) -> Capture the actual username (letters, numbers, underscores)

                    matches = re.findall(
                        r"(?:t\.me\/|(?<![a-zA-Z0-9])@)([a-zA-Z0-9_]{4,})",
                        message.text,
                    )

                    for username in matches:
                        username = username.lower()
                        if username in IGNORE_LIST:
                            continue

                        if username not in v2ray_channels:
                            found_channels.add(username)

            count = len(found_channels)
            if count > 0:
                print(f"✓ {channel:<30} | Found: {count}")
            else:
                print(f"- {channel:<30} | Found: 0")
            return found_channels

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


async def find(start_time_str: str, end_time_str: str):
    print("\n--- Starting Crawler ---")

    v2ray_channels = set(
        [ch.lower() for ch in read_channels.read_channels(TARGET_CHANNELS)]
    )

    print(f"Loaded {len(v2ray_channels)} seed channels to scan.")

    start_date, end_date = parse_date.parse_dates(start_time_str, end_time_str)

    print(f"Time Range: {start_date} to {end_date} (UTC)")

    async with client:
        print("Client connected successfully.\n")

        sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        tasks = []

        for channel in v2ray_channels:
            task = scan_channel(
                client, channel, start_date, end_date, sem, v2ray_channels
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        found_channels = set()
        for channel_result in results:
            found_channels.update(channel_result)

        print("\n--- Scan Complete ---")
        print(f"Total Unique Channels Found: {len(found_channels)}")

        return list(found_channels)


async def is_v2ray_channel(
    client: TelegramClient,
    channel: str,
    start_date,
    end_date,
    semaphore: asyncio.Semaphore,
):
    async with semaphore:
        # 1. RANDOM SLEEP (The "Anti-Ban" Shield)
        # Randomly wait between 2.0 and 4.5 seconds before every request
        delay = random.uniform(2.0, 4.5)
        await asyncio.sleep(delay)

        try:
            entity = await client.get_input_entity(channel)

            async for message in client.iter_messages(entity, offset_date=end_date):
                if message.date < start_date:
                    print(f"✗ {channel:<30} | No configs in time range")
                    return None

                if message.text:
                    found = re.findall(CONFIG_PATTERN, message.text)
                    if len(found) > 0:
                        print(f"✓ {channel:<30}")
                        return channel

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
            return None

    print(f"✗ {channel:<30}")
    return None


async def check_channels(start_time_str: str, end_time_str: str, channels: list[str]):
    async with client:
        start_date, end_date = parse_date.parse_dates(start_time_str, end_time_str)
        print(
            f"--- Checking {len(channels)} channels from {start_date} to {end_date} ---"
        )

        # Clear/Create the file first
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("")

        sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        tasks = []

        for channel in channels:
            task = is_v2ray_channel(client, channel, start_date, end_date, sem)
            tasks.append(task)

        # 4. PROCESS AS THEY FINISH (Real-Time Saving)
        found_count = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            if result:
                found_count += 1
                # Write to file immediately
                with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                    f.write(result + "\n")

        print(f"\nScan Complete! Found {found_count} v2ray channels.")

        print(f"Saved to {OUTPUT_FILE}")


async def main():
    # ch_list = await find("2026-01-24-00:00", "2026-02-01-00:00")
    #
    # with open("found-channels.txt", "w", encoding="utf-8") as f:
    #     for channel in ch_list:
    #         f.write(channel + "\n")
    #
    # print("saved to found-channels.txt")

    with open("found-channels.txt", "r", encoding="utf-8") as f:
        found_channels = f.read().split("\n")[:-1]

        await check_channels("2026-01-24-00:00", "2026-02-01-00:00", found_channels)


if __name__ == "__main__":
    asyncio.run(main())
