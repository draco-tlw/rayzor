import asyncio
import datetime
import random
import re

import aiohttp
from aiohttp_socks import ProxyConnector

from services.read_channels import read_channels
from services.telegram_web_scraping import (
    get_message_datetime,
    get_message_id,
    get_message_links,
    load_channel_messages,
)

PROXY_URL = "socks5://127.0.0.1:12334"
MAX_CONCURRENT_SCANS = 20
MAX_PAGES = 100
OUTPUT_FILE = "extracted-channels.txt"

SOURCE_CHANNELS_FILE = "./channels.txt"
DAYS_BACK = 7


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


async def extract_channel_links(
    channel: str,
    cutoff_date: datetime.datetime,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    v2ray_channels: set[str],
):
    async with semaphore:
        delay = random.uniform(1.5, 4.0)
        await asyncio.sleep(delay)

        channel_links: set[str] = set()

        last_msg_datetime = datetime.datetime.now(datetime.timezone.utc)
        next_offset_id = None

        for page_num in range(MAX_PAGES):
            if last_msg_datetime < cutoff_date:
                break

            messages = await load_channel_messages(channel, session, next_offset_id)

            if not messages:
                if page_num == 0:
                    print(
                        f"✗ {channel:<30} | Restricted (No Web Preview) or Private Channel"
                    )
                    return channel_links
                else:
                    break

            for msg in messages:
                msg_datetime = get_message_datetime(msg)

                if not msg_datetime:
                    continue

                if msg_datetime < cutoff_date:
                    if len(channel_links) > 0:
                        print(f"✓ {channel:<30} | Found: {len(channel_links)}")
                    else:
                        print(f"- {channel:<30} | Found: 0")
                    return channel_links

                msg_links = get_message_links(msg)
                if not msg_links:
                    continue

                for msg_link in msg_links:
                    msg_link = (
                        msg_link.replace("https://", "")
                        .replace("http://", "")
                        .replace("www.", "")
                    )

                    match = re.match(
                        r"(?:t\.me|telegram\.me)\/(?:s\/)?([a-zA-Z0-9_]{4,})(?:$|[\/\?\#])",
                        msg_link,
                    )

                    if match:
                        username = match.group(1).lower()

                        if username in IGNORE_LIST:
                            continue

                        if username.endswith("bot"):
                            continue

                        if username in v2ray_channels:
                            continue

                        channel_links.add(username)

            last_msg_datetime = None
            next_offset_id = None

            for msg in reversed(messages):
                p_id = get_message_id(msg)
                p_date = get_message_datetime(msg)

                if p_id and p_date:
                    next_offset_id = p_id
                    last_msg_datetime = p_date
                    break

            delay = random.uniform(0.5, 1.5)
            await asyncio.sleep(delay)

            if not last_msg_datetime or not next_offset_id:
                break

        count = len(channel_links)
        if count > 0:
            print(f"✓ {channel:<30} | Found: {count}")
        else:
            print(f"- {channel:<30} | Found: 0")

        return channel_links


async def extract_all_channels_links(channels: set[str], days_back: int):
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=days_back
    )

    print(f"--- Extracting channel links from {len(channels)} Channels ---")
    print(f"--- Cutoff Date: {cutoff_date.strftime('%Y-%m-%d %H:%M:%S UTC')} ---")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("")

    connector = ProxyConnector.from_url(PROXY_URL)
    sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for channel in channels:
            task = extract_channel_links(channel, cutoff_date, session, sem, channels)
            tasks.append(task)

        total_configs_found = 0
        channels_with_configs = 0

        for future in asyncio.as_completed(tasks):
            result = await future

            if result:
                count = len(result)
                total_configs_found += count
                channels_with_configs += 1

                with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                    for config in result:
                        f.write(config + "\n")

    print("\nExtraction Complete!")
    print(f"   • Channels with channel links: {channels_with_configs}")
    print(f"   • Total channel links saved:   {total_configs_found}")
    print(f"   • Saved to:                    {OUTPUT_FILE}")


async def main():
    channels = set(read_channels(SOURCE_CHANNELS_FILE))
    await extract_all_channels_links(channels, days_back=DAYS_BACK)


if __name__ == "__main__":
    asyncio.run(main())
