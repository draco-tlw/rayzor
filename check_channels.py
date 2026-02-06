import asyncio
import datetime
import random
import re

import aiohttp
from aiohttp_socks import ProxyConnector

from models.settings import load_settings
from models.v2ray_config import CONFIG_PATTERN
from services.read_channels import read_channels
from services.telegram_web_scraping import (
    get_message_datetime,
    get_message_id,
    get_message_text,
    load_channel_messages,
)

settings = load_settings("./settings.json")


async def check_channel(
    channel: str,
    cutoff_date: datetime.datetime,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
):

    async with semaphore:
        delay = random.uniform(1.5, 4.0)
        await asyncio.sleep(delay)

        last_msg_datetime = datetime.datetime.now(datetime.timezone.utc)
        next_offset_id = None

        for page_num in range(settings.MAX_PAGES):
            if last_msg_datetime < cutoff_date:
                print(
                    f"✗ {channel:<30} | Time limit reached before loading page {page_num+1}"
                )
                break

            messages = await load_channel_messages(channel, session, next_offset_id)

            if not messages:
                if page_num == 0:
                    print(
                        f"✗ {channel:<30} | Restricted (No Web Preview) or Private Channel"
                    )
                else:
                    print(
                        f"✗ {channel:<30} | End of history reached (No configs found)"
                    )
                return None

            for msg in messages:
                msg_datetime = get_message_datetime(msg)

                if not msg_datetime:
                    continue

                if msg_datetime < cutoff_date:
                    print(
                        f"✗ {channel:<30} | Time limit reached ({msg_datetime.strftime('%Y-%m-%d')})"
                    )
                    return None

                msg_text = get_message_text(msg)
                if msg_text:
                    found = re.findall(CONFIG_PATTERN, msg_text)
                    if found:
                        print(f"✓ {channel:<30}")
                        return channel

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
                print(f"✗ {channel:<30} | Error: Could not find ID for pagination")
                return None

        print(
            f"✗ {channel:<30} | Scanned {settings.MAX_PAGES} pages (No configs found)"
        )
        return None


async def check_channels(channels: list[str], days_back: int, output_file: str):
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=days_back
    )

    print(f"--- Checking {len(channels)} Channels ---")
    print(f"--- Cutoff Date: {cutoff_date.strftime('%Y-%m-%d %H:%M:%S UTC')} ---")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("")

    connector = ProxyConnector.from_url(settings.PROXY_URL)
    sem = asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for channel in channels:
            task = check_channel(channel, cutoff_date, session, sem)
            tasks.append(task)

        found_count = 0

        for future in asyncio.as_completed(tasks):
            result = await future
            if result:
                found_count += 1
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(result + "\n")

    print(f"\nScan Complete! Found {found_count} valid channels.")
    print(f"Saved to {output_file}")


def run(channels_file: str, days_back: int, output_file: str):
    channels = read_channels(channels_file)
    asyncio.run(check_channels(channels, days_back, output_file))
