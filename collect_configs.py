import asyncio
import datetime
import random
import re

import aiohttp
from aiohttp_socks import ProxyConnector

from models.settings import load_settings
from models.v2ray_config import CONFIG_PATTERN
from services import renamer
from services.read_channels import read_channels
from services.telegram_web_scraping import (
    get_message_datetime,
    get_message_id,
    get_message_text,
    load_channel_messages,
)

settings = load_settings("./settings.json")


async def collect_channel_configs(
    channel: str,
    cutoff_date: datetime.datetime,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
):
    async with semaphore:
        delay = random.uniform(1.5, 4.0)
        await asyncio.sleep(delay)

        channel_configs: set[str] = set()

        last_msg_datetime = datetime.datetime.now(datetime.timezone.utc)
        next_offset_id = None

        for page_num in range(settings.MAX_PAGES):
            if last_msg_datetime < cutoff_date:
                break

            messages = await load_channel_messages(channel, session, next_offset_id)

            if not messages:
                if page_num == 0:
                    print(
                        f"✗ {channel:<30} | Restricted (No Web Preview) or Private Channel"
                    )
                    return channel_configs
                else:
                    break

            for msg in messages:
                msg_datetime = get_message_datetime(msg)

                if not msg_datetime:
                    continue

                if msg_datetime < cutoff_date:
                    if len(channel_configs) > 0:
                        print(f"✓ {channel:<30} | Found: {len(channel_configs)}")
                    else:
                        print(f"- {channel:<30} | Found: 0")
                    return channel_configs

                msg_text = get_message_text(msg)
                if msg_text:
                    found = re.findall(CONFIG_PATTERN, msg_text)
                    for config in found:
                        config = config.rstrip(".:,;!?")

                        renamed_config = renamer.rename_config(config, channel)
                        channel_configs.add(str(renamed_config))

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

        count = len(channel_configs)
        if count > 0:
            print(f"✓ {channel:<30} | Found: {count}")
        else:
            print(f"- {channel:<30} | Found: 0")

        return channel_configs


async def collect_all_channels_configs(
    channels: list[str], hours_back: int, output_file: str
):
    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        hours=hours_back
    )

    print(f"--- Collecting Configs from {len(channels)} Channels ---")
    print(f"--- Cutoff Date: {cutoff_date.strftime('%Y-%m-%d %H:%M:%S UTC')} ---")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("")

    connector = ProxyConnector.from_url(settings.PROXY_URL)
    sem = asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for channel in channels:
            task = collect_channel_configs(channel, cutoff_date, session, sem)
            tasks.append(task)

        total_configs_found = 0
        channels_with_configs = 0

        for future in asyncio.as_completed(tasks):
            result = await future

            if result:
                count = len(result)
                total_configs_found += count
                channels_with_configs += 1

                with open(output_file, "a", encoding="utf-8") as f:
                    for config in result:
                        f.write(config + "\n")

    print("\nCollection Complete!")
    print(f"   • Channels with configs: {channels_with_configs}")
    print(f"   • Total configs saved:   {total_configs_found}")
    print(f"   • Saved to:              {output_file}")


def run(channels_file: str, hours_back: int, output_file: str):
    channels = read_channels(channels_file)
    asyncio.run(collect_all_channels_configs(channels, hours_back, output_file))
