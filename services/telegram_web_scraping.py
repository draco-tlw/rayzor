import asyncio

import aiohttp
from aiohttp_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError
from bs4 import BeautifulSoup, Tag

from services.parse_iso_date import parse_iso_date

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
PROXY_URL = "socks5://127.0.0.1:12334"
MAX_RETRIES = 5
BASE_DELAY = 5


def get_message_id(msg: Tag):
    try:
        post_data = msg.get("data-post")
        if not post_data:
            # print("[!] Error: 'data-post' attribute missing in tag.")
            return None

        post_data_str = str(post_data)
        msg_id = post_data_str.split("/")[-1]

        return msg_id
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def get_message_datetime(msg: Tag):
    try:
        time_tag = msg.find("time", class_="time")

        if not time_tag:
            # print("[!] Error: <time> tag with class 'time' not found.")
            return None

        datetime = time_tag.get("datetime")
        if not datetime:
            # print("[!] Error: 'datetime' attribute missing from <time> tag.")
            return None

        datetime_str = str(datetime)
        msg_date = parse_iso_date(datetime_str)

        return msg_date
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def get_message_text(msg: Tag):
    try:
        text_div = msg.find("div", class_="tgme_widget_message_text")
        if not text_div:
            # print(
            #     "[!] Error: <div> tag with class 'tgme_widget_message_text' not found."
            # )
            return None

        text = text_div.get_text()
        return text
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def get_message_forwarded_from(msg: Tag):
    try:
        forwarded_from_a = msg.find(
            "a", class_="tgme_widget_message_forwarded_from_name"
        )
        if not forwarded_from_a:
            return None

        link = forwarded_from_a.get("href")

        if not link:
            return None

        link = str(link)
        parts = link.split("/")

        if len(parts) > 3:
            return parts[3]

        return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def get_message_links(msg: Tag):
    try:
        msg_links = msg.find_all("a")

        if not msg_links:
            return None

        links = [
            str(msg_link.get("href")) for msg_link in msg_links if msg_link.get("href")
        ]

        return links
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


async def load_channel_messages(
    channel: str, session: aiohttp.ClientSession, before: str | None = None
):

    channel_url = f"https://t.me/s/{channel}"
    if before:
        channel_url += f"?before={before}"

    for attempt in range(MAX_RETRIES):
        try:

            async with session.get(channel_url, headers=HEADERS) as response:
                if response.status == 200:
                    html = await response.text()

                    soup = BeautifulSoup(html, "html.parser")
                    messages = soup.find_all("div", class_="tgme_widget_message")

                    if not messages:
                        # print(f"[!] No messages found for {channel} (Private/Empty?)")
                        return None

                    messages.reverse()
                    return messages

                elif response.status == 429 or response.status >= 500:
                    wait_time = BASE_DELAY * (attempt + 1)
                    print(
                        f"! {channel:<30} | Rate Limit ({response.status}). Retrying in {wait_time}s..."
                    )
                    await asyncio.sleep(wait_time)
                    continue

                # Hard Failure (404 Not Found, etc.)
                else:
                    return None
        except (
            aiohttp.ClientError,
            asyncio.TimeoutError,
            ProxyError,
            ProxyConnectionError,
            ProxyTimeoutError,
        ):
            # Connection Dropped (IP Block often looks like this)
            wait_time = BASE_DELAY * (attempt + 1)
            print(f"! {channel:<30} | Connection Error. Retrying in {wait_time}s...")
            await asyncio.sleep(wait_time)
            continue

    print(f"✗ {channel:<30} | Failed after {MAX_RETRIES} retries")
    return None
