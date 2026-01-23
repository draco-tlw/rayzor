from datetime import datetime, timezone
from zoneinfo import ZoneInfo


def parse_dates(start_str, end_str):
    """Converts string inputs to UTC datetime objects."""
    fmt = "%Y-%m-%d-%H:%M"
    tehran_tz = ZoneInfo("Asia/Tehran")
    # Create datetime objects
    start_local = datetime.strptime(start_str, fmt)
    end_local = datetime.strptime(end_str, fmt)

    start_tehran = start_local.replace(tzinfo=tehran_tz)
    end_tehran = end_local.replace(tzinfo=tehran_tz)

    # Force them to be UTC aware (since Telegram works in UTC)
    start_utc = start_tehran.astimezone(timezone.utc)
    end_utc = end_tehran.astimezone(timezone.utc)

    return start_utc, end_utc


if __name__ == "__main__":
    start, end = parse_dates("2025-01-23-12:00", "2025-01-23-18:00")

    print("start: ", start)
    print("end: ", end)
