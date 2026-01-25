import base64
import json
import urllib.parse


def safe_base64_decode(s):
    """Helper to decode base64 strings with missing padding."""
    s = s.strip()
    missing_padding = len(s) % 4
    if missing_padding:
        s += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")


def safe_base64_encode(s):
    """Helper to encode string to base64."""
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")


def rename_vmess(link, channel_name):
    """Parses VMess, updates the 'ps' field, and re-encodes it."""
    try:
        payload = link.replace("vmess://", "")
        decoded_json = safe_base64_decode(payload)
        data = json.loads(decoded_json)

        # Get current name and prepend channel
        current_name = data.get("ps", "Server")
        new_name = f"{channel_name} | {current_name}"

        data["ps"] = new_name

        # Re-encode
        new_payload = json.dumps(data)
        encoded_payload = safe_base64_encode(new_payload)
        return f"vmess://{encoded_payload}"
    except Exception:
        return link  # If fails, return original


def rename_url_config(link, channel_name):
    """Handles VLESS, Trojan, SS, Tuic, Hysteria."""
    try:
        parsed = urllib.parse.urlparse(link)

        # Get current fragment (remark)
        current_remark = parsed.fragment
        if not current_remark:
            current_remark = "Server"

        # Create new remark
        new_remark = f"{channel_name} | {current_remark}"

        # Rebuild URL with new fragment
        new_parsed = parsed._replace(fragment=new_remark)
        return urllib.parse.urlunparse(new_parsed)
    except Exception:
        return link


def rename_config(link, channel_name):
    """Main entry point to rename any config."""
    # Clean up the channel name (remove @ or http)
    clean_name = str(channel_name).split("/")[-1].replace("@", "").strip()

    if link.startswith("vmess://"):
        return rename_vmess(link, clean_name)
    else:
        return rename_url_config(link, clean_name)
