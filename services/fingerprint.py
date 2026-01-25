import base64
import json
import urllib.parse


def safe_base64_decode(s):
    """Safely decodes base64 strings with missing padding."""
    s = s.strip()
    missing_padding = len(s) % 4
    if missing_padding:
        s += "=" * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def get_vmess_fingerprint(link):
    """
    Parses VMess JSON and creates a unique signature.
    Ignores the 'ps' (remark) field.
    """
    try:
        # 1. Remove prefix and decode
        payload = link.replace("vmess://", "")
        decoded = safe_base64_decode(payload)
        if not decoded:
            return None

        data = json.loads(decoded)

        # 2. Extract functional fields only
        # We assume if IP, Port, ID, and Network match, it's the same server.
        # 'add' = address, 'id' = uuid
        fingerprint = (
            f"vmess|"
            f"{data.get('add', '').lower()}|"
            f"{data.get('port', '')}|"
            f"{data.get('id', '')}|"
            f"{data.get('net', '')}|"
            f"{data.get('path', '')}|"
            f"{data.get('host', '')}|"
            f"{data.get('sni', '')}"
        )
        return fingerprint
    except Exception:
        return None  # If we can't parse it, treat it as invalid or unique


def get_url_fingerprint(link):
    """
    Parses standard URI schemes (VLESS, Trojan, Tuic, Hysteria).
    Ignores the fragment (#remark).
    """
    try:
        parsed = urllib.parse.urlparse(link)

        # Parse query params to sort them (to ensure order doesn't matter)
        query = urllib.parse.parse_qs(parsed.query)

        # Extract critical params for uniqueness
        # We care about: security, sni, type, serviceName, path, host
        relevant_params = []
        for key in ["security", "sni", "host", "type", "serviceName", "path"]:
            val = query.get(key, [""])[0]
            if val:
                relevant_params.append(f"{key}={val}")

        params_str = "|".join(sorted(relevant_params))

        fingerprint = (
            f"{parsed.scheme}|"
            f"{parsed.hostname.lower()}|"
            f"{parsed.port}|"
            f"{parsed.username}|"
            f"{params_str}"
        )
        return fingerprint
    except Exception:
        return None


def get_ss_fingerprint(link):
    """
    Parses Shadowsocks (SS) links.
    """
    try:
        # Remove ss://
        body = link.split("ss://")[1]
        # Remove remark (#...)
        if "#" in body:
            body = body.split("#")[0]

        # SS links can be base64 encoded or plain text
        if "@" not in body:
            # likely base64 encoded "method:password@host:port"
            decoded = safe_base64_decode(body)
            if decoded:
                body = decoded

        # Normalize
        return f"ss|{body}"
    except Exception:
        return None


def generate_fingerprint(config):
    """
    Main router function to handle different protocols.
    """
    if config.startswith("vmess://"):
        return get_vmess_fingerprint(config)
    elif config.startswith("ss://"):
        return get_ss_fingerprint(config)
    elif config.startswith(("vless://", "trojan://", "tuic://", "hysteria")):
        return get_url_fingerprint(config)

    # Fallback: if we don't know the protocol, just use the link itself
    return config
