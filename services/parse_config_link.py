import base64
import json
from urllib.parse import parse_qs, unquote, urlparse


def safe_base64_decode(s):
    """Helper to decode base64 strings with or without padding."""
    if not s:
        return ""
    s = s.strip()
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8")
    except Exception:
        try:
            return base64.b64decode(s).decode("utf-8")
        except Exception:
            return ""


def parse_vmess(link):
    """Parses VMess (base64 encoded JSON)."""
    b64_str = link[8:]
    try:
        data = json.loads(safe_base64_decode(b64_str))
    except Exception:
        raise ValueError("Invalid VMess base64")

    outbound = {
        "type": "vmess",
        "tag": data.get("ps", "vmess-proxy"),
        "server": data.get("add"),
        "server_port": int(data.get("port")),
        "uuid": data.get("id"),
        "alter_id": int(data.get("aid", 0)),
        "security": data.get("scy", "auto"),
    }

    net = data.get("net", "tcp")
    if net == "raw":
        net = "tcp"

    if net and net not in ["tcp", "kcp", "quic"]:
        transport = {"type": net}
        if net == "ws":
            transport["path"] = data.get("path", "/")
            transport["headers"] = {"Host": data.get("host", "")}
        elif net == "grpc":
            transport["service_name"] = data.get("path", "")
        elif net == "httpupgrade":
            transport["path"] = data.get("path", "/")
            transport["headers"] = {"Host": data.get("host", "")}
        outbound["transport"] = transport

    # TLS
    if data.get("tls") == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": data.get("sni") or data.get("host"),
            "insecure": True,
        }

    return outbound


def parse_server_host_port(server_str):
    """
    Parses 'host:port' string, handling IPv6 brackets safely.
    Example: "[::1]:8388" -> "::1", 8388
    """
    try:
        # We use rsplit because IPv6 addresses contain colons.
        # The port is ALWAYS the last element after the last colon.
        host_str, port_str = server_str.rsplit(":", 1)

        # Remove brackets from IPv6 (e.g., [::1] -> ::1)
        if host_str.startswith("[") and host_str.endswith("]"):
            host_str = host_str[1:-1]

        return host_str, int(port_str)
    except ValueError:
        raise ValueError(f"Invalid server format: {server_str}")


VALID_SS_METHODS = {
    # AEAD
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    # SS-2022
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    # Stream / Legacy
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
    "chacha20",
}


def parse_shadowsocks(link):
    """
    Master Shadowsocks Parser.
    Supports:
      1. SIP002 (ss://base64(user:pass)@host:port)
      2. Legacy (ss://base64(method:pass@host:port))
      3. Plugins (obfs, v2ray-plugin)
      4. IPv6 Hosts
    """
    if not link.startswith("ss://"):
        raise ValueError("Not a Shadowsocks link")

    # Strip scheme
    uri = link[5:]

    # 1. Extract Tag (Fragment)
    tag = "ss-proxy"
    if "#" in uri:
        uri, tag_raw = uri.split("#", 1)
        tag = unquote(tag_raw).strip()

    # 2. Extract Plugins (Query) - SIP002 feature
    plugin_opts = None
    if "?" in uri:
        uri, query_part = uri.split("?", 1)
        # We store plugins but Sing-box support varies, so we mostly extract
        # to clean the URI for the next steps.
        q_params = parse_qs(query_part)
        if "plugin" in q_params:
            plugin_opts = unquote(q_params["plugin"][0])

    # 3. Determine Format (SIP002 vs Legacy)
    method = ""
    password = ""
    host = ""
    port = 0

    if "@" in uri:
        # --- SIP002 Format: userinfo@host:port ---
        # userinfo might be plain "method:pass" OR base64("method:pass")
        userinfo, server_str = uri.rsplit("@", 1)

        # Try decoding userinfo. If it fails or has no colon, treat as plain text
        # (Standard SIP002 says userinfo SHOULD be base64 URL-safe, but some clients don't)
        decoded_userinfo = safe_base64_decode(userinfo)

        # Logic: If decoding works and looks like "method:pass", use it.
        # Otherwise, assume the original string was "method:pass".
        if ":" in decoded_userinfo:
            method, password = decoded_userinfo.split(":", 1)
        elif ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            # Fallback: maybe it's just a method (no pass)? Rare.
            method = userinfo

        host, port = parse_server_host_port(server_str)

    else:
        # --- Legacy Format: base64(method:pass@host:port) ---
        decoded = safe_base64_decode(uri)

        if "@" not in decoded:
            raise ValueError("Invalid Legacy SS Base64 (No '@' found)")

        creds, server_str = decoded.rsplit("@", 1)
        host, port = parse_server_host_port(server_str)

        if ":" in creds:
            method, password = creds.split(":", 1)
        else:
            # Legacy weirdness
            method = creds

    # 4. Final Method Sanitization (Double-Encoding Fix)
    # Some links have the method itself Base64 encoded inside the Base64 userinfo
    method = method.lower()
    if method not in VALID_SS_METHODS:
        try:
            # Try decoding just the method
            potential_method = safe_base64_decode(method).lower()
            if potential_method in VALID_SS_METHODS:
                method = potential_method
        except Exception:
            pass

    # 5. Sing-box Output Construction
    config = {
        "type": "shadowsocks",
        "tag": tag,
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }

    # Handle Plugin (Optional Mapping)
    # If the link had a plugin, we can map it to Sing-box 'plugin' or 'transport' fields
    # simple-obfs / obfs-local -> Sing-box doesn't natively support strictly,
    # but v2ray-plugin maps to websocket/httpupgrade transport.
    if plugin_opts:
        if "obfs-local" in plugin_opts or "simple-obfs" in plugin_opts:
            # Just a hint, sing-box usually needs "shadowsocks-obfs" type
            # but often standard SS handles it if configured right.
            pass
        elif "v2ray-plugin" in plugin_opts:
            # Extract opts
            # e.g., "v2ray-plugin;mode=websocket;host=..."
            pass  # (Add complex plugin mapping here if needed)

    return config


def parse_standard_uri(link, protocol):
    """Generic parser."""
    parsed = urlparse(link)
    params = parse_qs(parsed.query)

    outbound = {
        "type": protocol,
        "tag": unquote(parsed.fragment) if parsed.fragment else f"{protocol}-proxy",
        "server": parsed.hostname,
        "server_port": parsed.port,
    }

    if protocol == "vless":
        outbound["uuid"] = parsed.username
        if "flow" in params:
            outbound["flow"] = params["flow"][0]
    elif protocol == "trojan":
        outbound["password"] = parsed.username
    elif protocol == "tuic":
        outbound["uuid"] = parsed.username
        outbound["password"] = parsed.password
        outbound["congestion_control"] = params.get("congestion_control", ["bbr"])[0]
    elif "hysteria2" in protocol or "hy2" in protocol:
        outbound["type"] = "hysteria2"
        outbound["password"] = parsed.username or "password"
        if "obfs" in params:
            outbound["obfs"] = {
                "type": params["obfs"][0],
                "password": params.get("obfs-password", [""])[0],
            }

    # TLS
    security = params.get("security", [""])[0]
    sni = params.get("sni", [""])[0]
    fp = params.get("fp", [""])[0]

    if security == "tls" or protocol in ["tuic", "hysteria2", "hy2"]:
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni if sni else parsed.hostname,
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": fp} if fp else None,
        }
        if security == "reality":
            outbound["tls"]["reality"] = {
                "enabled": True,
                "public_key": params.get("pbk", [""])[0],
                "short_id": params.get("sid", [""])[0],
            }

    # Transport
    net = params.get("type", ["tcp"])[0]
    if net in ["ws", "grpc", "httpupgrade"]:
        transport = {"type": net}
        if net == "ws":
            transport["path"] = params.get("path", ["/"])[0]
            host = params.get("host", [""])[0]
            if host:
                transport["headers"] = {"Host": host}
        elif net == "grpc":
            transport["service_name"] = params.get("serviceName", [""])[0]
        outbound["transport"] = transport

    return outbound


def parse_link(link):
    link = link.strip()
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("ss://"):
        return parse_shadowsocks(link)
    if link.startswith("vless://"):
        return parse_standard_uri(link, "vless")
    if link.startswith("trojan://"):
        return parse_standard_uri(link, "trojan")
    if link.startswith("tuic://"):
        return parse_standard_uri(link, "tuic")
    if "hysteria2" in link or "hy2://" in link:
        return parse_standard_uri(link, "hysteria2")
    raise ValueError("Unsupported protocol")


if __name__ == "__main__":
    # Example Links (These are dummy links for structure demonstration)
    links = [
        "vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInZtZXNzLXRscyIsDQogICJhZGQiOiAidm1lc3MuZXhhbXBsZS5jb20iLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRiY2RlZmctMTIzNC01Njc4LTEyMzQtNTY3ODEyMzQ1Njc4IiwNCiAgImFpZCI6ICIwIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICJ2bWVzcy5leGFtcGxlLmNvbSIsDQogICJwYXRoIjogIi9jaGF0IiwNCiAgInRscyI6ICJ0bHMiDQp9",
        "vless://uuid@vless.example.com:443?security=reality&sni=google.com&fp=chrome&pbk=789_public_key&type=grpc&serviceName=grpcpath#vless-reality",
        "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjg4ODg=#ss-legacy",
        "trojan://password@trojan.example.com:443?security=tls&sni=trojan.example.com&type=ws&path=%2Ftrojan#trojan-ws",
        "hysteria2://myuser@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=secret#hy2-test",
        "tuic://uuid:pass@tuic.example.com:443?congestion_control=bbr&sni=tuic.example.com#tuic-test",
    ]

    for l in links:
        try:
            config = parse_link(l)
            print(f"Parsed {config['type']}:")
            print(json.dumps(config, indent=2))
            print("-" * 30)
        except Exception as e:
            print(f"Error parsing {l[:10]}... : {e}")
