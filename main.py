#!/usr/bin/env python3
"""
Mihomo Hub & Subscription Converter for Android (Full Edition, No WARP)
"""
from __future__ import annotations

import base64
import copy
import gzip
import json
import os
import re
import sys
import threading
import uuid as _uuid
import zlib
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse, urlencode
import urllib.request
import urllib.error

DATA_DIR = os.environ.get("ANDROID_PRIVATE") or os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(DATA_DIR, "subscriptions.json")
CUSTOM_RULES_FILE = os.path.join(DATA_DIR, "custom_routing.json")
PORT = 12096

try:
    import yaml
except ImportError:
    yaml = None

PROTO_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f: 
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_config(cfg: dict) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f: 
        json.dump(cfg, f, indent=2, ensure_ascii=False)

def load_custom_routing() -> dict:
    if os.path.exists(CUSTOM_RULES_FILE):
        try:
            with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    default_routing = {"groups": []}
    return default_routing

def save_custom_routing(data: dict):
    with open(CUSTOM_RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def default_rule_providers() -> Dict[str, dict]:
    return {
        "geosite-private": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs", "path": "./rule-sets/geosite-private.mrs"},
        "ai": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs", "path": "./rule-sets/ai.mrs"},
        "geoip-for-ru": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "ipcidr", "format": "mrs", "url": "https://raw.githubusercontent.com/Davoyan/mihomo-rule-sets/main/ip-for-ru/lists/ips-for-ru.mrs", "path": "./rule-sets/geoip-for-ru.mrs"},
        "discord_domains": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.mrs", "path": "./rule-sets/discord_domains.mrs"},
        "discord_voiceips": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "ipcidr", "format": "mrs", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/other/discord-voice-ip-list.mrs", "path": "./rule-sets/discord_voiceips.mrs"},
        "refilter_domains": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/legiz-ru/mihomo-rule-sets/main/re-filter/domain-rule.mrs", "path": "./rule-sets/refilter.mrs"},
        "youtube": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs", "path": "./rule-sets/youtube.mrs"},
        "telegram-ips": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "ipcidr", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs", "path": "./rule-sets/telegram-ips.mrs"},
        "telegram-domains": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs", "path": "./rule-sets/telegram-domains.mrs"},
        "geosite-ru": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "domain", "format": "mrs", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ru.mrs", "path": "./rule-sets/geosite-ru.mrs"},
        "ru-inside": {"type": "http", "proxy": "🚫 Недоступные сайты", "interval": 86400, "behavior": "classical", "format": "text", "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-clashx.lst", "path": "./rule-sets/ru-inside.lst"},
        "inline-blocked-ips": {"type": "inline", "payload": ["IP-CIDR,172.232.25.131/32"], "behavior": "classical"},
        "ru-inline-banned": {"type": "inline", "payload": ["DOMAIN-SUFFIX,ua","DOMAIN-SUFFIX,habr.com","DOMAIN-SUFFIX,seasonvar.ru","DOMAIN-SUFFIX,lib.social","DOMAIN-SUFFIX,kemono.su","DOMAIN-SUFFIX,jut.su","DOMAIN-SUFFIX,theins.ru","DOMAIN-SUFFIX,tvrain.ru","DOMAIN-SUFFIX,echo.msk.ru","DOMAIN-SUFFIX,natribu.org"], "behavior": "classical"},
        "ru-inline": {"type": "inline", "payload": ["DOMAIN-SUFFIX,2ip.ru","DOMAIN-SUFFIX,yastatic.net","DOMAIN-SUFFIX,yandex.net","DOMAIN-SUFFIX,yandex.kz","DOMAIN-SUFFIX,yandex.com","DOMAIN-SUFFIX,vk.com","DOMAIN-SUFFIX,ru","DOMAIN-SUFFIX,su","DOMAIN-SUFFIX,by","DOMAIN-KEYWORD,avito","DOMAIN-KEYWORD,ozon","DOMAIN-KEYWORD,wildberries"], "behavior": "classical"},
    }

def default_proxy_groups() -> List[dict]:
    return [
        {"name": "🚫 Недоступные сайты", "type": "select", "proxies": ["⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "▶️ YouTube", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "💬 Discord", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "➤ Telegram", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {"name": "⚪🔵🔴 RU сайты", "type": "select", "proxies": ["🇷🇺 Без VPN"]},
        {"name": "🌍 Остальные сайты", "type": "select", "proxies": ["🚫 Недоступные сайты", "⚡ Минимальная задержка", "🇷🇺 Без VPN"]},
        {
            "name": "⚡ Минимальная задержка",
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "lazy": True,
            "proxies": []
        },
    ]

def default_rules() -> List[str]:
    return [
        "RULE-SET,geosite-private,DIRECT",
        "RULE-SET,ai,🚫 Недоступные сайты",
        "RULE-SET,youtube,▶️ YouTube",
        "RULE-SET,telegram-ips,➤ Telegram",
        "RULE-SET,telegram-domains,➤ Telegram",
        "RULE-SET,discord_domains,💬 Discord",
        "RULE-SET,discord_voiceips,💬 Discord,no-resolve",
        "RULE-SET,ru-inside,🚫 Недоступные сайты",
        "RULE-SET,refilter_domains,🚫 Недоступные сайты",
        "RULE-SET,ru-inline-banned,🚫 Недоступные сайты",
        "RULE-SET,inline-blocked-ips,🚫 Недоступные сайты",
        "RULE-SET,ru-inline,⚪🔵🔴 RU сайты",
        "RULE-SET,geosite-ru,⚪🔵🔴 RU сайты",
        "RULE-SET,geoip-for-ru,⚪🔵🔴 RU сайты,no-resolve",
        "MATCH,🌍 Остальные сайты",
    ]

def default_dns() -> dict:
    return {
        "enable": True,
        "use-hosts": True,
        "ipv6": False,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": ["*.lan", "time.windows.com", "time.apple.com"],
        "default-nameserver": ["77.88.8.8", "8.8.8.8"],
        "nameserver": ["https://8.8.8.8/dns-query#🌍 Остальные сайты", "https://77.88.8.8/dns-query#⚪🔵🔴 RU сайты"]
    }

def default_mihomo_config() -> dict:
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "bind-address": "*",
        "tcp-concurrent": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "dns": default_dns(),
        "proxies": [],
        "proxy-groups": default_proxy_groups(),
        "rule-providers": default_rule_providers(),
        "rules": default_rules(),
    }

def decompress(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":
        try: return gzip.decompress(data)
        except Exception: pass
    if data[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        try: return zlib.decompress(data)
        except Exception: pass
    return data

def fetch_raw(url: str, user_agent: str, headers: dict) -> bytes:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url)
    req.headers["User-Agent"] = user_agent
    req.headers["Accept"] = "*/*"
    for k, v in headers.items():
        req.headers[k] = str(v)
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return decompress(resp.read())

def parse_vmess(url: str) -> Optional[dict]:
    try:
        t = url[8:].replace("-", "+").replace("_", "/")
        d = json.loads(base64.b64decode(t + "=" * (-len(t) % 4)).decode())
        return {"name": d.get("ps", "vmess"), "type": "vmess", "server": d["add"], "port": int(d.get("port", 443)), "uuid": d["id"], "alterId": int(d.get("aid", 0)), "cipher": "auto", "network": d.get("net", "tcp"), "tls": d.get("tls") == "tls", "udp": True}
    except Exception: return None

def parse_vless(url: str) -> Optional[dict]:
    try:
        p = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(p.query).items()}
        port = int(p.port) if p.port else 443
        net = params.get("type", "tcp")
        sec = params.get("security", "none")
        node = {"name": unquote(p.fragment or "vless"), "type": "vless", "server": p.hostname, "port": port, "uuid": p.username, "network": net, "tls": sec in ("tls", "reality"), "udp": True}
        if params.get("flow"): node["flow"] = params["flow"]
        if sec == "reality":
            node["reality-opts"] = {"public-key": params.get("pbk", ""), "short-id": params.get("sid", "")}
            node["client-fingerprint"] = params.get("fp", "chrome")
            node["servername"] = params.get("sni", p.hostname)
        elif sec == "tls":
            node["servername"] = params.get("sni", p.hostname)
        if net == "grpc":
            node["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
        return node
    except Exception: return None

def parse_trojan(url: str) -> Optional[dict]:
    try:
        p = urlparse(url)
        port = int(p.port) if p.port else 443
        return {"name": unquote(p.fragment or "trojan"), "type": "trojan", "server": p.hostname, "port": port, "password": unquote(p.username or ""), "tls": True, "udp": True}
    except Exception: return None

def parse_ss(url: str) -> Optional[dict]:
    try:
        p = urlparse(url)
        port = int(p.port) if p.port else 443
        return {"name": unquote(p.fragment or "ss"), "type": "ss", "server": p.hostname or "ss", "port": port, "cipher": "aes-256-gcm", "password": "pass", "udp": True}
    except Exception: return None

def parse_hy2(url: str) -> Optional[dict]:
    try:
        p = urlparse(url)
        port = int(p.port) if p.port else 443
        return {"name": unquote(p.fragment or "hy2"), "type": "hysteria2", "server": p.hostname, "port": port, "password": unquote(p.username or ""), "udp": True}
    except Exception: return None

def url_to_mihomo(url: str) -> Optional[dict]:
    if url.startswith("vless://"): return parse_vless(url)
    if url.startswith("vmess://"): return parse_vmess(url)
    if url.startswith("trojan://"): return parse_trojan(url)
    if url.startswith("ss://"): return parse_ss(url)
    if url.startswith(("hysteria2://", "hy2://")): return parse_hy2(url)
    return None

def build_mihomo_config_from_sources(sources: List[dict]) -> str:
    base_cfg = default_mihomo_config()
    incoming = []
    for src in sources:
        if src["kind"] == "yaml":
            incoming.extend([p for p in src["cfg"].get("proxies", []) if isinstance(p, dict)])
        elif src.get("uris"):
            for uri in src["uris"]:
                node = url_to_mihomo(uri)
                if node: incoming.append(node)

    merged = dedupe_and_merge_proxies(base_cfg.get("proxies", []), incoming)
    clean_names = [p["name"] for p in merged if p.get("name") and p.get("name") != "🇷🇺 Без VPN"]

    for g in base_cfg["proxy-groups"]:
        if g["name"] == "⚡ Минимальная задержка":
            g["proxies"] = list(clean_names)
        elif isinstance(g.get("proxies"), list):
            for cn in clean_names:
                if cn not in g["proxies"]: g["proxies"].append(cn)

    if not any(p.get("name") == "🇷🇺 Без VPN" for p in merged):
        merged.insert(0, {"name": "🇷🇺 Без VPN", "type": "direct", "udp": True})

    base_cfg["proxies"] = merged
    return yaml.dump(base_cfg, allow_unicode=True, sort_keys=False) if yaml else json.dumps(base_cfg, indent=2)

def dedupe_and_merge_proxies(existing: List[dict], incoming: List[dict]) -> List[dict]:
    res = copy.deepcopy(existing)
    names = {p["name"] for p in res if "name" in p}
    for p in incoming:
        if not isinstance(p, dict): continue
        p = copy.deepcopy(p)
        base = p.get("name", "proxy")
        final = base; i = 2
        while final in names:
            final = f"{base} #{i}"
            i += 1
        p["name"] = final
        names.add(final)
        res.append(p)
    return res

def collect_entry_sources(entry: dict, cfg: dict) -> List[dict]:
    if entry.get("type") == "merge":
        res = []
        for s in entry.get("sources", []):
            if s in cfg: res.extend(collect_entry_sources(cfg[s], cfg))
        return res
    try:
        url = entry.get("url", "")
        if url.startswith("data:text/yaml;base64,"):
            text = base64.b64decode(url.split(",", 1)[1]).decode("utf-8")
        else:
            text = fetch_raw(url, entry.get("user_agent", "v2rayNG/1.8.9"), entry.get("headers", {})).decode("utf-8", errors="replace")
    except Exception:
        return []

    if yaml:
        try:
            y = yaml.safe_load(text)
            if isinstance(y, dict) and (isinstance(y.get("proxies"), list) or isinstance(y.get("Proxy"), list)):
                return [{"kind": "yaml", "cfg": y}]
        except Exception: pass

    lines = [l.strip() for l in text.splitlines() if any(l.strip().startswith(p) for p in PROTO_PREFIXES)]
    if lines: return [{"kind": "uris", "uris": lines}]

    try:
        dec = base64.b64decode(re.sub(r'\s+', '', text) + "==").decode("utf-8", errors="replace")
        lines_dec = [l.strip() for l in dec.splitlines() if any(l.strip().startswith(p) for p in PROTO_PREFIXES)]
        if lines_dec: return [{"kind": "uris", "uris": lines_dec}]
    except Exception: pass
    return []

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mihomo Hub</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 15px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #38bdf8; font-size: 1.4rem; border-bottom: 2px solid #1e293b; padding-bottom: 10px; margin-top: 5px; }
        .card { background: #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
        .btn { background: #0284c7; color: #fff; border: none; padding: 12px; border-radius: 8px; font-weight: bold; width: 100%; font-size: 1rem; cursor: pointer; }
        .btn-danger { background: #dc2626; padding: 6px 10px; width: auto; font-size: 0.8rem; border: none; color: #fff; border-radius: 6px; cursor: pointer; }
        input { width: 100%; background: #0f172a; border: 1px solid #334155; color: #fff; padding: 10px; border-radius: 8px; box-sizing: border-box; margin-bottom: 12px; }
        label { font-size: 0.85rem; color: #94a3b8; display: block; margin-bottom: 4px; }
        .sub-item { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding: 10px 0; }
        .sub-link { color: #38bdf8; font-size: 0.8rem; word-break: break-all; margin-top: 4px; display: block; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Mihomo Android Hub</h1>

        <div class="card">
            <h3 style="margin-top:0;">➕ Добавить подписку</h3>
            <form action="/api/add_sub" method="POST">
                <label>Название:</label>
                <input type="text" name="name" placeholder="Мой VPN" required>
                <label>Ссылка на подписку (URL):</label>
                <input type="url" name="url" placeholder="https://..." required>
                <button type="submit" class="btn">Сохранить подписку</button>
            </form>
        </div>

        <div class="card">
            <h3 style="margin-top:0;">📋 Ваши ссылки для FlClash / Hiddify:</h3>
            <div id="subs-list"></div>
        </div>
    </div>

    <script>
        const subs = %SUBS_JSON%;
        const container = document.getElementById('subs-list');
        if (Object.keys(subs).length === 0) {
            container.innerHTML = '<p style="color:#64748b; font-size:0.9rem;">Подписок пока нет. Добавьте выше первую ссылку.</p>';
        } else {
            for (const [id, s] of Object.entries(subs)) {
                const div = document.createElement('div');
                div.className = 'sub-item';
                div.innerHTML = `
                    <div style="flex-grow: 1; padding-right: 10px;">
                        <strong>${s.name}</strong>
                        <a class="sub-link" href="/${id}?format=mihomo">http://127.0.0.1:12096/${id}?format=mihomo</a>
                    </div>
                    <form action="/api/delete_sub" method="POST" style="margin:0;">
                        <input type="hidden" name="id" value="${id}">
                        <button type="submit" class="btn-danger">Удалить</button>
                    </form>
                `;
                container.appendChild(div);
            }
        }
    </script>
</body>
</html>
"""

class AndroidProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        path = urlparse(self.path).path
        if "127.0.0.1" in path or "localhost" in path:
            if str(PORT) in path:
                path = path.split(str(PORT), 1)[1]
        
        uid = path.strip("/")

        if uid == "favicon.ico":
            self.send_response(204); self.end_headers(); return

        if uid in ("", "gui", "index.html", "index.htm", "index"):
            cfg = load_config()
            html = HTML_TEMPLATE.replace("%SUBS_JSON%", json.dumps(cfg, ensure_ascii=False)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        cfg = load_config()
        if uid not in cfg:
            msg = b"Subscription not found. Open /gui"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        entry = cfg[uid]
        sources = collect_entry_sources(entry, cfg)
        out_yaml = build_mihomo_config_from_sources(sources).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(out_yaml)))
        self.send_header("profile-update-interval", "24")
        self.end_headers()
        self.wfile.write(out_yaml)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = parse_qs(self.rfile.read(length).decode("utf-8"))
        path = urlparse(self.path).path
        if str(PORT) in path:
            path = path.split(str(PORT), 1)[1]
        p = "/" + path.strip("/")

        if p == "/api/add_sub":
            name = data.get("name", ["VPN"])[0]
            url = data.get("url", [""])[0]
            if url:
                cfg = load_config()
                uid = str(_uuid.uuid4())[:8]
                cfg[uid] = {"name": name, "type": "single", "url": url, "headers": {"x-hwid": str(_uuid.uuid4())}}
                save_config(cfg)
        elif p == "/api/delete_sub":
            sid = data.get("id", [""])[0]
            cfg = load_config()
            if sid in cfg: del cfg[sid]; save_config(cfg)

        self.send_response(303)
        self.send_header('Location', '/gui')
        self.end_headers()

def start_server():
    server = HTTPServer(("0.0.0.0", PORT), AndroidProxyHandler)
    server.serve_forever()

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.core.window import Window

class MihomoHubApp(App):
    def build(self):
        Window.clearcolor = (0.06, 0.09, 0.16, 1)
        layout = BoxLayout(orientation='vertical', padding=25, spacing=15)
        lbl_title = Label(text="⚡ Mihomo Android Hub", font_size='22sp', bold=True, size_hint_y=0.25)
        lbl_status = Label(text="Сервер запущен:\n127.0.0.1:12096", font_size='16sp', halign='center', color=(0.2, 0.8, 0.4, 1), size_hint_y=0.35)
        
        btn_open = Button(text="🌐 Открыть панель управления", size_hint_y=0.25, background_color=(0.01, 0.52, 0.78, 1))
        btn_open.bind(on_release=lambda x: webbrowser.open("http://127.0.0.1:12096/gui"))
        
        layout.add_widget(lbl_title)
        layout.add_widget(lbl_status)
        layout.add_widget(btn_open)
        return layout

if __name__ == "__main__":
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    MihomoHubApp().run()