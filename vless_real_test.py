# --- UTF-8 stdout/stderr fix for GitHub Actions / Windows ---
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
# --- END UTF-8 FIX ---
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoCF VLESS Real Tester
========================

鐢ㄩ€旓細
1. 璇诲彇 decoded_sub.txt / usable_nodes.txt 涓殑 VLESS
2. 璋冪敤鏈満 xray.exe 寤虹珛鐪熷疄 VLESS -> SOCKS5
3. 閫氳繃 SOCKS5 瀹為檯璁块棶 Cloudflare trace
4. 鑾峰彇鐪熷疄浠ｇ悊鍑哄彛 IP
5. 鏌ヨ鍑哄彛 IP 鍥藉/鍩庡競
6. 娴嬭瘯瀹為檯浠ｇ悊寤惰繜
7. 鍙€夊仛澶氳疆绋冲畾鎬ф祴璇?8. 杈撳嚭锛?   real_results.csv
   real_usable_nodes.txt
   real_usable_subscription.txt
   real_summary.txt

娉ㄦ剰锛?- 杩欎竴姝ヤ笌 scanner_v4.py 涓嶅悓锛氬畠娴嬭瘯鐨勬槸鈥滅湡姝ｉ€氳繃 VLESS 浠ｇ悊涓婄綉鈥濄€?- 鏈▼搴忎笉浼氫慨鏀?Windows 绯荤粺浠ｇ悊銆?- 闇€瑕?xray.exe 鏀惧湪 I:\\AutoCF\\xray.exe锛屾垨鍔犲叆 PATH銆?"""

import base64
import csv
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import Request, urlopen

BASE = Path(__file__).resolve().parent

# 浼樺厛浣跨敤 V4 绛涢€夊悗鐨勮妭鐐癸紱娌℃湁鍒欎娇鐢?decoded_sub.txt
INPUT_FILES = [
    BASE / "usable_nodes.txt",
    BASE / "decoded_sub.txt",
]

XRAY = BASE / "xray.exe"

TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"
IPINFO_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as"

LOCAL_SOCKS_START = 21000

# 姣忎釜鑺傜偣鏈€闀跨瓑寰?START_TIMEOUT = 12
REQUEST_TIMEOUT = 15

# 绋冲畾鎬ф祴璇曟鏁?STABILITY_ROUNDS = 3

# 閫氳繃鏍囧噯
MIN_SUCCESS_RATE = 0.66
MAX_EXIT_LATENCY_MS = 5000

# 涓轰簡閬垮厤鍚屼竴鏃堕棿鍚姩澶 xray锛岄粯璁ら€愪釜娴嬭瘯
# 20 涓妭鐐瑰苟涓嶇畻澶氾紝閫愪釜鏇寸ǔ銆?COUNTRY_MAP = {
    "JP": "鏃ユ湰", "US": "缇庡浗", "HK": "棣欐腐", "SG": "鏂板姞鍧?,
    "KR": "闊╁浗", "TW": "鍙版咕", "CN": "涓浗", "GB": "鑻卞浗",
    "DE": "寰峰浗", "NL": "鑽峰叞", "FR": "娉曞浗", "CA": "鍔犳嬁澶?,
    "AU": "婢冲ぇ鍒╀簹", "IN": "鍗板害", "RU": "淇勭綏鏂?, "TR": "鍦熻€冲叾",
    "SE": "鐟炲吀", "FI": "鑺叞", "PL": "娉㈠叞", "IT": "鎰忓ぇ鍒?,
    "ES": "瑗跨彮鐗?, "AE": "闃胯仈閰?,
}

def log(s=""):
    print(s, flush=True)

def find_input():
    for p in INPUT_FILES:
        if p.exists() and p.stat().st_size > 0:
            return p
    raise FileNotFoundError(
        "鎵句笉鍒?usable_nodes.txt 鎴?decoded_sub.txt銆?
    )

def find_xray():
    if XRAY.exists():
        return str(XRAY)
    found = shutil.which("xray.exe") or shutil.which("xray")
    if found:
        return found
    raise FileNotFoundError(
        "鎵句笉鍒?xray.exe銆傝鎶?xray.exe 鏀惧埌 I:\\AutoCF\\xray.exe锛?
        "鎴栨妸 Xray 鍔犲叆 PATH銆?
    )

def load_vless(path):
    lines = []
    seen = set()

    text = path.read_text(encoding="utf-8", errors="ignore")
    # 鍚屾椂鏀寔鏅€?VLESS 鏂囨湰鍜?Base64 璁㈤槄
    if "vless://" not in text:
        try:
            decoded = base64.b64decode(
                "".join(text.split()), validate=False
            ).decode("utf-8", errors="ignore")
            text = decoded
        except Exception:
            pass

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue

        m = re.search(r"@(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
        if not m:
            continue

        key = (m.group(1), int(m.group(2)))
        if key in seen:
            continue

        seen.add(key)
        lines.append(line)

    return lines

def parse_vless(uri):
    u = urlparse(uri)

    if u.scheme.lower() != "vless":
        raise ValueError("涓嶆槸 VLESS URI")

    uuid = unquote(u.username or "")
    host = u.hostname
    port = u.port

    if not uuid or not host or not port:
        raise ValueError("VLESS URI 缂哄皯 UUID / host / port")

    q = parse_qs(u.query, keep_blank_values=True)

    def first(k, default=""):
        v = q.get(k)
        return unquote(v[0]) if v else default

    security = first("security", "none")
    transport = first("type", "tcp")
    sni = first("sni", first("host", ""))
    host_header = first("host", sni)
    path = first("path", "/")
    fp = first("fp", "")

    return {
        "uuid": uuid,
        "host": host,
        "port": port,
        "security": security,
        "type": transport,
        "sni": sni,
        "host_header": host_header,
        "path": path or "/",
        "fp": fp,
        "fragment": unquote(u.fragment or ""),
        "raw": uri,
        "params": q,
    }

def make_xray_config(v, socks_port):
    # 閽堝褰撳墠璁㈤槄鐨?TLS + WebSocket VLESS銆?    # ECH 鍙傛暟濡傛灉瀛樺湪浣嗘棤娉曠洿鎺ヨ浆鎹负 Xray 鐨勬爣鍑?ECH 閰嶇疆锛?    # 杩欓噷鍏堜笉娉ㄥ叆锛屽厛楠岃瘉鍩虹 VLESS 鏄惁鍙敤銆?    stream = {
        "network": v["type"],
    }

    if v["type"] == "ws":
        stream["wsSettings"] = {
            "path": v["path"],
            "headers": {
                "Host": v["host_header"]
            }
        }

    if v["security"] == "tls":
        tls = {
            "serverName": v["sni"] or v["host"],
        }
        if v["fp"]:
            tls["fingerprint"] = v["fp"]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls

    cfg = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": False
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": v["host"],
                            "port": v["port"],
                            "users": [
                                {
                                    "id": v["uuid"],
                                    "encryption": "none"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": stream
            },
            {
                "tag": "direct",
                "protocol": "freedom"
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": []
        }
    }

    return cfg

def wait_port(port, timeout=START_TIMEOUT):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False

def start_xray(xray, cfg_path):
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NO_WINDOW

    p = subprocess.Popen(
        [xray, "run", "-c", str(cfg_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    return p

def curl_via_socks(port):
    cmd = [
        "curl.exe",
        "-4",
        "--noproxy", "",
        "--proxy", f"socks5h://127.0.0.1:{port}",
        "--connect-timeout", "8",
        "--max-time", str(REQUEST_TIMEOUT),
        "-sS",
        TEST_URL,
    ]

    started = time.perf_counter()

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=REQUEST_TIMEOUT + 4,
        )
        elapsed = round((time.perf_counter() - started) * 1000)
        text = (p.stdout or "").strip()

        ip = ""
        for line in text.splitlines():
            if line.startswith("ip="):
                ip = line.split("=", 1)[1].strip()
                break

        ok = p.returncode == 0 and bool(ip)

        return {
            "ok": ok,
            "exit_ip": ip,
            "latency_ms": elapsed,
            "raw": text[:1000],
            "error": "" if ok else ((p.stderr or "").strip()[:300] or "浠ｇ悊璇锋眰澶辫触"),
        }

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "exit_ip": "",
            "latency_ms": REQUEST_TIMEOUT * 1000,
            "raw": "",
            "error": "REQUEST_TIMEOUT",
        }

def geoip(ip):
    if not ip:
        return {}

    try:
        req = Request(
            IPINFO_URL.format(ip=ip),
            headers={"User-Agent": "AutoCF/1.0"}
        )
        with urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return {}

def test_one(uri, xray, socks_port):
    v = parse_vless(uri)

    with tempfile.TemporaryDirectory(prefix="autocf_") as td:
        cfg_path = Path(td) / "config.json"
        cfg = make_xray_config(v, socks_port)
        cfg_path.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

        p = None
        try:
            p = start_xray(xray, cfg_path)

            if not wait_port(socks_port):
                return {
                    "ok": False,
                    "vless": uri,
                    "ip": v["host"],
                    "port": v["port"],
                    "exit_ip": "",
                    "region": "??",
                    "country": "",
                    "city": "",
                    "latency_ms": 0,
                    "success_rate": 0,
                    "error": "XRAY 鍚姩澶辫触鎴?SOCKS 绔彛鏈洃鍚?,
                }

            rounds = []
            for _ in range(STABILITY_ROUNDS):
                r = curl_via_socks(socks_port)
                rounds.append(r)
                time.sleep(0.4)

            success = [x for x in rounds if x["ok"]]
            success_rate = len(success) / len(rounds) if rounds else 0

            if not success:
                return {
                    "ok": False,
                    "vless": uri,
                    "ip": v["host"],
                    "port": v["port"],
                    "exit_ip": "",
                    "region": "??",
                    "country": "",
                    "city": "",
                    "latency_ms": max((x["latency_ms"] for x in rounds), default=0),
                    "success_rate": success_rate,
                    "error": rounds[-1]["error"] if rounds else "鏃犵粨鏋?,
                }

            best = min(success, key=lambda x: x["latency_ms"])
            exit_ip = best["exit_ip"]
            g = geoip(exit_ip)
            region = g.get("countryCode", "??")

            ok = (
                success_rate >= MIN_SUCCESS_RATE
                and best["latency_ms"] <= MAX_EXIT_LATENCY_MS
            )

            return {
                "ok": ok,
                "vless": uri,
                "ip": v["host"],
                "port": v["port"],
                "exit_ip": exit_ip,
                "region": region,
                "country": g.get("country", ""),
                "city": g.get("city", ""),
                "isp": g.get("isp", ""),
                "org": g.get("org", ""),
                "latency_ms": best["latency_ms"],
                "success_rate": success_rate,
                "error": "" if ok else "绋冲畾鎬?寤惰繜鏈揪鏍?,
            }

        finally:
            if p:
                try:
                    p.terminate()
                    p.wait(timeout=3)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass

def score(r):
    if not r["ok"]:
        return 0

    latency = r["latency_ms"]
    rate = r["success_rate"]

    if latency <= 500:
        base = 100
    elif latency <= 800:
        base = 95
    elif latency <= 1200:
        base = 88
    elif latency <= 1600:
        base = 78
    elif latency <= 2200:
        base = 65
    elif latency <= 3000:
        base = 50
    else:
        base = 35

    return round(base * rate)

def rename_vless(uri, name):
    if "#" in uri:
        uri = uri.split("#", 1)[0]
    return uri + "#" + name

def main():
    print("=" * 72)
    print("AutoCF VLESS REAL TEST")
    print("=" * 72)
    print("杩欎竴闃舵娴嬭瘯鐨勬槸锛氱湡瀹?VLESS 浠ｇ悊锛岃€屼笉鏄崟绾?IP/TLS 鍙揪鎬с€?)
    print()

    try:
        xray = find_xray()
    except FileNotFoundError as e:
        print(f"閿欒锛歿e}")
        print()
        print("鎶?xray.exe 鏀惧埌锛?)
        print(str(XRAY))
        sys.exit(1)

    input_file = find_input()
    uris = load_vless(input_file)

    print(f"杈撳叆鏂囦欢: {input_file.name}")
    print(f"鍙戠幇 VLESS: {len(uris)}")
    print(f"Xray: {xray}")
    print(f"绋冲畾鎬ф祴璇? {STABILITY_ROUNDS} 杞?)
    print()

    if not uris:
        print("娌℃湁鍙戠幇 VLESS 鑺傜偣銆?)
        sys.exit(1)

    rows = []

    for i, uri in enumerate(uris, 1):
        try:
            v = parse_vless(uri)
            print(
                f"[{i:02d}/{len(uris)}] "
                f"{v['host']}:{v['port']} ... ",
                end="",
                flush=True
            )

            # 闃叉鏃ц繘绋嬪崰鐢紝瀵绘壘鍙敤鏈湴绔彛
            socks_port = LOCAL_SOCKS_START + i
            result = test_one(uri, xray, socks_port)
            result["score"] = score(result)

            rows.append(result)

            if result["ok"]:
                print(
                    f"OK  鍑哄彛={result['exit_ip']} "
                    f"{result['region']} "
                    f"{result['latency_ms']}ms "
                    f"绋冲畾={result['success_rate']:.0%}"
                )
            else:
                print(
                    f"FAIL  {result.get('error','')} "
                    f"({result.get('latency_ms',0)}ms)"
                )

        except Exception as e:
            print(f"ERROR {e}")
            rows.append({
                "ok": False,
                "vless": uri,
                "ip": "",
                "port": "",
                "exit_ip": "",
                "region": "??",
                "country": "",
                "city": "",
                "isp": "",
                "org": "",
                "latency_ms": 0,
                "success_rate": 0,
                "score": 0,
                "error": str(e),
            })

    rows.sort(
        key=lambda r: (
            not r["ok"],
            -r.get("score", 0),
            r.get("latency_ms", 999999),
        )
    )

    # CSV
    fields = [
        "ok", "ip", "port", "exit_ip", "region", "country",
        "city", "isp", "org", "latency_ms", "success_rate",
        "score", "error"
    ]

    with open(BASE / "real_results.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})

    usable = [r for r in rows if r["ok"]]

    # 姣忎釜鐪熷疄鍑哄彛鍦板尯鏈€澶?3 涓?    region_count = {}
    selected = []

    for r in usable:
        region = r["region"] or "??"
        if region_count.get(region, 0) >= 3:
            continue
        region_count[region] = region_count.get(region, 0) + 1
        selected.append(r)

    # 鐢ㄧ湡瀹炲嚭鍙ｅ湴鍖哄懡鍚?    out_lines = []
    for r in selected:
        region = r["region"] or "??"
        num = region_count[region]
        # 杩欓噷閲嶆柊鎸夊嚭鐜伴『搴忕紪鍙?        count = sum(1 for x in selected if x["region"] == region)
        # 鍚庨潰鐢ㄥ崟鐙鏁板櫒瑕嗙洊
    counters = {}
    for r in selected:
        region = r["region"] or "??"
        counters[region] = counters.get(region, 0) + 1
        name = f"{region}-{counters[region]:02d}"
        r["name"] = name
        out_lines.append(rename_vless(r["vless"], name))

    (BASE / "real_usable_nodes.txt").write_text(
        "\n".join(out_lines) + ("\n" if out_lines else ""),
        encoding="utf-8"
    )

    raw = "\n".join(out_lines) + ("\n" if out_lines else "")
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    (BASE / "real_usable_subscription.txt").write_text(
        encoded + "\n",
        encoding="ascii"
    )

    summary = []
    summary.append("AutoCF VLESS REAL TEST")
    summary.append("=" * 72)
    summary.append(f"杈撳叆鑺傜偣: {len(uris)}")
    summary.append(f"鐪熷疄 VLESS 鍙敤: {len(usable)}")
    summary.append(f"鏈€缁堜繚鐣? {len(selected)}")
    summary.append("")
    summary.append("鐪熷疄鍑哄彛鍦板尯缁熻")
    summary.append("-" * 72)

    for region in sorted(region_count):
        summary.append(
            f"{region:4} {COUNTRY_MAP.get(region, ''):8} "
            f"{region_count[region]} nodes"
        )

    summary.append("")
    summary.append("鏈€缁堣妭鐐?)
    summary.append("-" * 72)

    for i, r in enumerate(selected, 1):
        summary.append(
            f"{i:02d}. {r['name']:6} "
            f"鍏ュ彛={r['ip']}:{r['port']} "
            f"鍑哄彛={r['exit_ip']} "
            f"{r['latency_ms']}ms "
            f"绋冲畾={r['success_rate']:.0%} "
            f"Score={r['score']}"
        )

    (BASE / "real_summary.txt").write_text(
        "\n".join(summary) + "\n",
        encoding="utf-8"
    )

    print()
    print("=" * 72)
    print(f"鐪熷疄 VLESS 鍙敤: {len(usable)} / {len(rows)}")
    print(f"鏈€缁堜繚鐣?        {len(selected)}")
    print("=" * 72)
    print()
    print(f"{'NAME':7} {'鍏ュ彛IP':18} {'鍑哄彛IP':16} {'REGION':7} {'LATENCY':9} {'STABLE':8} {'SCORE':6}")
    print("-" * 88)

    for r in selected:
        print(
            f"{r['name']:7} "
            f"{r['ip']:18} "
            f"{r['exit_ip']:16} "
            f"{r['region']:7} "
            f"{r['latency_ms']:<9} "
            f"{r['success_rate']:.0%}     "
            f"{r['score']:<6}"
        )

    print()
    print("杈撳嚭鏂囦欢锛?)
    print("  real_results.csv")
    print("  real_usable_nodes.txt")
    print("  real_usable_subscription.txt")
    print("  real_summary.txt")

if __name__ == "__main__":
    main()

