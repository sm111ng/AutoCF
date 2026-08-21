#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoCF VLESS Real Tester
========================

用途：
1. 读取 decoded_sub.txt / usable_nodes.txt 中的 VLESS
2. 调用本机 xray.exe 建立真实 VLESS -> SOCKS5
3. 通过 SOCKS5 实际访问 Cloudflare trace
4. 获取真实代理出口 IP
5. 查询出口 IP 国家/城市
6. 测试实际代理延迟
7. 可选做多轮稳定性测试
8. 输出：
   real_results.csv
   real_usable_nodes.txt
   real_usable_subscription.txt
   real_summary.txt

注意：
- 这一步与 scanner_v4.py 不同：它测试的是“真正通过 VLESS 代理上网”。
- 本程序不会修改 Windows 系统代理。
- 需要 xray.exe 放在 I:\\AutoCF\\xray.exe，或加入 PATH。
"""

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

# 优先使用 V4 筛选后的节点；没有则使用 decoded_sub.txt
INPUT_FILES = [
    BASE / "usable_nodes.txt",
    BASE / "decoded_sub.txt",
]

XRAY = BASE / "xray.exe"

TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"
IPINFO_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as"

LOCAL_SOCKS_START = 21000

# 每个节点最长等待
START_TIMEOUT = 12
REQUEST_TIMEOUT = 15

# 稳定性测试次数
STABILITY_ROUNDS = 3

# 通过标准
MIN_SUCCESS_RATE = 0.66
MAX_EXIT_LATENCY_MS = 5000

# 为了避免同一时间启动太多 xray，默认逐个测试
# 20 个节点并不算多，逐个更稳。
COUNTRY_MAP = {
    "JP": "日本", "US": "美国", "HK": "香港", "SG": "新加坡",
    "KR": "韩国", "TW": "台湾", "CN": "中国", "GB": "英国",
    "DE": "德国", "NL": "荷兰", "FR": "法国", "CA": "加拿大",
    "AU": "澳大利亚", "IN": "印度", "RU": "俄罗斯", "TR": "土耳其",
    "SE": "瑞典", "FI": "芬兰", "PL": "波兰", "IT": "意大利",
    "ES": "西班牙", "AE": "阿联酋",
}

def log(s=""):
    print(s, flush=True)

def find_input():
    for p in INPUT_FILES:
        if p.exists() and p.stat().st_size > 0:
            return p
    raise FileNotFoundError(
        "找不到 usable_nodes.txt 或 decoded_sub.txt。"
    )

def find_xray():
    if XRAY.exists():
        return str(XRAY)
    found = shutil.which("xray.exe") or shutil.which("xray")
    if found:
        return found
    raise FileNotFoundError(
        "找不到 xray.exe。请把 xray.exe 放到 I:\\AutoCF\\xray.exe，"
        "或把 Xray 加入 PATH。"
    )

def load_vless(path):
    lines = []
    seen = set()

    text = path.read_text(encoding="utf-8", errors="ignore")
    # 同时支持普通 VLESS 文本和 Base64 订阅
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
        raise ValueError("不是 VLESS URI")

    uuid = unquote(u.username or "")
    host = u.hostname
    port = u.port

    if not uuid or not host or not port:
        raise ValueError("VLESS URI 缺少 UUID / host / port")

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
    # 针对当前订阅的 TLS + WebSocket VLESS。
    # ECH 参数如果存在但无法直接转换为 Xray 的标准 ECH 配置，
    # 这里先不注入，先验证基础 VLESS 是否可用。
    stream = {
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
            "error": "" if ok else ((p.stderr or "").strip()[:300] or "代理请求失败"),
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
                    "error": "XRAY 启动失败或 SOCKS 端口未监听",
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
                    "error": rounds[-1]["error"] if rounds else "无结果",
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
                "error": "" if ok else "稳定性/延迟未达标",
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
    print("这一阶段测试的是：真实 VLESS 代理，而不是单纯 IP/TLS 可达性。")
    print()

    try:
        xray = find_xray()
    except FileNotFoundError as e:
        print(f"错误：{e}")
        print()
        print("把 xray.exe 放到：")
        print(str(XRAY))
        sys.exit(1)

    input_file = find_input()
    uris = load_vless(input_file)

    print(f"输入文件: {input_file.name}")
    print(f"发现 VLESS: {len(uris)}")
    print(f"Xray: {xray}")
    print(f"稳定性测试: {STABILITY_ROUNDS} 轮")
    print()

    if not uris:
        print("没有发现 VLESS 节点。")
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

            # 防止旧进程占用，寻找可用本地端口
            socks_port = LOCAL_SOCKS_START + i
            result = test_one(uri, xray, socks_port)
            result["score"] = score(result)

            rows.append(result)

            if result["ok"]:
                print(
                    f"OK  出口={result['exit_ip']} "
                    f"{result['region']} "
                    f"{result['latency_ms']}ms "
                    f"稳定={result['success_rate']:.0%}"
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

    # 每个真实出口地区最多 3 个
    region_count = {}
    selected = []

    for r in usable:
        region = r["region"] or "??"
        if region_count.get(region, 0) >= 3:
            continue
        region_count[region] = region_count.get(region, 0) + 1
        selected.append(r)

    # 用真实出口地区命名
    out_lines = []
    for r in selected:
        region = r["region"] or "??"
        num = region_count[region]
        # 这里重新按出现顺序编号
        count = sum(1 for x in selected if x["region"] == region)
        # 后面用单独计数器覆盖
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
    summary.append(f"输入节点: {len(uris)}")
    summary.append(f"真实 VLESS 可用: {len(usable)}")
    summary.append(f"最终保留: {len(selected)}")
    summary.append("")
    summary.append("真实出口地区统计")
    summary.append("-" * 72)

    for region in sorted(region_count):
        summary.append(
            f"{region:4} {COUNTRY_MAP.get(region, ''):8} "
            f"{region_count[region]} nodes"
        )

    summary.append("")
    summary.append("最终节点")
    summary.append("-" * 72)

    for i, r in enumerate(selected, 1):
        summary.append(
            f"{i:02d}. {r['name']:6} "
            f"入口={r['ip']}:{r['port']} "
            f"出口={r['exit_ip']} "
            f"{r['latency_ms']}ms "
            f"稳定={r['success_rate']:.0%} "
            f"Score={r['score']}"
        )

    (BASE / "real_summary.txt").write_text(
        "\n".join(summary) + "\n",
        encoding="utf-8"
    )

    print()
    print("=" * 72)
    print(f"真实 VLESS 可用: {len(usable)} / {len(rows)}")
    print(f"最终保留:        {len(selected)}")
    print("=" * 72)
    print()
    print(f"{'NAME':7} {'入口IP':18} {'出口IP':16} {'REGION':7} {'LATENCY':9} {'STABLE':8} {'SCORE':6}")
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
    print("输出文件：")
    print("  real_results.csv")
    print("  real_usable_nodes.txt")
    print("  real_usable_subscription.txt")
    print("  real_summary.txt")

if __name__ == "__main__":
    main()
