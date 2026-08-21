#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoCF scanner_v4.py

用途：
1. 从 decoded_sub.txt 读取 VLESS 节点
2. 提取 IP / Port / 原始 VLESS
3. 使用真实域名 + SNI + --resolve 做 HTTPS 验证
4. 查询 IP 地理位置，给节点标记 JP / US / HK / SG / ...
5. 按延迟和可用性排序
6. 输出：
   results.csv
   usable_nodes.txt
   usable_subscription.txt   （Base64 VLESS 订阅）
   summary.txt

说明：
- HTTPS=OK 代表该 IP:Port 能在指定 SNI 下成功到达 Cloudflare。
- 这不是 100% 等同于“VLESS 已经能代理上网”。
- 如果机器安装了 xray.exe，可在后续版本增加真正的 VLESS 代理实测。
"""

import base64
import csv
import json
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

# =========================
# 配置
# =========================

SUB_FILE = Path("decoded_sub.txt")
DOMAIN = "diaoyong.smil1ng.dpdns.org"

# 每个地区最多保留多少个节点；0 = 不限制
TOP_PER_REGION = 3

# 并发数
WORKERS = 12

# curl 超时
CONNECT_TIMEOUT = 8
MAX_TIME = 12

# 只有 HTTP 成功才算 HTTPS_OK
ACCEPT_HTTP = {200, 204, 301, 302, 400, 403, 404}

# 是否只保留 Cloudflare
REQUIRE_CLOUDFLARE = True

# =========================
# 地区名称
# =========================

COUNTRY_MAP = {
    "JP": "日本",
    "US": "美国",
    "HK": "香港",
    "SG": "新加坡",
    "KR": "韩国",
    "TW": "台湾",
    "CN": "中国",
    "GB": "英国",
    "DE": "德国",
    "NL": "荷兰",
    "FR": "法国",
    "CA": "加拿大",
    "AU": "澳大利亚",
    "IN": "印度",
    "RU": "俄罗斯",
    "TR": "土耳其",
    "SE": "瑞典",
    "FI": "芬兰",
    "PL": "波兰",
    "IT": "意大利",
    "ES": "西班牙",
}

# =========================
# 工具
# =========================

def log(msg):
    print(msg, flush=True)


def parse_vless_file(path):
    nodes = []

    if not path.exists():
        raise FileNotFoundError(f"找不到 {path.resolve()}")

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue

        m = re.search(r"@(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
        if not m:
            continue

        ip = m.group(1)
        port = int(m.group(2))

        # 去重，但保留第一次出现的完整 VLESS
        key = (ip, port)
        if any((x["ip"], x["port"]) == key for x in nodes):
            continue

        nodes.append({
            "ip": ip,
            "port": port,
            "vless": line,
        })

    return nodes


def curl_https_test(ip, port):
    """
    使用 curl：
      --noproxy "*"
      --resolve DOMAIN:PORT:IP
      https://DOMAIN:PORT/

    这样测试不会受到 Windows 当前代理设置影响。
    """

    url = f"https://{DOMAIN}:{port}/"
    resolve = f"{DOMAIN}:{port}:{ip}"

    cmd = [
        "curl.exe",
        "-4",
        "-I",
        "--noproxy", "*",
        "--connect-timeout", str(CONNECT_TIMEOUT),
        "--max-time", str(MAX_TIME),
        "--resolve", resolve,
        url,
    ]

    started = time.perf_counter()

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=MAX_TIME + 3,
        )
        elapsed = round((time.perf_counter() - started) * 1000)

        text = (p.stdout or "") + "\n" + (p.stderr or "")

        m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d+)", text)
        http = int(m.group(1)) if m else 0

        sm = re.search(r"(?im)^Server:\s*([^\r\n]+)", text)
        server = sm.group(1).strip() if sm else ""

        cf_ok = "cloudflare" in server.lower() or "CF-RAY:" in text.upper()

        ok = http in ACCEPT_HTTP
        if REQUIRE_CLOUDFLARE:
            ok = ok and cf_ok

        return {
            "https_ok": ok,
            "http": http,
            "server": server,
            "cloudflare": cf_ok,
            "latency_ms": elapsed,
            "error": "" if ok else "HTTPS验证失败",
        }

    except subprocess.TimeoutExpired:
        return {
            "https_ok": False,
            "http": 0,
            "server": "",
            "cloudflare": False,
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "error": "TIMEOUT",
        }
    except Exception as e:
        return {
            "https_ok": False,
            "http": 0,
            "server": "",
            "cloudflare": False,
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "error": str(e),
        }


def geoip_batch(ips):
    """
    ip-api.com 批量查询，最多一次 100 个 IP。
    返回：
      countryCode / country / city / regionName / org / as
    """
    if not ips:
        return {}

    result = {}

    # ip-api batch 单次最多 100
    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]

        payload = json.dumps([
            {
                "query": ip,
                "fields": "status,country,countryCode,regionName,city,isp,org,as,query"
            }
            for ip in batch
        ]).encode("utf-8")

        req = Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))

            for item in data:
                ip = item.get("query")
                if not ip:
                    continue

                if item.get("status") == "success":
                    result[ip] = item
                else:
                    result[ip] = {
                        "status": "fail",
                        "countryCode": "??",
                        "country": "Unknown",
                        "regionName": "",
                        "city": "",
                        "isp": "",
                        "org": "",
                        "as": "",
                    }

        except Exception as e:
            log(f"[GeoIP] 批量查询失败: {e}")

    return result


def region_name(code):
    return COUNTRY_MAP.get(code, code or "??")


def make_vless(line, ip, port, region_code):
    """
    只替换 endpoint IP:Port。
    保留 UUID、TLS、WS、SNI、path、host 等全部原参数。
    同时把节点名称改成：
      JP-01
      US-02
    """
    new_line = re.sub(
        r"@(\d{1,3}(?:\.\d{1,3}){3}):\d+",
        f"@{ip}:{port}",
        line,
        count=1,
    )

    # 去掉旧 fragment
    if "#" in new_line:
        new_line = new_line.split("#", 1)[0]

    return f"{new_line}#{region_code}"


def score(row):
    """
    当前评分只用于排序，不代表真实代理质量。
    HTTPS OK 是硬门槛。
    """
    if not row["https_ok"]:
        return 0

    latency = row["latency_ms"]

    if latency <= 500:
        s = 100
    elif latency <= 800:
        s = 95
    elif latency <= 1200:
        s = 88
    elif latency <= 1600:
        s = 78
    elif latency <= 2200:
        s = 65
    elif latency <= 3000:
        s = 50
    else:
        s = 35

    if row["cloudflare"]:
        s += 3

    return min(s, 100)


def write_csv(rows):
    fields = [
        "ip", "port", "region", "country", "city",
        "isp", "org", "as",
        "https_ok", "http", "server",
        "cloudflare", "latency_ms", "score", "error"
    ]

    with open("results.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()

        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def main():
    print("=" * 72)
    print("AutoCF Scanner V4")
    print("=" * 72)

    if not shutil_which("curl.exe"):
        print("错误：找不到 curl.exe")
        print("Windows 10/11 通常自带 curl.exe。")
        sys.exit(1)

    nodes = parse_vless_file(SUB_FILE)

    print(f"发现 VLESS 节点: {len(nodes)}")

    if not nodes:
        print("没有找到可解析的 vless:// 节点。")
        sys.exit(1)

    # 先做 HTTPS/SNI
    print()
    print("[1/3] HTTPS + SNI 批量验证")
    print(f"域名: {DOMAIN}")
    print(f"并发: {WORKERS}")
    print()

    results = []

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        future_map = {
            ex.submit(curl_https_test, n["ip"], n["port"]): n
            for n in nodes
        }

        done = 0
        for future in as_completed(future_map):
            n = future_map[future]
            test = future.result()

            row = {
                **n,
                **test,
            }

            done += 1

            state = "OK" if test["https_ok"] else "FAIL"
            print(
                f"[{done:02d}/{len(nodes)}] "
                f"{n['ip']}:{n['port']} "
                f"{state:4} "
                f"{test['latency_ms']:5} ms"
            )

            results.append(row)

    # GeoIP
    print()
    print("[2/3] GeoIP 地区识别")

    ips = list(dict.fromkeys(r["ip"] for r in results))
    geo = geoip_batch(ips)

    for r in results:
        g = geo.get(r["ip"], {})

        code = g.get("countryCode", "??")
        r["region"] = code
        r["country"] = g.get("country", "Unknown")
        r["city"] = g.get("city", "")
        r["isp"] = g.get("isp", "")
        r["org"] = g.get("org", "")
        r["as"] = g.get("as", "")
        r["score"] = score(r)

    # 排序
    results.sort(
        key=lambda r: (
            not r["https_ok"],
            -r["score"],
            r["latency_ms"],
        )
    )

    write_csv(results)

    # 只保留 HTTPS 可用
    usable = [r for r in results if r["https_ok"]]

    # 每个地区 Top N
    selected = []
    region_counts = {}

    for r in sorted(
        usable,
        key=lambda x: (x["region"], -x["score"], x["latency_ms"])
    ):
        region = r["region"]

        if TOP_PER_REGION > 0 and region_counts.get(region, 0) >= TOP_PER_REGION:
            continue

        region_counts[region] = region_counts.get(region, 0) + 1
        selected.append(r)

    selected.sort(key=lambda r: (-r["score"], r["latency_ms"]))

    # 节点文本
    vless_lines = []

    for r in selected:
        vless_lines.append(
            make_vless(
                r["vless"],
                r["ip"],
                r["port"],
                f"{r['region']}-{region_counts.get(r['region'], 0)}"
            )
        )

    Path("usable_nodes.txt").write_text(
        "\n".join(vless_lines) + ("\n" if vless_lines else ""),
        encoding="utf-8"
    )

    # Base64 subscription
    raw = "\n".join(vless_lines) + ("\n" if vless_lines else "")
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")

    Path("usable_subscription.txt").write_text(
        encoded + "\n",
        encoding="ascii"
    )

    # 摘要
    summary = []
    summary.append("AutoCF Scanner V4 Result")
    summary.append("=" * 60)
    summary.append(f"输入节点: {len(results)}")
    summary.append(f"HTTPS可用: {len(usable)}")
    summary.append(f"最终保留: {len(selected)}")
    summary.append("")

    summary.append("地区统计")
    summary.append("-" * 60)

    for region, count in sorted(region_counts.items()):
        summary.append(
            f"{region:4} {region_name(region):8} {count:3} nodes"
        )

    summary.append("")
    summary.append("最终节点")
    summary.append("-" * 60)

    for i, r in enumerate(selected, 1):
        summary.append(
            f"{i:02d}. "
            f"{r['region']:4} "
            f"{r['ip']}:{r['port']} "
            f"{r['latency_ms']}ms "
            f"Score={r['score']}"
        )

    Path("summary.txt").write_text(
        "\n".join(summary) + "\n",
        encoding="utf-8"
    )

    # 控制台输出
    print()
    print("[3/3] 完成")
    print()
    print("=" * 72)
    print(f"HTTPS 可用: {len(usable)} / {len(results)}")
    print(f"最终保留:   {len(selected)}")
    print("=" * 72)

    print()
    print(f"{'REGION':8} {'IP':18} {'PORT':7} {'LATENCY':10} {'SCORE':6}")
    print("-" * 60)

    for r in selected:
        print(
            f"{r['region']:8} "
            f"{r['ip']:18} "
            f"{r['port']:<7} "
            f"{r['latency_ms']:<10} "
            f"{r['score']:<6}"
        )

    print()
    print("输出文件：")
    print("  results.csv")
    print("  usable_nodes.txt")
    print("  usable_subscription.txt")
    print("  summary.txt")


def shutil_which(name):
    """
    不额外依赖 shutil，兼容直接运行。
    """
    import shutil
    return shutil.which(name)


if __name__ == "__main__":
    main()
