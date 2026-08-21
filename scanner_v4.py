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
AutoCF scanner_v4.py

鐢ㄩ€旓細
1. 浠?decoded_sub.txt 璇诲彇 VLESS 鑺傜偣
2. 鎻愬彇 IP / Port / 鍘熷 VLESS
3. 浣跨敤鐪熷疄鍩熷悕 + SNI + --resolve 鍋?HTTPS 楠岃瘉
4. 鏌ヨ IP 鍦扮悊浣嶇疆锛岀粰鑺傜偣鏍囪 JP / US / HK / SG / ...
5. 鎸夊欢杩熷拰鍙敤鎬ф帓搴?6. 杈撳嚭锛?   results.csv
   usable_nodes.txt
   usable_subscription.txt   锛圔ase64 VLESS 璁㈤槄锛?   summary.txt

璇存槑锛?- HTTPS=OK 浠ｈ〃璇?IP:Port 鑳藉湪鎸囧畾 SNI 涓嬫垚鍔熷埌杈?Cloudflare銆?- 杩欎笉鏄?100% 绛夊悓浜庘€淰LESS 宸茬粡鑳戒唬鐞嗕笂缃戔€濄€?- 濡傛灉鏈哄櫒瀹夎浜?xray.exe锛屽彲鍦ㄥ悗缁増鏈鍔犵湡姝ｇ殑 VLESS 浠ｇ悊瀹炴祴銆?"""

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
# 閰嶇疆
# =========================

SUB_FILE = Path("decoded_sub.txt")
DOMAIN = "diaoyong.smil1ng.dpdns.org"

# 姣忎釜鍦板尯鏈€澶氫繚鐣欏灏戜釜鑺傜偣锛? = 涓嶉檺鍒?TOP_PER_REGION = 3

# 骞跺彂鏁?WORKERS = 12

# curl 瓒呮椂
CONNECT_TIMEOUT = 8
MAX_TIME = 12

# 鍙湁 HTTP 鎴愬姛鎵嶇畻 HTTPS_OK
ACCEPT_HTTP = {200, 204, 301, 302, 400, 403, 404}

# 鏄惁鍙繚鐣?Cloudflare
REQUIRE_CLOUDFLARE = True

# =========================
# 鍦板尯鍚嶇О
# =========================

COUNTRY_MAP = {
    "JP": "鏃ユ湰",
    "US": "缇庡浗",
    "HK": "棣欐腐",
    "SG": "鏂板姞鍧?,
    "KR": "闊╁浗",
    "TW": "鍙版咕",
    "CN": "涓浗",
    "GB": "鑻卞浗",
    "DE": "寰峰浗",
    "NL": "鑽峰叞",
    "FR": "娉曞浗",
    "CA": "鍔犳嬁澶?,
    "AU": "婢冲ぇ鍒╀簹",
    "IN": "鍗板害",
    "RU": "淇勭綏鏂?,
    "TR": "鍦熻€冲叾",
    "SE": "鐟炲吀",
    "FI": "鑺叞",
    "PL": "娉㈠叞",
    "IT": "鎰忓ぇ鍒?,
    "ES": "瑗跨彮鐗?,
}

# =========================
# 宸ュ叿
# =========================

def log(msg):
    print(msg, flush=True)


def parse_vless_file(path):
    nodes = []

    if not path.exists():
        raise FileNotFoundError(f"鎵句笉鍒?{path.resolve()}")

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue

        m = re.search(r"@(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
        if not m:
            continue

        ip = m.group(1)
        port = int(m.group(2))

        # 鍘婚噸锛屼絾淇濈暀绗竴娆″嚭鐜扮殑瀹屾暣 VLESS
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
    浣跨敤 curl锛?      --noproxy "*"
      --resolve DOMAIN:PORT:IP
      https://DOMAIN:PORT/

    杩欐牱娴嬭瘯涓嶄細鍙楀埌 Windows 褰撳墠浠ｇ悊璁剧疆褰卞搷銆?    """

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
            "error": "" if ok else "HTTPS楠岃瘉澶辫触",
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
    ip-api.com 鎵归噺鏌ヨ锛屾渶澶氫竴娆?100 涓?IP銆?    杩斿洖锛?      countryCode / country / city / regionName / org / as
    """
    if not ips:
        return {}

    result = {}

    # ip-api batch 鍗曟鏈€澶?100
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
            log(f"[GeoIP] 鎵归噺鏌ヨ澶辫触: {e}")

    return result


def region_name(code):
    return COUNTRY_MAP.get(code, code or "??")


def make_vless(line, ip, port, region_code):
    """
    鍙浛鎹?endpoint IP:Port銆?    淇濈暀 UUID銆乀LS銆乄S銆丼NI銆乸ath銆乭ost 绛夊叏閮ㄥ師鍙傛暟銆?    鍚屾椂鎶婅妭鐐瑰悕绉版敼鎴愶細
      JP-01
      US-02
    """
    new_line = re.sub(
        r"@(\d{1,3}(?:\.\d{1,3}){3}):\d+",
        f"@{ip}:{port}",
        line,
        count=1,
    )

    # 鍘绘帀鏃?fragment
    if "#" in new_line:
        new_line = new_line.split("#", 1)[0]

    return f"{new_line}#{region_code}"


def score(row):
    """
    褰撳墠璇勫垎鍙敤浜庢帓搴忥紝涓嶄唬琛ㄧ湡瀹炰唬鐞嗚川閲忋€?    HTTPS OK 鏄‖闂ㄦ銆?    """
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
        print("閿欒锛氭壘涓嶅埌 curl.exe")
        print("Windows 10/11 閫氬父鑷甫 curl.exe銆?)
        sys.exit(1)

    nodes = parse_vless_file(SUB_FILE)

    print(f"鍙戠幇 VLESS 鑺傜偣: {len(nodes)}")

    if not nodes:
        print("娌℃湁鎵惧埌鍙В鏋愮殑 vless:// 鑺傜偣銆?)
        sys.exit(1)

    # 鍏堝仛 HTTPS/SNI
    print()
    print("[1/3] HTTPS + SNI 鎵归噺楠岃瘉")
    print(f"鍩熷悕: {DOMAIN}")
    print(f"骞跺彂: {WORKERS}")
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
    print("[2/3] GeoIP 鍦板尯璇嗗埆")

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

    # 鎺掑簭
    results.sort(
        key=lambda r: (
            not r["https_ok"],
            -r["score"],
            r["latency_ms"],
        )
    )

    write_csv(results)

    # 鍙繚鐣?HTTPS 鍙敤
    usable = [r for r in results if r["https_ok"]]

    # 姣忎釜鍦板尯 Top N
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

    # 鑺傜偣鏂囨湰
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

    # 鎽樿
    summary = []
    summary.append("AutoCF Scanner V4 Result")
    summary.append("=" * 60)
    summary.append(f"杈撳叆鑺傜偣: {len(results)}")
    summary.append(f"HTTPS鍙敤: {len(usable)}")
    summary.append(f"鏈€缁堜繚鐣? {len(selected)}")
    summary.append("")

    summary.append("鍦板尯缁熻")
    summary.append("-" * 60)

    for region, count in sorted(region_counts.items()):
        summary.append(
            f"{region:4} {region_name(region):8} {count:3} nodes"
        )

    summary.append("")
    summary.append("鏈€缁堣妭鐐?)
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

    # 鎺у埗鍙拌緭鍑?    print()
    print("[3/3] 瀹屾垚")
    print()
    print("=" * 72)
    print(f"HTTPS 鍙敤: {len(usable)} / {len(results)}")
    print(f"鏈€缁堜繚鐣?   {len(selected)}")
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
    print("杈撳嚭鏂囦欢锛?)
    print("  results.csv")
    print("  usable_nodes.txt")
    print("  usable_subscription.txt")
    print("  summary.txt")


def shutil_which(name):
    """
    涓嶉澶栦緷璧?shutil锛屽吋瀹圭洿鎺ヨ繍琛屻€?    """
    import shutil
    return shutil.which(name)


if __name__ == "__main__":
    main()


