import asyncio
import json
import ssl
import time
from pathlib import Path

import yaml


BASE_DIR = Path(__file__).resolve().parent

CONFIG_FILE = BASE_DIR / "config.yaml"

CANDIDATE_FILE = (
    BASE_DIR
    / "data"
    / "cloudflare_candidates.txt"
)

RESULT_FILE = (
    BASE_DIR
    / "results"
    / "scanner_v3.json"
)


# ============================================================
# 配置
# ============================================================

def load_config():

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        return yaml.safe_load(f)


# ============================================================
# 候选 IP
# ============================================================

def load_candidates():

    if not CANDIDATE_FILE.exists():

        raise FileNotFoundError(
            f"找不到候选池：{CANDIDATE_FILE}"
        )

    with open(
        CANDIDATE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        ips = [
            line.strip()
            for line in f
            if line.strip()
        ]

    return list(
        dict.fromkeys(ips)
    )


# ============================================================
# 地区映射
# ============================================================

def build_region_map(config):

    regions = {}

    for region_code, info in config.get(
        "regions",
        {}
    ).items():

        for colo in info.get(
            "colos",
            []
        ):

            regions[
                colo.upper()
            ] = region_code.upper()

    return regions


# ============================================================
# TCP
# ============================================================

async def tcp_connect(
    ip,
    port,
    timeout
):

    start = time.perf_counter()

    try:

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
            ),
            timeout=timeout,
        )

        elapsed = (
            time.perf_counter()
            - start
        ) * 1000

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        return round(
            elapsed,
            2
        )

    except Exception:

        return None


# ============================================================
# HTTPS
#
# 关键：
# TCP 连接目标 = IP
# TLS SNI       = cloudflare.com
# HTTP Host     = cloudflare.com
#
# 这是 Cloudflare IP 优选必须的方式。
# ============================================================

async def https_probe(
    ip,
    host,
    port,
    timeout
):

    start = time.perf_counter()

    ssl_context = ssl.create_default_context()

    try:

        reader, writer = await asyncio.wait_for(

            asyncio.open_connection(

                host=ip,

                port=port,

                ssl=ssl_context,

                server_hostname=host,

            ),

            timeout=timeout,
        )

        request = (
            f"GET /cdn-cgi/trace HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: AutoCF-V3\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        writer.write(
            request.encode(
                "ascii"
            )
        )

        await asyncio.wait_for(
            writer.drain(),
            timeout=timeout,
        )

        data = b""

        while True:

            try:

                chunk = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=timeout,
                )

            except asyncio.TimeoutError:

                break

            if not chunk:
                break

            data += chunk

            if len(data) > 65536:
                break

        elapsed = (
            time.perf_counter()
            - start
        ) * 1000

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        text = data.decode(
            "utf-8",
            errors="ignore"
        )

        # ----------------------------------------------------
        # HTTP 状态
        # ----------------------------------------------------

        status = None

        first_line = (
            text.splitlines()[0]
            if text.splitlines()
            else ""
        )

        parts = first_line.split()

        if (
            len(parts) >= 2
            and parts[0].startswith("HTTP/")
        ):

            try:

                status = int(
                    parts[1]
                )

            except ValueError:

                pass

        # ----------------------------------------------------
        # Cloudflare trace
        # ----------------------------------------------------

        colo = None
        loc = None

        for line in text.splitlines():

            line = line.strip()

            if line.startswith(
                "colo="
            ):

                colo = (
                    line.split(
                        "=",
                        1
                    )[1]
                    .strip()
                )

            elif line.startswith(
                "loc="
            ):

                loc = (
                    line.split(
                        "=",
                        1
                    )[1]
                    .strip()
                )

        return {
            "ok": (
                status == 200
                and colo is not None
            ),
            "http_ms": round(
                elapsed,
                2
            ),
            "status": status,
            "colo": colo,
            "loc": loc,
            "error": None,
        }

    except Exception as e:

        return {
            "ok": False,
            "http_ms": None,
            "status": None,
            "colo": None,
            "loc": None,
            "error": (
                type(e).__name__
                + ": "
                + str(e)
            ),
        }


# ============================================================
# 单 IP
# ============================================================

async def probe_one(
    ip,
    host,
    port,
    timeout,
    semaphore,
    region_map,
):

    async with semaphore:

        result = {
            "ip": ip,
            "ok": False,
            "tcp_ms": None,
            "http_ms": None,
            "status": None,
            "colo": None,
            "loc": None,
            "region": "OTHER",
            "error": None,
        }

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        tcp_ms = await tcp_connect(
            ip,
            port,
            timeout,
        )

        if tcp_ms is None:

            result["error"] = (
                "TCP connection failed"
            )

            return result

        result["tcp_ms"] = tcp_ms

        # ----------------------------------------------------
        # HTTPS + SNI
        # ----------------------------------------------------

        http_result = await https_probe(
            ip,
            host,
            port,
            timeout,
        )

        result["http_ms"] = (
            http_result["http_ms"]
        )

        result["status"] = (
            http_result["status"]
        )

        result["colo"] = (
            http_result["colo"]
        )

        result["loc"] = (
            http_result["loc"]
        )

        result["error"] = (
            http_result["error"]
        )

        if not http_result["ok"]:

            return result

        # ----------------------------------------------------
        # 地区
        # ----------------------------------------------------

        colo = (
            result["colo"]
            or ""
        ).upper()

        result["region"] = (
            region_map.get(
                colo,
                "OTHER"
            )
        )

        result["ok"] = True

        return result


# ============================================================
# 扫描
# ============================================================

async def scan_all(
    candidates,
    config,
):

    candidate_config = config.get(
        "candidate_pool",
        {}
    )

    probe_config = config.get(
        "probe",
        {}
    )

    workers = int(
        candidate_config.get(
            "probe_workers",
            30
        )
    )

    timeout = float(
        candidate_config.get(
            "probe_timeout",
            3
        )
    )

    host = probe_config.get(
        "host",
        "cloudflare.com"
    )

    port = int(
        probe_config.get(
            "port",
            443
        )
    )

    region_map = build_region_map(
        config
    )

    semaphore = asyncio.Semaphore(
        workers
    )

    total = len(
        candidates
    )

    print()
    print("=" * 70)
    print("AutoCF Scanner V3")
    print("=" * 70)

    print(
        f"候选 IP：{total}"
    )

    print(
        f"并发：{workers}"
    )

    print(
        f"超时：{timeout}s"
    )

    print(
        f"TLS SNI：{host}"
    )

    print(
        f"HTTP Host：{host}"
    )

    print()

    start_time = time.perf_counter()

    tasks = [
        asyncio.create_task(
            probe_one(
                ip,
                host,
                port,
                timeout,
                semaphore,
                region_map,
            )
        )
        for ip in candidates
    ]

    results = []

    for index, task in enumerate(
        asyncio.as_completed(tasks),
        start=1,
    ):

        result = await task

        results.append(
            result
        )

        if result["ok"]:

            print(
                f"[{index}/{total}] ✓ "
                f"{result['ip']} "
                f"| {result['colo']} "
                f"| {result['region']} "
                f"| TCP={result['tcp_ms']}ms "
                f"| HTTP={result['http_ms']}ms"
            )

        else:

            print(
                f"[{index}/{total}] × "
                f"{result['ip']}"
            )

    elapsed = (
        time.perf_counter()
        - start_time
    )

    return results, elapsed


# ============================================================
# 保存
# ============================================================

def save_results(
    results
):

    RESULT_FILE.parent.mkdir(
        exist_ok=True
    )

    with open(
        RESULT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            ensure_ascii=False,
            indent=2,
        )

    print()
    print(
        f"结果文件：{RESULT_FILE}"
    )


# ============================================================
# 统计
# ============================================================

def print_summary(
    results,
    elapsed,
):

    print()
    print("=" * 70)
    print("扫描完成")
    print("=" * 70)

    total = len(
        results
    )

    success = sum(
        1
        for x in results
        if x.get("ok")
    )

    print(
        f"总数：{total}"
    )

    print(
        f"成功：{success}"
    )

    print(
        f"失败：{total - success}"
    )

    print(
        f"耗时：{elapsed:.1f} 秒"
    )

    print()
    print("=" * 70)
    print("地区统计")
    print("=" * 70)

    regions = {
        "JP": 0,
        "SG": 0,
        "HK": 0,
        "US": 0,
        "OTHER": 0,
    }

    for result in results:

        if not result.get("ok"):
            continue

        region = result.get(
            "region",
            "OTHER"
        )

        if region not in regions:

            region = "OTHER"

        regions[region] += 1

    for region, count in regions.items():

        print(
            f"{region}: {count}"
        )


# ============================================================
# 主程序
# ============================================================

async def main_async():

    config = load_config()

    candidates = load_candidates()

    if not candidates:

        raise RuntimeError(
            "候选池为空"
        )

    results, elapsed = await scan_all(
        candidates,
        config,
    )

    save_results(
        results
    )

    print_summary(
        results,
        elapsed,
    )


def main():

    try:

        asyncio.run(
            main_async()
        )

    except KeyboardInterrupt:

        print()
        print(
            "用户中止扫描"
        )

    except Exception as e:

        print()
        print(
            "程序错误："
        )

        print(
            f"{type(e).__name__}: {e}"
        )


if __name__ == "__main__":

    main()