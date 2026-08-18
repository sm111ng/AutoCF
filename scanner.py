import asyncio
import aiohttp
import json
import time
import statistics
from pathlib import Path
from datetime import datetime, timezone

import yaml


# ============================================================
# 基础路径
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.yaml"

IPS_DIR = BASE_DIR / "ips"
RESULTS_DIR = BASE_DIR / "results"
OUTPUT_DIR = BASE_DIR / "output"
LOGS_DIR = BASE_DIR / "logs"


# ============================================================
# 配置
# ============================================================

def load_config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ============================================================
# IP读取
# ============================================================

def load_ips(region):
    file_path = IPS_DIR / f"{region}.txt"

    if not file_path.exists():
        return []

    ips = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:

            ip = line.strip()

            if not ip:
                continue

            if ip.startswith("#"):
                continue

            # 去掉可能误输入的协议
            ip = ip.replace("https://", "")
            ip = ip.replace("http://", "")

            # 如果用户误写成 IP:443
            if ":" in ip and ip.count(":") == 1:
                ip = ip.split(":")[0]

            ips.append(ip)

    # 去重
    return list(dict.fromkeys(ips))


# ============================================================
# 创建目录
# ============================================================

def ensure_directories():
    RESULTS_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)


# ============================================================
# HTTP延迟测试
#
# 注意：
# 这里不是传统 ICMP ping。
#
# 我们测试的是：
#
# 你的电脑
#   ↓
# Cloudflare IP
#   ↓
# HTTPS/HTTP响应
#
# 这个结果更加接近实际代理线路的连接表现。
# ============================================================

async def latency_test(
    session,
    ip,
    timeout_seconds
):

    url = f"https://{ip}/cdn-cgi/trace"

    start = time.perf_counter()

    try:

        async with session.get(
            url,
            headers={
                "Host": "cloudflare.com",
                "User-Agent": "AutoCF-Optimizer/1.0"
            },
            ssl=False,
            timeout=aiohttp.ClientTimeout(
                total=timeout_seconds
            )
        ) as response:

            await response.read()

            elapsed = (
                time.perf_counter() - start
            ) * 1000

            if response.status >= 500:
                return None

            return round(elapsed, 2)

    except Exception:
        return None


# ============================================================
# 下载测速
#
# 使用 Cloudflare speed test endpoint。
#
# 每个IP只做一次下载测试，避免大量消耗流量。
# ============================================================

async def download_test(
    session,
    ip,
    timeout_seconds,
    download_bytes
):

    url = (
        f"https://{ip}/__down"
        f"?bytes={download_bytes}"
    )

    start = time.perf_counter()

    total_bytes = 0

    try:

        async with session.get(
            url,
            headers={
                "Host": "speed.cloudflare.com",
                "User-Agent": "AutoCF-Optimizer/1.0"
            },
            ssl=False,
            timeout=aiohttp.ClientTimeout(
                total=timeout_seconds
            )
        ) as response:

            if response.status >= 400:
                return None

            async for chunk in response.content.iter_chunked(65536):

                total_bytes += len(chunk)

            elapsed = time.perf_counter() - start

            if elapsed <= 0:
                return None

            # Bytes/s → Mbps
            mbps = (
                total_bytes * 8
                / elapsed
                / 1_000_000
            )

            return round(mbps, 2)

    except Exception:
        return None


# ============================================================
# 单个IP完整测试
# ============================================================

async def test_ip(
    session,
    ip,
    config
):

    settings = config["settings"]

    rounds = settings["test_rounds"]
    timeout_seconds = settings["timeout_seconds"]
    download_bytes = settings["download_bytes"]

    latency_results = []

    # --------------------------------------------------------
    # 延迟测试
    # --------------------------------------------------------

    for _ in range(rounds):

        latency = await latency_test(
            session,
            ip,
            timeout_seconds
        )

        if latency is not None:
            latency_results.append(latency)

        # 防止连续请求过于密集
        await asyncio.sleep(0.15)

    # 完全无法连接
    if not latency_results:

        return {
            "ip": ip,
            "success": False,
            "latency_ms": None,
            "download_mbps": None,
            "stability": 0,
            "success_rate": 0
        }

    # --------------------------------------------------------
    # 延迟统计
    # --------------------------------------------------------

    avg_latency = statistics.mean(
        latency_results
    )

    min_latency = min(
        latency_results
    )

    max_latency = max(
        latency_results
    )

    success_rate = (
        len(latency_results)
        / rounds
    )

    # --------------------------------------------------------
    # 稳定性
    #
    # 100%成功 + 延迟波动小 = 高稳定性
    # --------------------------------------------------------

    if len(latency_results) >= 2:

        stdev = statistics.pstdev(
            latency_results
        )

    else:

        stdev = avg_latency

    # 波动越小越好
    variation_score = max(
        0,
        100 - stdev * 2
    )

    stability = (
        success_rate * 70
        + variation_score * 0.30
    )

    stability = min(
        100,
        stability
    )

    # --------------------------------------------------------
    # 下载测试
    # --------------------------------------------------------

    download_mbps = await download_test(
        session,
        ip,
        timeout_seconds,
        download_bytes
    )

    return {
        "ip": ip,
        "success": True,

        "latency_ms": round(
            avg_latency,
            2
        ),

        "min_latency_ms": round(
            min_latency,
            2
        ),

        "max_latency_ms": round(
            max_latency,
            2
        ),

        "download_mbps": download_mbps,

        "stability": round(
            stability,
            2
        ),

        "success_rate": round(
            success_rate * 100,
            2
        ),

        "latency_samples": latency_results
    }


# ============================================================
# 并发测试
# ============================================================

async def scan_region(
    region,
    ips,
    config
):

    settings = config["settings"]

    concurrency = settings["concurrency"]

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        ssl=False
    )

    timeout = aiohttp.ClientTimeout(
        total=settings["timeout_seconds"]
    )

    semaphore = asyncio.Semaphore(
        concurrency
    )

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout
    ) as session:

        async def worker(ip):

            async with semaphore:

                print(
                    f"[{region.upper()}] "
                    f"测试 {ip}"
                )

                result = await test_ip(
                    session,
                    ip,
                    config
                )

                return result

        tasks = [
            worker(ip)
            for ip in ips
        ]

        results = await asyncio.gather(
            *tasks
        )

    return results


# ============================================================
# 评分
# ============================================================

def calculate_scores(results, config):

    settings = config["settings"]

    weights = settings["weights"]

    min_speed = settings[
        "min_download_mbps"
    ]

    valid = []

    for item in results:

        if not item["success"]:
            continue

        speed = item["download_mbps"]

        if speed is None:
            continue

        # 最低速度过滤
        if speed < min_speed:
            continue

        valid.append(item)

    if not valid:
        return []

    # --------------------------------------------------------
    # 延迟分数
    #
    # 当前地区内部进行归一化
    # --------------------------------------------------------

    latencies = [
        x["latency_ms"]
        for x in valid
    ]

    speeds = [
        x["download_mbps"]
        for x in valid
    ]

    min_latency = min(latencies)
    max_latency = max(latencies)

    min_speed = min(speeds)
    max_speed = max(speeds)

    for item in valid:

        latency = item["latency_ms"]
        speed = item["download_mbps"]
        stability = item["stability"]

        # 延迟分数
        if max_latency == min_latency:

            latency_score = 100

        else:

            latency_score = (
                (max_latency - latency)
                /
                (max_latency - min_latency)
                * 100
            )

        # 下载速度分数
        if max_speed == min_speed:

            download_score = 100

        else:

            download_score = (
                (speed - min_speed)
                /
                (max_speed - min_speed)
                * 100
            )

        # 综合评分
        score = (
            latency_score
            * weights["latency"]
            +
            download_score
            * weights["download"]
            +
            stability
            * weights["stability"]
        )

        item["latency_score"] = round(
            latency_score,
            2
        )

        item["download_score"] = round(
            download_score,
            2
        )

        item["score"] = round(
            score,
            2
        )

    valid.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return valid


# ============================================================
# 保存JSON
# ============================================================

def save_json(
    region,
    results,
    config
):

    now = datetime.now(
        timezone.utc
    ).isoformat()

    data = {

        "region": region,

        "updated_at": now,

        "top_nodes": config[
            "settings"
        ]["top_nodes"],

        "nodes": results
    }

    file_path = (
        RESULTS_DIR
        / f"{region}.json"
    )

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2
        )

    return file_path


# ============================================================
# 保存简单IP列表
#
# 后面给 Cloudflare / EdgeTunnel 使用
# ============================================================

def save_output(
    region,
    results,
    config
):

    top_nodes = config[
        "settings"
    ]["top_nodes"]

    selected = results[
        :top_nodes
    ]

    file_path = (
        OUTPUT_DIR
        / f"{region}.txt"
    )

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:

        for item in selected:

            f.write(
                item["ip"]
                + "\n"
            )

    return selected


# ============================================================
# 主程序
# ============================================================

async def main():

    ensure_directories()

    config = load_config()

    print()
    print("=" * 70)
    print("        AutoCF 自动优选器")
    print("=" * 70)
    print()

    print(
        "测速时间：北京时间每天 01:00"
    )

    print(
        "每地区 TOP：",
        config["settings"]["top_nodes"]
    )

    print()

    for region, region_config in config["regions"].items():

        print()
        print("=" * 70)
        print(
            f"开始测试 "
            f"{region_config['name']}"
        )
        print("=" * 70)

        ips = load_ips(region)

        print(
            f"候选IP：{len(ips)}"
        )

        if not ips:

            print(
                "没有候选IP，跳过。"
            )

            continue

        start_time = time.perf_counter()

        raw_results = await scan_region(
            region,
            ips,
            config
        )

        scored_results = calculate_scores(
            raw_results,
            config
        )

        elapsed = (
            time.perf_counter()
            - start_time
        )

        save_json(
            region,
            scored_results,
            config
        )

        selected = save_output(
            region,
            scored_results,
            config
        )

        print()
        print(
            f"{region_config['name']} "
            f"测速完成"
        )

        print(
            f"耗时：{elapsed:.1f} 秒"
        )

        print(
            f"有效节点："
            f"{len(scored_results)}"
        )

        print()

        if not selected:

            print(
                "没有IP达到最低质量要求。"
            )

        else:

            print(
                "TOP 节点："
            )

            for index, item in enumerate(
                selected,
                start=1
            ):

                print(
                    f"{index}. "
                    f"{item['ip']} | "
                    f"{item['latency_ms']} ms | "
                    f"{item['download_mbps']} Mbps | "
                    f"稳定性 {item['stability']} | "
                    f"Score {item['score']}"
                )

    print()
    print("=" * 70)
    print("全部地区测速完成")
    print("=" * 70)
    print()

    print(
        "结果目录：",
        RESULTS_DIR
    )

    print(
        "优选IP目录：",
        OUTPUT_DIR
    )


if __name__ == "__main__":

    try:

        asyncio.run(main())

    except KeyboardInterrupt:

        print()
        print(
            "用户中断测速。"
        )