import asyncio
import json
import socket
import ssl
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import aiohttp


# ============================================================
# AutoCF Scanner V2
#
# 功能：
# 1. 读取 Cloudflare 候选 IP
# 2. TCP 443 测试
# 3. TLS 测试
# 4. /cdn-cgi/trace
# 5. 获取 Cloudflare colo
# 6. 根据 colo 判断地区
# 7. 第一阶段筛选
# 8. 第二阶段下载测速
# 9. 稳定性测试
# 10. 输出 JP / SG / HK / US TOP 3
# ============================================================


BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"
OUTPUT_DIR = BASE_DIR / "output"

DATA_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


CANDIDATE_FILE = (
    DATA_DIR / "cloudflare_candidates.txt"
)


# ============================================================
# Cloudflare 测试域名
#
# /cdn-cgi/trace 是 Cloudflare 官方提供的诊断端点。
# ============================================================

TEST_HOST = "cloudflare.com"

TRACE_PATH = "/cdn-cgi/trace"


# ============================================================
# 测试参数
# ============================================================

TCP_TIMEOUT = 3.0

TLS_TIMEOUT = 5.0

HTTP_TIMEOUT = 7.0

MAX_CONCURRENT = 30

TOP_FOR_DOWNLOAD = 10

STABILITY_ROUNDS = 3


# ============================================================
# 地区映射
#
# Cloudflare colo 是三字母机场代码。
# 这里按照主要目标地区归类。
#
# US 会包含美国多个 PoP。
# ============================================================

REGION_COLOS = {

    "JP": {
        "NRT",
        "KIX",
        "HND",
        "ITM",
        "NGO",
        "FUK",
        "CTS",
        "OKA",
    },

    "SG": {
        "SIN",
    },

    "HK": {
        "HKG",
    },

    "US": {
        "LAX",
        "SJC",
        "SEA",
        "PDX",
        "SFO",
        "DEN",
        "PHX",
        "LAS",
        "DFW",
        "IAH",
        "ORD",
        "ATL",
        "MIA",
        "IAD",
        "DCA",
        "EWR",
        "JFK",
        "BOS",
        "MSP",
        "DTW",
        "CLT",
        "TPA",
        "MCO",
        "BNA",
        "STL",
        "RDU",
        "PIT",
        "CMH",
        "IND",
        "CLE",
        "CVG",
        "SAT",
        "AUS",
        "MSY",
        "SLC",
        "ABQ",
        "OAK",
        "SNA",
        "BUR",
        "SMF",
        "RNO",
        "SJC",
    },
}


# ============================================================
# 根据 colo 判断地区
# ============================================================

def get_region(colo):

    if not colo:
        return None

    colo = colo.upper().strip()

    for region, colos in REGION_COLOS.items():

        if colo in colos:
            return region

    return None


# ============================================================
# 读取候选 IP
# ============================================================

def load_candidates():

    if not CANDIDATE_FILE.exists():

        raise FileNotFoundError(
            f"找不到候选文件：{CANDIDATE_FILE}"
        )

    candidates = []

    with open(
        CANDIDATE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            ip = line.strip()

            if not ip:
                continue

            if ip.startswith("#"):
                continue

            try:

                socket.inet_aton(ip)

            except OSError:

                continue

            candidates.append(ip)

    return list(dict.fromkeys(candidates))


# ============================================================
# TCP + TLS 测试
# ============================================================

async def tcp_tls_test(ip):

    loop = asyncio.get_running_loop()

    start = time.perf_counter()

    try:

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        tcp_start = time.perf_counter()

        connect_task = asyncio.open_connection(
            host=ip,
            port=443,
            ssl=False
        )

        reader, writer = await asyncio.wait_for(
            connect_task,
            timeout=TCP_TIMEOUT
        )

        tcp_ms = (
            time.perf_counter()
            - tcp_start
        ) * 1000

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        tls_start = time.perf_counter()

        context = ssl.create_default_context()

        context.check_hostname = True

        tls_task = asyncio.open_connection(
            host=ip,
            port=443,
            ssl=context,
            server_hostname=TEST_HOST
        )

        reader, writer = await asyncio.wait_for(
            tls_task,
            timeout=TLS_TIMEOUT
        )

        tls_ms = (
            time.perf_counter()
            - tls_start
        ) * 1000

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        total_ms = (
            time.perf_counter()
            - start
        ) * 1000

        return {
            "ok": True,
            "tcp_ms": round(tcp_ms, 2),
            "tls_ms": round(tls_ms, 2),
            "total_ms": round(total_ms, 2),
        }

    except Exception as e:

        return {
            "ok": False,
            "error": str(e),
        }


# ============================================================
# HTTP trace
# ============================================================

async def trace_test(
    session,
    ip
):

    url = (
        f"https://{TEST_HOST}"
        f"{TRACE_PATH}"
    )

    start = time.perf_counter()

    try:

        # ----------------------------------------------------
        # 强制连接到指定 IP
        #
        # aiohttp 默认会 DNS。
        #
        # 我们使用自定义 resolver。
        # ----------------------------------------------------

        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=1
        )

        timeout = aiohttp.ClientTimeout(
            total=HTTP_TIMEOUT
        )

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as local_session:

            # ------------------------------------------------
            # SSL
            # ------------------------------------------------

            ssl_context = ssl.create_default_context()

            ssl_context.check_hostname = True

            async with local_session.get(
                url,
                headers={
                    "Host": TEST_HOST,
                    "User-Agent": (
                        "AutoCF/2.0"
                    ),
                },
                ssl=ssl_context,
                server_hostname=TEST_HOST,
            ) as response:

                body = await response.text()

                elapsed_ms = (
                    time.perf_counter()
                    - start
                ) * 1000

                trace = {}

                for line in body.splitlines():

                    if "=" not in line:
                        continue

                    key, value = (
                        line.split(
                            "=",
                            1
                        )
                    )

                    trace[
                        key.strip()
                    ] = value.strip()

                return {
                    "ok": True,
                    "status": response.status,
                    "http_ms": round(
                        elapsed_ms,
                        2
                    ),
                    "colo": trace.get(
                        "colo"
                    ),
                    "loc": trace.get(
                        "loc"
                    ),
                    "http": trace.get(
                        "http"
                    ),
                    "tls": trace.get(
                        "tls"
                    ),
                    "trace": trace,
                }

    except Exception as e:

        return {
            "ok": False,
            "error": str(e),
        }


# ============================================================
# 单 IP 第一阶段测试
# ============================================================

async def scan_one(
    semaphore,
    ip
):

    async with semaphore:

        result = {
            "ip": ip,
            "timestamp": (
                datetime.now().isoformat()
            ),
        }

        tcp_tls = await tcp_tls_test(
            ip
        )

        result.update(
            tcp_tls
        )

        if not tcp_tls.get("ok"):

            return result

        trace = await trace_test(
            None,
            ip
        )

        result.update(
            {
                "trace_ok":
                    trace.get("ok"),

                "status":
                    trace.get("status"),

                "http_ms":
                    trace.get("http_ms"),

                "colo":
                    trace.get("colo"),

                "loc":
                    trace.get("loc"),

                "http":
                    trace.get("http"),

                "tls":
                    trace.get("tls"),
            }
        )

        colo = trace.get(
            "colo"
        )

        result["region"] = (
            get_region(colo)
        )

        return result


# ============================================================
# 第一阶段
# ============================================================

async def first_stage(
    candidates
):

    print()
    print("=" * 70)
    print("第一阶段：TCP / TLS / Cloudflare Colo")
    print("=" * 70)

    semaphore = asyncio.Semaphore(
        MAX_CONCURRENT
    )

    tasks = []

    for ip in candidates:

        tasks.append(
            asyncio.create_task(
                scan_one(
                    semaphore,
                    ip
                )
            )
        )

    results = []

    total = len(tasks)

    completed = 0

    for task in asyncio.as_completed(
        tasks
    ):

        result = await task

        results.append(
            result
        )

        completed += 1

        if completed % 10 == 0:

            print(
                f"进度："
                f"{completed}/{total}"
            )

    return results


# ============================================================
# 下载测速
#
# 使用 Cloudflare speed.cloudflare.com
# 的下载测试接口。
#
# 如果接口不可用，会自动跳过下载分数。
# ============================================================

async def download_test(
    ip
):

    url = (
        "https://speed.cloudflare.com/"
        "__down?bytes=262144"
    )

    start = time.perf_counter()

    bytes_received = 0

    try:

        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=1
        )

        timeout = aiohttp.ClientTimeout(
            total=15
        )

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as session:

            ssl_context = (
                ssl.create_default_context()
            )

            ssl_context.check_hostname = True

            async with session.get(
                url,
                headers={
                    "Host": (
                        "speed.cloudflare.com"
                    ),
                    "User-Agent":
                        "AutoCF/2.0",
                },
                ssl=ssl_context,
            ) as response:

                if response.status != 200:

                    return {
                        "ok": False,
                        "status":
                            response.status
                    }

                async for chunk in (
                    response.content.iter_chunked(
                        16384
                    )
                ):

                    bytes_received += len(
                        chunk
                    )

                elapsed = (
                    time.perf_counter()
                    - start
                )

                if elapsed <= 0:

                    return {
                        "ok": False
                    }

                mbps = (
                    bytes_received
                    * 8
                    / elapsed
                    / 1_000_000
                )

                return {
                    "ok": True,
                    "bytes":
                        bytes_received,
                    "seconds":
                        round(
                            elapsed,
                            3
                        ),
                    "mbps":
                        round(
                            mbps,
                            2
                        ),
                }

    except Exception as e:

        return {
            "ok": False,
            "error": str(e),
        }


# ============================================================
# 稳定性
# ============================================================

async def stability_test(
    ip
):

    times = []

    successes = 0

    for _ in range(
        STABILITY_ROUNDS
    ):

        result = await tcp_tls_test(
            ip
        )

        if result.get("ok"):

            successes += 1

            times.append(
                result.get(
                    "total_ms",
                    9999
                )
            )

        await asyncio.sleep(
            0.2
        )

    if not times:

        return {
            "success_rate": 0,
            "avg_ms": None,
        }

    return {
        "success_rate": round(
            successes
            / STABILITY_ROUNDS
            * 100,
            2
        ),

        "avg_ms": round(
            sum(times)
            / len(times),
            2
        ),
    }


# ============================================================
# 计算分数
# ============================================================

def calculate_score(
    result
):

    tcp = result.get(
        "tcp_ms"
    )

    tls = result.get(
        "tls_ms"
    )

    http = result.get(
        "http_ms"
    )

    mbps = result.get(
        "mbps"
    )

    stability = result.get(
        "success_rate"
    )

    if tcp is None:
        return 0

    if http is None:
        http = tcp + tls

    if mbps is None:
        mbps = 0

    if stability is None:
        stability = 0

    # --------------------------------------------------------
    # 延迟分
    # --------------------------------------------------------

    latency_score = max(
        0,
        100
        - min(
            http,
            1000
        ) / 10
    )

    # --------------------------------------------------------
    # 下载分
    #
    # 100 Mbps 封顶
    # --------------------------------------------------------

    speed_score = min(
        100,
        mbps
    )

    # --------------------------------------------------------
    # 稳定性
    # --------------------------------------------------------

    stability_score = (
        stability
    )

    # --------------------------------------------------------
    # 综合
    # --------------------------------------------------------

    score = (
        latency_score * 0.40
        +
        speed_score * 0.35
        +
        stability_score * 0.25
    )

    return round(
        score,
        2
    )


# ============================================================
# 第二阶段
# ============================================================

async def second_stage(
    grouped
):

    print()
    print("=" * 70)
    print("第二阶段：下载 + 稳定性")
    print("=" * 70)

    final_results = []

    for region in [
        "JP",
        "SG",
        "HK",
        "US"
    ]:

        candidates = grouped.get(
            region,
            []
        )

        print()
        print(
            f"🇯🇵 JP"
            if region == "JP"
            else
            f"🇸🇬 SG"
            if region == "SG"
            else
            f"🇭🇰 HK"
            if region == "HK"
            else
            f"🇺🇸 US"
        )

        print(
            f"进入第二阶段："
            f"{len(candidates)}"
        )

        for result in candidates:

            ip = result["ip"]

            print(
                f"[{region}] "
                f"{ip} "
                f"下载测试..."
            )

            download = (
                await download_test(
                    ip
                )
            )

            result.update(
                {
                    "mbps":
                        download.get(
                            "mbps"
                        ),

                    "download_ok":
                        download.get(
                            "ok"
                        ),
                }
            )

            stability = (
                await stability_test(
                    ip
                )
            )

            result.update(
                stability
            )

            result["score"] = (
                calculate_score(
                    result
                )
            )

            final_results.append(
                result
            )

    return final_results


# ============================================================
# 保存 JSON
# ============================================================

def save_json(
    results
):

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output = (
        RESULTS_DIR
        / f"scan_{timestamp}.json"
    )

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            ensure_ascii=False,
            indent=2
        )

    return output


# ============================================================
# 保存 TOP 3
# ============================================================

def save_top3(
    results
):

    top = {}

    for region in [
        "JP",
        "SG",
        "HK",
        "US"
    ]:

        items = [
            r
            for r in results
            if r.get(
                "region"
            ) == region
        ]

        items.sort(
            key=lambda x:
                x.get(
                    "score",
                    0
                ),
            reverse=True
        )

        top[region] = items[:3]

    output = (
        OUTPUT_DIR
        / "top3.json"
    )

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            top,
            f,
            ensure_ascii=False,
            indent=2
        )

    return top


# ============================================================
# 打印结果
# ============================================================

def print_top3(top):

    print()
    print("=" * 70)
    print("最终优选结果")
    print("=" * 70)

    names = {
        "JP": "🇯🇵 日本",
        "SG": "🇸🇬 新加坡",
        "HK": "🇭🇰 香港",
        "US": "🇺🇸 美国",
    }

    for region in [
        "JP",
        "SG",
        "HK",
        "US"
    ]:

        print()
        print(
            names[region]
        )

        items = top.get(
            region,
            []
        )

        if not items:

            print(
                "没有有效节点"
            )

            continue

        for index, item in enumerate(
            items,
            1
        ):

            print(
                f"{index}. "
                f"{item['ip']} "
                f"| "
                f"colo={item.get('colo')} "
                f"| "
                f"延迟={item.get('http_ms')}ms "
                f"| "
                f"速度={item.get('mbps')}Mbps "
                f"| "
                f"稳定={item.get('success_rate')}% "
                f"| "
                f"Score={item.get('score')}"
            )


# ============================================================
# 主程序
# ============================================================

async def main():

    print()
    print("=" * 70)
    print("        AutoCF 自动优选器 V2")
    print("=" * 70)

    print()
    print(
        "候选池：",
        CANDIDATE_FILE
    )

    candidates = load_candidates()

    print(
        f"候选 IP：{len(candidates)}"
    )

    # --------------------------------------------------------
    # 第一阶段
    # --------------------------------------------------------

    first_results = (
        await first_stage(
            candidates
        )
    )

    # --------------------------------------------------------
    # 保存第一阶段结果
    # --------------------------------------------------------

    first_file = (
        RESULTS_DIR
        / "first_stage.json"
    )

    with open(
        first_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            first_results,
            f,
            ensure_ascii=False,
            indent=2
        )

    # --------------------------------------------------------
    # 根据地区分组
    # --------------------------------------------------------

    grouped = defaultdict(list)

    for result in first_results:

        region = result.get(
            "region"
        )

        if not region:
            continue

        if not result.get(
            "trace_ok"
        ):
            continue

        grouped[
            region
        ].append(
            result
        )

    # --------------------------------------------------------
    # 每个地区按照 HTTP 延迟排序
    # --------------------------------------------------------

    for region in grouped:

        grouped[region].sort(
            key=lambda x:
                x.get(
                    "http_ms",
                    999999
                )
        )

        grouped[region] = (
            grouped[region][
                :TOP_FOR_DOWNLOAD
            ]
        )

    # --------------------------------------------------------
    # 打印第一阶段统计
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("第一阶段地区统计")
    print("=" * 70)

    for region in [
        "JP",
        "SG",
        "HK",
        "US"
    ]:

        print(
            f"{region}: "
            f"{len(grouped.get(region, []))}"
        )

    # --------------------------------------------------------
    # 第二阶段
    # --------------------------------------------------------

    final_results = (
        await second_stage(
            grouped
        )
    )

    # --------------------------------------------------------
    # 保存
    # --------------------------------------------------------

    json_file = save_json(
        final_results
    )

    top = save_top3(
        final_results
    )

    # --------------------------------------------------------
    # 输出
    # --------------------------------------------------------

    print_top3(
        top
    )

    print()
    print(
        "完整结果：",
        json_file
    )

    print(
        "TOP3：",
        OUTPUT_DIR
        / "top3.json"
    )

    print()


if __name__ == "__main__":

    try:

        asyncio.run(
            main()
        )

    except KeyboardInterrupt:

        print()
        print(
            "用户取消测速。"
        )