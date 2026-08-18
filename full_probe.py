import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from cf_probe import probe


BASE_DIR = Path(__file__).resolve().parent

CANDIDATE_FILE = (
    BASE_DIR
    / "data"
    / "cloudflare_candidates.txt"
)

RESULT_FILE = (
    BASE_DIR
    / "results"
    / "full_probe.json"
)

RESULT_FILE.parent.mkdir(
    exist_ok=True
)


# ============================================================
# 参数
# ============================================================

MAX_WORKERS = 20

TIMEOUT = 3


# ============================================================
# 地区
# ============================================================

JP = {
    "NRT",
    "KIX",
    "HND",
    "ITM",
    "NGO",
    "FUK",
    "CTS",
    "OKA",
}

SG = {
    "SIN",
}

HK = {
    "HKG",
}

US = {
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
}


def get_region(colo):

    if not colo:
        return None

    colo = colo.upper()

    if colo in JP:
        return "JP"

    if colo in SG:
        return "SG"

    if colo in HK:
        return "HK"

    if colo in US:
        return "US"

    return None


def load_ips():

    with open(
        CANDIDATE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        return list(
            dict.fromkeys(
                x.strip()
                for x in f
                if x.strip()
            )
        )


def test_ip(ip):

    result = probe(
        ip=ip,
        host="cloudflare.com",
        timeout=TIMEOUT,
    )

    result["region"] = get_region(
        result.get("colo")
    )

    return result


def main():

    print()
    print("=" * 70)
    print("AutoCF 全量 Cloudflare IP 探测")
    print("=" * 70)

    ips = load_ips()

    print(
        f"候选 IP：{len(ips)}"
    )

    print(
        f"并发数：{MAX_WORKERS}"
    )

    print()

    results = []

    start = time.perf_counter()

    completed = 0

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                test_ip,
                ip
            ): ip
            for ip in ips
        }

        for future in as_completed(
            futures
        ):

            ip = futures[future]

            try:

                result = future.result()

            except Exception as e:

                result = {
                    "ip": ip,
                    "ok": False,
                    "error": (
                        f"{type(e).__name__}: {e}"
                    ),
                    "region": None,
                }

            results.append(
                result
            )

            completed += 1

            if result.get("ok"):

                print(
                    f"[{completed}/{len(ips)}] "
                    f"✓ {ip} "
                    f"| "
                    f"{result.get('colo')} "
                    f"| "
                    f"{result.get('tcp_ms')}ms "
                    f"| "
                    f"{result.get('http_ms')}ms"
                )

            else:

                print(
                    f"[{completed}/{len(ips)}] "
                    f"× {ip}"
                )

    elapsed = (
        time.perf_counter()
        - start
    )

    # ========================================================
    # 保存
    # ========================================================

    with open(
        RESULT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            ensure_ascii=False,
            indent=2
        )

    # ========================================================
    # 统计
    # ========================================================

    success = [
        r
        for r in results
        if r.get("ok")
    ]

    print()
    print("=" * 70)
    print("扫描完成")
    print("=" * 70)

    print(
        f"总数：{len(ips)}"
    )

    print(
        f"成功：{len(success)}"
    )

    print(
        f"失败："
        f"{len(ips) - len(success)}"
    )

    print(
        f"耗时：{elapsed:.1f} 秒"
    )

    print()

    # ========================================================
    # 地区统计
    # ========================================================

    regions = {
        "JP": [],
        "SG": [],
        "HK": [],
        "US": [],
        "OTHER": [],
    }

    for r in success:

        region = r.get(
            "region"
        )

        if region in regions:

            regions[
                region
            ].append(r)

        else:

            regions[
                "OTHER"
            ].append(r)

    print("=" * 70)
    print("地区统计")
    print("=" * 70)

    for region, items in regions.items():

        print(
            f"{region}: "
            f"{len(items)}"
        )

    print()

    print(
        f"结果文件：{RESULT_FILE}"
    )

    print()


if __name__ == "__main__":

    main()