import sys
import time

from cf_probe import probe


CANDIDATE_FILE = (
    "data/cloudflare_candidates.txt"
)

TEST_COUNT = 10


def main():

    with open(
        CANDIDATE_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        ips = [
            x.strip()
            for x in f
            if x.strip()
        ]

    ips = ips[:TEST_COUNT]

    print()
    print("=" * 70)
    print("AutoCF 快速 IP 探测")
    print("=" * 70)

    print(
        f"测试数量：{len(ips)}"
    )

    print()

    success = []

    for index, ip in enumerate(
        ips,
        1
    ):

        print(
            f"[{index}/{len(ips)}] "
            f"{ip}"
        )

        result = probe(
            ip=ip,
            host="cloudflare.com",
            timeout=3,
        )

        if result["ok"]:

            print(
                f"  ✓ "
                f"colo={result['colo']} "
                f"loc={result['loc']} "
                f"tcp={result['tcp_ms']}ms "
                f"http={result['http_ms']}ms"
            )

            success.append(
                result
            )

        else:

            print(
                f"  × "
                f"{result['error']}"
            )

        time.sleep(
            0.1
        )

    print()
    print("=" * 70)
    print("测试结果")
    print("=" * 70)

    print(
        f"成功：{len(success)}"
    )

    print(
        f"失败：{len(ips) - len(success)}"
    )

    print()

    for result in success:

        print(
            f"{result['ip']} "
            f"| {result['colo']} "
            f"| {result['loc']} "
            f"| {result['http_ms']} ms"
        )


if __name__ == "__main__":

    main()