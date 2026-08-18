import ipaddress
import random
from pathlib import Path

import requests
import yaml


BASE_DIR = Path(__file__).resolve().parent

CONFIG_FILE = BASE_DIR / "config.yaml"

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "cloudflare_candidates.txt"
)


def load_config():

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        return yaml.safe_load(f)


def get_cloudflare_ipv4():

    print()
    print("=" * 70)
    print("获取 Cloudflare 官方 IPv4 网段")
    print("=" * 70)

    url = "https://www.cloudflare.com/ips-v4"

    response = requests.get(
        url,
        timeout=15,
    )

    response.raise_for_status()

    cidrs = [
        x.strip()
        for x in response.text.splitlines()
        if x.strip()
    ]

    print(
        f"官方 IPv4 网段：{len(cidrs)}"
    )

    return cidrs


def generate_candidates(
    cidrs,
    per_cidr,
):

    all_ips = []

    print()
    print("=" * 70)
    print("生成 Cloudflare 候选 IP")
    print("=" * 70)

    for cidr in cidrs:

        network = ipaddress.ip_network(
            cidr
        )

        hosts = list(
            network.hosts()
        )

        if not hosts:
            continue

        count = min(
            per_cidr,
            len(hosts)
        )

        selected = random.sample(
            hosts,
            count
        )

        print(
            f"{cidr} -> {len(selected)}"
        )

        all_ips.extend(
            str(ip)
            for ip in selected
        )

    # 去重
    all_ips = list(
        dict.fromkeys(
            all_ips
        )
    )

    # 打乱顺序
    random.shuffle(
        all_ips
    )

    return all_ips


def main():

    config = load_config()

    candidate_config = config.get(
        "candidate_pool",
        {}
    )

    per_cidr = int(
        candidate_config.get(
            "ips_per_cidr",
            50
        )
    )

    OUTPUT_FILE.parent.mkdir(
        exist_ok=True
    )

    cidrs = get_cloudflare_ipv4()

    ips = generate_candidates(
        cidrs,
        per_cidr,
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(ips)
        )

    print()
    print("=" * 70)
    print("候选池生成完成")
    print("=" * 70)

    print(
        f"每网段候选：{per_cidr}"
    )

    print(
        f"总候选 IP：{len(ips)}"
    )

    print(
        f"输出：{OUTPUT_FILE}"
    )

    print()


if __name__ == "__main__":

    main()