from pathlib import Path
import ipaddress
import random
import requests


BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
IPS_DIR = BASE_DIR / "ips"

DATA_DIR.mkdir(exist_ok=True)
IPS_DIR.mkdir(exist_ok=True)


CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4/"

# 每个 Cloudflare 网段抽样数量
SAMPLES_PER_NETWORK = 30


def fetch_networks():

    print()
    print("=" * 70)
    print("获取 Cloudflare 官方 IPv4 网段")
    print("=" * 70)

    response = requests.get(
        CLOUDFLARE_IPV4_URL,
        timeout=20
    )

    response.raise_for_status()

    networks = []

    for line in response.text.splitlines():

        line = line.strip()

        if not line:
            continue

        try:

            network = ipaddress.ip_network(
                line,
                strict=False
            )

            if network.version == 4:
                networks.append(network)

        except ValueError:

            pass

    return networks


def sample_network(network):

    addresses = list(network.hosts())

    if not addresses:
        return []

    if len(addresses) <= SAMPLES_PER_NETWORK:

        return [
            str(ip)
            for ip in addresses
        ]

    return [
        str(ip)
        for ip in random.sample(
            addresses,
            SAMPLES_PER_NETWORK
        )
    ]


def generate_candidates(networks):

    candidates = set()

    print()
    print("=" * 70)
    print("生成 Cloudflare 候选 IP")
    print("=" * 70)

    for network in networks:

        samples = sample_network(
            network
        )

        candidates.update(samples)

        print(
            f"{network} -> "
            f"{len(samples)}"
        )

    return sorted(
        candidates,
        key=lambda x: tuple(
            int(part)
            for part in x.split(".")
        )
    )


def save_candidates(candidates):

    output = (
        DATA_DIR
        / "cloudflare_candidates.txt"
    )

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:

        for ip in candidates:

            f.write(ip + "\n")

    return output


def clear_old_generated_regions():

    # 旧版程序随机分区产生的数据已经没有意义。
    #
    # 这里不删除文件。
    #
    # 只是写入说明，让 scanner_v2
    # 不再把这些文件当作真正的地区池。

    for region in [
        "jp",
        "sg",
        "hk",
        "us"
    ]:

        path = IPS_DIR / f"{region}.txt"

        if not path.exists():
            path.touch()


def save_metadata(networks, candidates):

    output = (
        DATA_DIR
        / "candidate_metadata.txt"
    )

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "AutoCF Cloudflare Candidate Pool\n"
        )

        f.write(
            f"IPv4网段数量: {len(networks)}\n"
        )

        f.write(
            f"候选IP数量: {len(candidates)}\n"
        )

        f.write(
            "\n"
        )

        f.write(
            "注意：\n"
        )

        f.write(
            "Cloudflare Anycast IP 没有固定国家属性。\n"
        )

        f.write(
            "地区必须通过实际网络测试/Cloudflare Colo判断。\n"
        )

    return output


def main():

    print()
    print("=" * 70)
    print("        AutoCF Candidate Pool V2")
    print("=" * 70)

    networks = fetch_networks()

    print()
    print(
        f"官方 IPv4 网段：{len(networks)}"
    )

    candidates = generate_candidates(
        networks
    )

    print()
    print(
        f"总候选 IP：{len(candidates)}"
    )

    candidate_file = save_candidates(
        candidates
    )

    save_metadata(
        networks,
        candidates
    )

    clear_old_generated_regions()

    print()
    print("=" * 70)
    print("候选池生成完成")
    print("=" * 70)

    print()
    print(
        f"候选池：{candidate_file}"
    )

    print()
    print(
        "下一阶段由 scanner_v2 根据实际连接结果"
    )

    print(
        "判断 JP / SG / HK / US，而不是随机分组。"
    )

    print()


if __name__ == "__main__":
    main()