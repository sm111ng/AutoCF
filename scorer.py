import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


INPUT_FILE = (
    BASE_DIR
    / "results"
    / "scanner_v3.json"
)


OUTPUT_FILE = (
    BASE_DIR
    / "results"
    / "scored_nodes.json"
)


def normalize(value, min_v, max_v):

    if value is None:
        return 0

    if max_v == min_v:
        return 100

    score = (
        (max_v - value)
        /
        (max_v - min_v)
    ) * 100

    return max(
        0,
        min(
            100,
            score
        )
    )


def main():

    print("=" * 70)
    print("AutoCF 节点评分器")
    print("=" * 70)


    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        nodes = json.load(f)


    nodes = [
        x
        for x in nodes
        if x.get("ok")
    ]


    if not nodes:

        print(
            "没有有效节点"
        )

        return


    tcp_values = [
        x["tcp_ms"]
        for x in nodes
        if x["tcp_ms"]
    ]


    http_values = [
        x["http_ms"]
        for x in nodes
        if x["http_ms"]
    ]


    min_tcp = min(tcp_values)
    max_tcp = max(tcp_values)

    min_http = min(http_values)
    max_http = max(http_values)



    result = []


    for node in nodes:


        latency_score = normalize(
            node["tcp_ms"],
            min_tcp,
            max_tcp
        )


        speed_score = normalize(
            node["http_ms"],
            min_http,
            max_http
        )


        stability_score = 100


        total = (

            latency_score
            * 0.30

            +

            speed_score
            * 0.45

            +

            stability_score
            * 0.25

        )


        node["latency_score"] = round(
            latency_score,
            2
        )

        node["speed_score"] = round(
            speed_score,
            2
        )

        node["stability_score"] = (
            stability_score
        )


        node["score"] = round(
            total,
            2
        )


        result.append(node)



    result.sort(
        key=lambda x:x["score"],
        reverse=True
    )


    OUTPUT_FILE.parent.mkdir(
        exist_ok=True
    )


    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            ensure_ascii=False,
            indent=2
        )


    print()

    print(
        f"有效节点：{len(result)}"
    )


    print()

    print(
        "TOP 10:"
    )


    for i,node in enumerate(
        result[:10],
        1
    ):

        print(
            f"{i}. "
            f"{node['ip']} "
            f"{node['colo']} "
            f"{node['http_ms']}ms "
            f"score={node['score']}"
        )


    print()

    print(
        f"输出：{OUTPUT_FILE}"
    )



if __name__=="__main__":

    main()