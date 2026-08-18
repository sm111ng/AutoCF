import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


INPUT = (
    BASE_DIR
    /
    "output"
    /
    "final_nodes.json"
)


OUTPUT = (
    BASE_DIR
    /
    "output"
    /
    "proxyip.txt"
)



def main():

    with open(
        INPUT,
        encoding="utf-8"
    ) as f:

        nodes=json.load(f)


    result=[]


    for n in nodes:

        ip=n["ip"]

        result.append(
            f"{ip}:443"
        )


    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(result)
        )


    print(
        "生成完成:"
    )

    print(
        OUTPUT
    )

    print(
        "节点数量:",
        len(result)
    )



if __name__=="__main__":
    main()