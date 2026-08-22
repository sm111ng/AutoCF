import os
import json
import subprocess
import time


INPUT = "decoded_sub.txt"
OUTPUT = "results/vless_test.json"


def load_nodes():
    if not os.path.exists(INPUT):
        print("decoded_sub.txt not found")
        return []

    nodes = []

    with open(INPUT, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if line.startswith("vless://"):
                nodes.append(line)

    return nodes


def test_node(node):

    # 基础检查
    if "@" not in node:
        return False

    return True



def main():

    print("="*50)
    print("AutoCF VLESS TEST")
    print("="*50)


    nodes = load_nodes()

    print("Nodes:", len(nodes))


    results=[]


    for i,node in enumerate(nodes):

        ok=test_node(node)

        results.append(
            {
                "index":i,
                "alive":ok,
                "node":node
            }
        )


        print(
            f"{i+1}/{len(nodes)}",
            "OK" if ok else "FAIL"
        )


    os.makedirs(
        "results",
        exist_ok=True
    )


    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=2,
            ensure_ascii=False
        )


    print("DONE")



if __name__=="__main__":
    main()