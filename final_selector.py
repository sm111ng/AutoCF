import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


INPUT_FILE = (
    BASE_DIR
    / "results"
    / "stability_nodes.json"
)


OUTPUT_FILE = (
    BASE_DIR
    / "output"
    / "final_nodes.json"
)



# 每地区数量
PER_REGION = 3



# 优先顺序

REGION_ORDER = [

    "JP",

    "SG",

    "HK",

    "US",

]



# 亚洲备用

ASIA_COLO = [

    "HKG",

    "NRT",

    "KIX",

    "SIN",

]



def main():


    print("="*70)

    print(
        "AutoCF 最终节点选择器"
    )

    print("="*70)



    with open(
        INPUT_FILE,
        encoding="utf-8"
    ) as f:

        nodes=json.load(f)



    # 按评分排序

    nodes.sort(

        key=lambda x:
        x.get(
            "score",
            0
        ),

        reverse=True

    )


    selected=[]


    used=set()



    print()


    # =====================
    # 地区选择
    # =====================

    for region in REGION_ORDER:


        count=0


        for node in nodes:


            if node["ip"] in used:

                continue


            if node.get(
                "region"
            ) == region:


                selected.append(node)

                used.add(
                    node["ip"]
                )


                count+=1


                if count>=PER_REGION:

                    break



        print(
            region,
            ":",
            count
        )



    # =====================
    # 亚洲补充
    # =====================


    asia=[]


    for node in nodes:


        if node["ip"] in used:

            continue



        if node.get(
            "colo"
        ) in ASIA_COLO:


            asia.append(node)



    for node in asia[:3]:


        selected.append(node)

        used.add(
            node["ip"]
        )



    # =====================
    # 全球补充
    # =====================


    for node in nodes:


        if len(selected)>=15:

            break



        if node["ip"] in used:

            continue



        selected.append(node)

        used.add(
            node["ip"]
        )



    # 输出


    OUTPUT_FILE.parent.mkdir(
        exist_ok=True
    )


    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:


        json.dump(

            selected,

            f,

            ensure_ascii=False,

            indent=2

        )



    print()

    print(
        "最终节点:",
        len(selected)
    )


    print()


    for i,node in enumerate(
        selected,
        1
    ):


        print(

            i,

            node["ip"],

            node["colo"],

            node.get(
                "score"
            )

        )



    print()

    print(
        "输出:",
        OUTPUT_FILE
    )



if __name__=="__main__":

    main()