import json
import base64
from pathlib import Path
import yaml


BASE_DIR = Path(__file__).resolve().parent


INPUT_FILE = (
    BASE_DIR
    / "output"
    / "final_nodes.json"
)


OUTPUT_DIR = (
    BASE_DIR
    / "output"
)


CLASH_FILE = (
    OUTPUT_DIR
    / "clash.yaml"
)


BASE64_FILE = (
    OUTPUT_DIR
    / "subscription.txt"
)



PORT = 443

SERVER_NAME = "cloudflare.com"



def load_nodes():

    with open(
        INPUT_FILE,
        encoding="utf-8"
    ) as f:

        return json.load(f)



def build_clash(nodes):


    proxies=[]


    for i,node in enumerate(nodes,1):


        proxy={

            "name":
            f"AutoCF-{i}-{node['colo']}",


            "type":
            "vless",


            "server":
            node["ip"],


            "port":
            PORT,


            "udp":
            True,


            "tls":
            True,


            "servername":
            SERVER_NAME,


            "skip-cert-verify":
            True,

        }


        proxies.append(proxy)



    config={

        "mixed-port":
        7890,


        "allow-lan":
        True,


        "mode":
        "rule",


        "proxies":
        proxies,


        "proxy-groups":[

            {

                "name":
                "AutoCF",

                "type":
                "select",

                "proxies":
                [
                    x["name"]
                    for x in proxies
                ]

            }

        ],


        "rules":[

            "MATCH,AutoCF"

        ]

    }



    return config



def generate_base64(nodes):


    text="\n".join(

        [
            f"{x['ip']}:443"
            for x in nodes
        ]

    )


    return base64.b64encode(

        text.encode()

    ).decode()



def main():


    print("="*70)

    print(
        "AutoCF 订阅生成器"
    )

    print("="*70)



    nodes=load_nodes()



    OUTPUT_DIR.mkdir(
        exist_ok=True
    )


    clash=build_clash(nodes)



    with open(
        CLASH_FILE,
        "w",
        encoding="utf-8"
    ) as f:


        yaml.dump(

            clash,

            f,

            allow_unicode=True,

            sort_keys=False

        )



    sub=generate_base64(nodes)



    with open(
        BASE64_FILE,
        "w",
        encoding="utf-8"
    ) as f:


        f.write(sub)



    print()

    print(
        "节点数量:",
        len(nodes)
    )


    print()

    print(
        "生成:"
    )

    print(
        CLASH_FILE
    )

    print(
        BASE64_FILE
    )



if __name__=="__main__":

    main()