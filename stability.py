import asyncio
import json
import ssl
import time
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


INPUT_FILE = (
    BASE_DIR
    / "results"
    / "scored_nodes.json"
)


OUTPUT_FILE = (
    BASE_DIR
    / "results"
    / "stability_nodes.json"
)


TEST_COUNT = 5

MAX_NODES = 50


async def test_node(
    node
):

    ip = node["ip"]

    host = "cloudflare.com"

    success = 0

    times = []


    for i in range(TEST_COUNT):

        start = time.perf_counter()

        try:

            context = (
                ssl.create_default_context()
            )

            reader, writer = await asyncio.wait_for(

                asyncio.open_connection(

                    ip,

                    443,

                    ssl=context,

                    server_hostname=host,

                ),

                timeout=5

            )


            request = (
                "GET /cdn-cgi/trace HTTP/1.1\r\n"
                "Host: cloudflare.com\r\n"
                "Connection: close\r\n"
                "\r\n"
            )


            writer.write(
                request.encode()
            )


            await writer.drain()


            data = await asyncio.wait_for(
                reader.read(4096),
                timeout=5
            )


            elapsed = (
                time.perf_counter()
                -
                start
            ) * 1000


            writer.close()


            success += 1

            times.append(
                elapsed
            )


        except Exception:

            pass


        await asyncio.sleep(0.3)



    if times:

        avg = (
            sum(times)
            /
            len(times)
        )

    else:

        avg = 999



    stability = (
        success
        /
        TEST_COUNT
        *
        100
    )


    node["stability"] = round(
        stability,
        2
    )


    node["avg_test_ms"] = round(
        avg,
        2
    )


    return node



async def main_async():


    with open(
        INPUT_FILE,
        encoding="utf-8"
    ) as f:

        nodes=json.load(f)


    nodes = nodes[:MAX_NODES]


    print("="*70)

    print(
        "AutoCF 稳定性测试"
    )

    print("="*70)


    tasks=[

        test_node(n)

        for n in nodes

    ]


    results=[]


    for task in asyncio.as_completed(tasks):

        r=await task

        results.append(r)

        print(

            r["ip"],

            r["colo"],

            "稳定:",
            r["stability"],

            "%"

        )



    results.sort(

        key=lambda x:x["score"],

        reverse=True

    )


    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:


        json.dump(

            results,

            f,

            ensure_ascii=False,

            indent=2

        )


    print()

    print(
        "输出:",
        OUTPUT_FILE
    )



def main():

    asyncio.run(
        main_async()
    )


if __name__=="__main__":

    main()