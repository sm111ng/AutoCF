import subprocess
import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


LOG = (
    BASE_DIR
    /
    "logs"
    /
    "auto_run.log"
)


FILES = [

    "candidate_pool_v3.py",

    "scanner_v3.py",

    "scorer.py",

    "stability.py",

    "final_selector.py",

    "subscription_generator.py"

]



def write_log(msg):

    LOG.parent.mkdir(
        exist_ok=True
    )

    with open(
        LOG,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(

            "\n"
            +
            str(datetime.datetime.now())
            +
            " "
            +
            msg

        )



def run(file):

    write_log(
        "开始:"
        +
        file
    )


    result=subprocess.run(

        [
            "python",
            file
        ],

        cwd=BASE_DIR,

        capture_output=True,

        text=True

    )


    if result.returncode!=0:

        write_log(

            "失败:"
            +
            result.stderr

        )

        raise Exception(file)



    write_log(
        "完成:"
        +
        file
    )



def main():

    write_log(
        "====== AutoCF启动 ======"
    )


    for f in FILES:

        run(f)



    write_log(
        "====== AutoCF完成 ======"
    )



if __name__=="__main__":

    main()