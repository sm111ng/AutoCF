import socket
import ssl
import time
from typing import Optional


DEFAULT_HOST = "cloudflare.com"
DEFAULT_PORT = 443
TRACE_PATH = "/cdn-cgi/trace"


def probe(
    ip: str,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 5.0,
):
    result = {
        "ip": ip,
        "host": host,
        "port": port,
        "ok": False,
        "tcp_ms": None,
        "tls_ms": None,
        "http_ms": None,
        "status": None,
        "colo": None,
        "loc": None,
        "trace": {},
        "error": None,
    }

    sock: Optional[socket.socket] = None
    tls_sock: Optional[ssl.SSLSocket] = None

    try:
        # ====================================================
        # 1. 强制连接指定 IP
        # ====================================================

        tcp_start = time.perf_counter()

        sock = socket.create_connection(
            (ip, port),
            timeout=timeout,
        )

        tcp_ms = (
            time.perf_counter() - tcp_start
        ) * 1000

        result["tcp_ms"] = round(
            tcp_ms,
            2,
        )

        # ====================================================
        # 2. TLS
        #
        # server_hostname = host
        # 这就是 SNI
        # ====================================================

        context = ssl.create_default_context()

        tls_start = time.perf_counter()

        tls_sock = context.wrap_socket(
            sock,
            server_hostname=host,
        )

        tls_ms = (
            time.perf_counter() - tls_start
        ) * 1000

        result["tls_ms"] = round(
            tls_ms,
            2,
        )

        # ====================================================
        # 3. HTTP
        #
        # 连接仍然是：
        #
        # IP:443
        #
        # 但：
        #
        # SNI  = host
        # Host = host
        # ====================================================

        request = (
            f"GET {TRACE_PATH} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: AutoCF/2.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        http_start = time.perf_counter()

        tls_sock.sendall(
            request.encode("ascii")
        )

        data = b""

        while True:

            chunk = tls_sock.recv(16384)

            if not chunk:
                break

            data += chunk

            # trace 很小，避免异常服务器返回大量数据
            if len(data) > 1024 * 1024:
                break

        http_ms = (
            time.perf_counter() - http_start
        ) * 1000

        result["http_ms"] = round(
            http_ms,
            2,
        )

        # ====================================================
        # 4. HTTP 解析
        # ====================================================

        text = data.decode(
            "utf-8",
            errors="replace",
        )

        header_body = text.split(
            "\r\n\r\n",
            1,
        )

        headers = header_body[0]

        body = ""

        if len(header_body) > 1:
            body = header_body[1]

        # HTTP 状态
        first_line = (
            headers.splitlines()[0]
            if headers.splitlines()
            else ""
        )

        parts = first_line.split()

        if len(parts) >= 2:

            try:
                result["status"] = int(
                    parts[1]
                )
            except ValueError:
                pass

        # ====================================================
        # 5. 解析 /cdn-cgi/trace
        # ====================================================

        trace = {}

        for line in body.splitlines():

            line = line.strip()

            if "=" not in line:
                continue

            key, value = line.split(
                "=",
                1,
            )

            trace[
                key.strip()
            ] = value.strip()

        result["trace"] = trace

        result["colo"] = trace.get(
            "colo"
        )

        result["loc"] = trace.get(
            "loc"
        )

        # ====================================================
        # 6. 判断是否真正获得 Cloudflare trace
        # ====================================================

        if result["colo"]:

            result["ok"] = True

        else:

            result["error"] = (
                "HTTP 成功，但没有获得 colo"
            )

        return result

    except Exception as e:

        result["error"] = (
            f"{type(e).__name__}: {e}"
        )

        return result

    finally:

        try:

            if tls_sock is not None:
                tls_sock.close()

            elif sock is not None:
                sock.close()

        except Exception:
            pass


def print_result(result):

    print()
    print("=" * 70)
    print("Cloudflare Probe")
    print("=" * 70)

    print(
        f"IP       : {result['ip']}"
    )

    print(
        f"Host/SNI : {result['host']}"
    )

    print(
        f"Port     : {result['port']}"
    )

    print(
        f"TCP      : {result['tcp_ms']} ms"
    )

    print(
        f"TLS      : {result['tls_ms']} ms"
    )

    print(
        f"HTTP     : {result['http_ms']} ms"
    )

    print(
        f"HTTP状态 : {result['status']}"
    )

    print(
        f"Colo     : {result['colo']}"
    )

    print(
        f"Location : {result['loc']}"
    )

    print(
        f"成功     : {result['ok']}"
    )

    if result["error"]:

        print(
            f"错误     : {result['error']}"
        )

    print()

    if result["trace"]:

        print("Trace:")

        for key, value in (
            result["trace"].items()
        ):

            print(
                f"  {key} = {value}"
            )

    print()


if __name__ == "__main__":

    # ========================================================
    # 测试一个已知 Cloudflare IP
    #
    # 这里先使用你候选池里的一个 IP。
    # ========================================================

    test_ip = "104.16.0.1"

    result = probe(
        ip=test_ip,
        host="cloudflare.com",
    )

    print_result(result)