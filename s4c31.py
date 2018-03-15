import http.server
import threading
import time
from functools import partial

import requests

import webserver
from hmac import hmac_md5

CHARSET = "0123456789abcdef"


def do_trial(base, prefix, trial):
    signature = prefix + trial
    signature += "0" * (webserver.HASH_LEN - len(signature))
    assert len(signature) == webserver.HASH_LEN
    resp = requests.get(
        url=base + "/test",
        params={
            "file": "foo",
            "signature": signature
        }
    )
    return resp.text


def time_request(base, prefix: str, trial: str):
    t0 = time.time()
    do_trial(base, prefix, trial)
    t = time.time() - t0
    return t, trial


def get_last_char(base: str, prefix: str):
    assert len(prefix) == webserver.HASH_LEN - 1
    for trial in CHARSET:
        resp = do_trial(base, prefix, trial)
        if resp.strip().lower() == "yes":
            return trial
    raise RuntimeError("Could not derive last char")


def derive_mac(base):
    prefix = ""

    while len(prefix) < webserver.HASH_LEN - 1:
        f = partial(time_request, base, prefix)

        options = list(map(f, CHARSET))

        print("\n".join(str(a) for a in sorted(options)))
        print("")
        selected = max(options)
        score, ch = selected

        prefix += ch

    assert len(prefix) == webserver.HASH_LEN - 1

    prefix += get_last_char(base, prefix)

    return prefix


def start_server():
    addr = ('127.0.0.1', 0)  # TODO: random port
    s = http.server.HTTPServer(addr, webserver.Server)

    print("using", s.server_address)

    t = threading.Thread(
        target=webserver.serve,
        daemon=False,
        args=(s,)
    )

    t.start()
    time.sleep(0.250)

    base = "http://{}:{}".format(*s.server_address)

    return s, base


def main():
    s, base = start_server()

    signature = derive_mac(base)
    assert signature == hmac_md5(webserver.KEY, b"foo")

    requests.get(base + "/stop")
    print("done")


if __name__ == '__main__':
    main()
