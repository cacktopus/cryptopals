import http.server
import threading
import time
import urllib.parse
from functools import partial

import requests

import util
from hmac import hmac_md5

KEY = util.random_word()

debug = util.debug_print(True)

CHARSET = "0123456789abcdef"
ARTIFICIAL_DELAY = 0.050
HASH_LEN = 32


def insecure_compare(artificial_delay: float, s0: str, s1: str) -> bool:
    if len(s1) > len(s0):
        s0, s1 = s1, s0  # make s0 the longer of the two
    l0, l1 = list(s0), list(s1)
    l1 += [None] * (len(l0) - len(l1))  # pad l1 if needed

    assert len(l0) == len(l1)

    for c0, c1 in zip(l0, l1):
        ok = c0 == c1
        time.sleep(artificial_delay)
        if not ok:
            debug("")
            return False
        debug(c0, end='', flush=True)

    return True


stop = False


class Server(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global stop
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        path = self.path
        print(path)

        parts = urllib.parse.urlparse(path)
        print(parts)

        if parts.path == "/stop":
            print("stop")
            stop = True

        elif parts.path == "/test":

            query = urllib.parse.parse_qs(parts.query)
            print(query)

            contents = query['file'][0]
            signature = query['signature'][0]

            print(contents, signature)

            ok = self.test(contents.encode(), signature)
            self.wfile.write(ok + b"\n")

        else:
            assert 0, "Unknown path"

    def test(self, msg: bytes, mac: str):
        target = hmac_md5(KEY, msg)
        print(target, mac)

        ok = insecure_compare(ARTIFICIAL_DELAY, mac, target)

        return b"yes" if ok else b"no"


def serve(s):
    while not stop:
        print("stop?", stop)
        s.handle_request()
    print("stopping")


def do_trial(base, prefix, trial):
    signature = prefix + trial
    signature += "0" * (HASH_LEN - len(signature))
    assert len(signature) == HASH_LEN
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
    assert len(prefix) == HASH_LEN - 1
    for trial in CHARSET:
        resp = do_trial(base, prefix, trial)
        if resp.strip().lower() == "yes":
            return trial
    raise RuntimeError("Could not derive last char")


def derive_mac(base):
    prefix = ""

    while len(prefix) < HASH_LEN - 1:
        f = partial(time_request, base, prefix)

        options = list(map(f, CHARSET))

        print("\n".join(str(a) for a in sorted(options)))
        print("")
        selected = max(options)
        score, ch = selected

        prefix += ch

    assert len(prefix) == HASH_LEN - 1

    prefix += get_last_char(base, prefix)

    return prefix


def main():
    addr = ('127.0.0.1', 0)  # TODO: random port
    s = http.server.HTTPServer(addr, Server)

    print("using", s.server_address)

    t = threading.Thread(
        target=serve,
        daemon=False,
        args=(s,)
    )

    t.start()
    time.sleep(0.250)

    base = "http://{}:{}".format(*s.server_address)

    signature = derive_mac(base)
    assert signature == hmac_md5(KEY, b"foo")

    # target = hmac_md5(KEY, b"foo")
    # prefix = target[:HASH_LEN - 1]
    # print(prefix)
    # print(get_last_char(base, prefix))

    requests.get(base + "/stop")
    print("done")


if __name__ == '__main__':
    main()
