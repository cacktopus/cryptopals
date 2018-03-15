import http.server
import time
import urllib.parse

import util
from hmac import hmac_md5

KEY = util.random_word()

debug = util.debug_print(True)

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
