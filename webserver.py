import http.server
import time
import urllib.parse

import util
from s4c31 import hmac_sha1

KEY = util.random_word()

debug = util.debug_print(True)


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


class Server(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        path = self.path
        print(path)

        parts = urllib.parse.urlparse(path)
        print(parts)

        query = urllib.parse.parse_qs(parts.query)
        print(query)

        contents = query['file'][0]
        signature = query['signature'][0]

        print(contents, signature)

        ok = self.test(contents.encode(), signature)
        self.wfile.write(ok + b"\n")

    def test(self, msg: bytes, mac: bytes):
        target = hmac_sha1(KEY, msg)
        print(target, mac)
        return b"yes" if mac == target else b"no"


def serve():
    addr = ('127.0.0.1', 8000)
    print("Listening on", addr)
    s = http.server.HTTPServer(addr, Server)
    s.serve_forever()


def main():
    # serve()
    print(insecure_compare(0.50, "abcd", "abcd"))


if __name__ == '__main__':
    main()
