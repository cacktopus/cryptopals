import http.server
import threading
import time
import urllib.parse

import util
from hmac import hmac_md5

KEY = util.random_word()


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
            return False

    return True


class Server(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        path = self.path

        parts = urllib.parse.urlparse(path)

        if parts.path == "/stop":
            print("stop request")
            self.set_state("stop", True)

        elif parts.path == "/test":
            query = urllib.parse.parse_qs(parts.query)

            contents = query['file'][0]
            signature = query['signature'][0]

            ok = self.test(contents.encode(), signature)
            self.wfile.write(ok + b"\n")

        else:
            assert 0, "Unknown path"

    def test(self, msg: bytes, mac: str):
        target = self.hmac_func(KEY, msg)
        ok = insecure_compare(self.get_state("artificial_delay"), mac, target)

        return b"yes" if ok else b"no"

    def get_state(self, key: str):
        return self.server.server_state[key]

    def set_state(self, key: str, value):
        self.server.server_state[key] = value
        return self

    def log_message(self, *args, **kwargs):
        pass

    def hmac_func(self, key: bytes, msg: bytes):
        hash_len = self.get_state("hash_len")
        return hmac_md5(key, msg)[:hash_len]


def serve(s: http.server.HTTPServer):
    while not s.server_state['stop']:
        s.handle_request()
    print("stopping")


def start_server(**server_state_overrides):
    addr = ('127.0.0.1', 0)
    s = http.server.HTTPServer(addr, Server)

    assert not hasattr(s, "server_state")

    server_state = dict(
        artificial_delay=0.050,
        hash_len=6,
        stop=False,
    )

    server_state.update(server_state_overrides)

    s.server_state = server_state

    print("using", s.server_address)

    t = threading.Thread(
        target=serve,
        daemon=False,
        args=(s,)
    )

    t.start()
    time.sleep(0.250)

    base = "http://{}:{}".format(*s.server_address)

    return s, base
