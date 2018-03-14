import http.server
import urllib.parse

import util
from s4c31 import hmac_sha1

KEY = util.random_word()


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


def main():
    addr = ('127.0.0.1', 8000)
    print("Listening on", addr)
    s = http.server.HTTPServer(addr, Server)
    s.serve_forever()


if __name__ == '__main__':
    main()
