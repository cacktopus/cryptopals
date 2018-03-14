import http.server
import urllib.parse


class Server(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Hi\n")
        path = self.path
        print(path)

        parts = urllib.parse.urlparse(path)
        print(parts)

        query = urllib.parse.parse_qs(parts.query)
        print(query)

        filename = query['file'][0]
        signature = query['signature'][0]

        print(filename, signature)


def main():
    addr = ('127.0.0.1', 8000)
    print("Listening on", addr)
    s = http.server.HTTPServer(addr, Server)
    s.serve_forever()


if __name__ == '__main__':
    main()
