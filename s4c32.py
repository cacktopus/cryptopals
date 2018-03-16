import requests

import webserver
from s4c31 import derive_mac


def main():
    s, base = webserver.start_server(artificial_delay=0.005, hash_len=16)
    hash_len = s.server_state['hash_len']

    try:
        for i in range(10):  # this can randomly succeed, so give it a few chances to fail
            print("attempt", i + 1)
            signature = derive_mac(base, hash_len)
            # assert signature == webserver.hmac_func(webserver.KEY, b"foo")
    finally:
        requests.get(base + "/stop")
        print("done")


if __name__ == '__main__':
    main()  # pragma nocover
