import requests

import webserver
from s4c31 import derive_mac

HASH_LEN = 16


def prove_low_delay_raises():
    s, base = webserver.start_server(artificial_delay=0.001, hash_len=HASH_LEN)

    try:
        for i in range(10):  # this can randomly succeed, so give it a few chances to fail
            print("attempt", i + 1)
            signature = derive_mac(base, HASH_LEN)
            # assert signature == webserver.hmac_func(webserver.KEY, b"foo")
    finally:
        requests.get(base + "/stop")
        print("done")


def works_with_many_iterations():
    s, base = webserver.start_server(artificial_delay=0.001, hash_len=HASH_LEN)

    try:
        signature = derive_mac(base, HASH_LEN, iterations=50)
    finally:
        requests.get(base + "/stop")
        print("done")
