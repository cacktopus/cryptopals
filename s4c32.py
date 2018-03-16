import requests

import webserver
from s4c31 import derive_mac

HASH_LEN = 16
DELAY = 0.0025
ITERATIONS = 40


def prove_low_delay_raises():
    s, base = webserver.start_server(artificial_delay=DELAY, hash_len=HASH_LEN)

    try:
        for i in range(10):  # this can randomly succeed, so give it a few chances to fail
            print("attempt", i + 1)
            signature = derive_mac(base, HASH_LEN)
            assert signature != webserver.hmac_func(HASH_LEN, webserver.KEY, b"foo")
    finally:
        requests.get(base + "/stop")
        print("done")


def works_with_many_iterations():
    s, base = webserver.start_server(artificial_delay=DELAY, hash_len=HASH_LEN)

    try:
        signature = derive_mac(base, HASH_LEN, iterations=ITERATIONS)
        assert signature == webserver.hmac_func(HASH_LEN, webserver.KEY, b"foo")
    finally:
        requests.get(base + "/stop")
        print("done")
