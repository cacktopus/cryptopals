import requests

import webserver
from hmac import hmac_md5
from s4c31 import start_server, derive_mac


def main():
    webserver.ARTIFICIAL_DELAY = 0.005

    s, base = start_server()

    signature = derive_mac(base)
    assert signature == hmac_md5(webserver.KEY, b"foo")

    requests.get(base + "/stop")
    print("done")
