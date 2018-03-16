import time
from functools import partial

import requests

import webserver

CHARSET = "0123456789abcdef"


class NotDerivedError(Exception):
    pass


def do_trial(base, hash_len: int, prefix: str, trial: str) -> bytes:
    signature = prefix + trial
    signature += "0" * (hash_len - len(signature))
    assert len(signature) == hash_len
    resp = requests.get(
        url=base + "/test",
        params={
            "file": "foo",
            "signature": signature
        }
    )
    return resp.text


def time_request(base, hash_len: int, prefix: str, trial: str):
    t0 = time.time()
    do_trial(base, hash_len, prefix, trial)
    t = time.time() - t0
    return t, trial


def get_last_char(base: str, hash_len: int, prefix: str):
    assert len(prefix) == hash_len - 1
    for trial in CHARSET:
        resp = do_trial(base, hash_len, prefix, trial)
        if resp.strip().lower() == "yes":
            return trial
    raise NotDerivedError("Could not derive last char")


def derive_mac(base, hash_len: int):
    prefix = ""

    while len(prefix) < hash_len - 1:
        f = partial(time_request, base, hash_len, prefix)

        options = list(map(f, CHARSET))

        print("\n".join(str(a) for a in sorted(options)))
        print("")
        selected = max(options)
        score, ch = selected

        prefix += ch

    assert len(prefix) == hash_len - 1

    prefix += get_last_char(base, hash_len, prefix)

    return prefix


def main():
    s, base = webserver.start_server()
    hash_len = s.server_state['hash_len']

    try:
        signature = derive_mac(base, hash_len)
        # assert signature == hmac_func(webserver.KEY, b"foo")
    finally:
        requests.get(base + "/stop")
        print("done")


if __name__ == '__main__':
    main()  # pragma nocover
