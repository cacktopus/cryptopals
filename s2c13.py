from typing import Dict


def parse_kv(s: str) -> Dict:
    pairs = (p.split("=", 1) for p in s.split("&"))
    return dict(pairs)


def encode_pair(k: str, v: str) -> str:
    return "{}={}".format(k, v.replace("&", "").replace("=", ""))


def profile_for(email: str, uid: str, role: str) -> str:
    return "&".join([
        encode_pair("email", email),
        encode_pair("uid", uid),
        encode_pair("role", role),
    ])
