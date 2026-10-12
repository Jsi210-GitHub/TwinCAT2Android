"""Self-contained hashlib MD4 patch for Python 3.13+ (md4 removed from hashlib).

Python 3.13/3.14 removed MD4 from hashlib, which breaks ntlm_auth / requests_ntlm.
We inject a pure-Python MD4 so NTLM handshakes work on any Python >=3.13.
The MD4 implementation is the public-domain reference (RFC 1320) port, the same
algorithm used by spnego's _ntlm_raw.md4.
"""

import hashlib
import struct


def _md4_raw(data: bytes) -> bytes:
    data_block = bytearray(data)
    orig_length = len(data)
    b_orig_length = ((orig_length * 8) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")

    # pad to 64-byte boundary: 0x80 then zeros, then 8-byte little-endian length
    pad_len = (55 - orig_length) % 64 + 1  # includes the 0x80 byte
    data_block += b"\x80" + bytes(pad_len - 1) + b_orig_length

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    def ROTL(x, n):
        return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

    def FF(a, b, c, d, x, s):
        return ROTL((a + F(b, c, d) + x) & 0xFFFFFFFF, s)

    def GG(a, b, c, d, x, s):
        return ROTL((a + G(b, c, d) + x + 0x5A827999) & 0xFFFFFFFF, s)

    def HH(a, b, c, d, x, s):
        return ROTL((a + H(b, c, d) + x + 0x6ED9EBA1) & 0xFFFFFFFF, s)

    while data_block:
        AA, BB, CC, DD = A, B, C, D
        X = struct.unpack("<16I", data_block[:64])
        data_block = data_block[64:]

        # Round 1
        AA = FF(AA, BB, CC, DD, X[0], 3)
        DD = FF(DD, AA, BB, CC, X[1], 7)
        CC = FF(CC, DD, AA, BB, X[2], 11)
        BB = FF(BB, CC, DD, AA, X[3], 19)
        AA = FF(AA, BB, CC, DD, X[4], 3)
        DD = FF(DD, AA, BB, CC, X[5], 7)
        CC = FF(CC, DD, AA, BB, X[6], 11)
        BB = FF(BB, CC, DD, AA, X[7], 19)
        AA = FF(AA, BB, CC, DD, X[8], 3)
        DD = FF(DD, AA, BB, CC, X[9], 7)
        CC = FF(CC, DD, AA, BB, X[10], 11)
        BB = FF(BB, CC, DD, AA, X[11], 19)
        AA = FF(AA, BB, CC, DD, X[12], 3)
        DD = FF(DD, AA, BB, CC, X[13], 7)
        CC = FF(CC, DD, AA, BB, X[14], 11)
        BB = FF(BB, CC, DD, AA, X[15], 19)
        # Round 2
        AA = GG(AA, BB, CC, DD, X[0], 3)
        DD = GG(DD, AA, BB, CC, X[4], 5)
        CC = GG(CC, DD, AA, BB, X[8], 9)
        BB = GG(BB, CC, DD, AA, X[12], 13)
        AA = GG(AA, BB, CC, DD, X[1], 3)
        DD = GG(DD, AA, BB, CC, X[5], 5)
        CC = GG(CC, DD, AA, BB, X[9], 9)
        BB = GG(BB, CC, DD, AA, X[13], 13)
        AA = GG(AA, BB, CC, DD, X[2], 3)
        DD = GG(DD, AA, BB, CC, X[6], 5)
        CC = GG(CC, DD, AA, BB, X[10], 9)
        BB = GG(BB, CC, DD, AA, X[14], 13)
        AA = GG(AA, BB, CC, DD, X[3], 3)
        DD = GG(DD, AA, BB, CC, X[7], 5)
        CC = GG(CC, DD, AA, BB, X[11], 9)
        BB = GG(BB, CC, DD, AA, X[15], 13)
        # Round 3
        AA = HH(AA, BB, CC, DD, X[0], 3)
        DD = HH(DD, AA, BB, CC, X[8], 9)
        CC = HH(CC, DD, AA, BB, X[4], 11)
        BB = HH(BB, CC, DD, AA, X[12], 15)
        AA = HH(AA, BB, CC, DD, X[2], 3)
        DD = HH(DD, AA, BB, CC, X[10], 9)
        CC = HH(CC, DD, AA, BB, X[6], 11)
        BB = HH(BB, CC, DD, AA, X[14], 15)
        AA = HH(AA, BB, CC, DD, X[1], 3)
        DD = HH(DD, AA, BB, CC, X[9], 9)
        CC = HH(CC, DD, AA, BB, X[5], 11)
        BB = HH(BB, CC, DD, AA, X[13], 15)
        AA = HH(AA, BB, CC, DD, X[3], 3)
        DD = HH(DD, AA, BB, CC, X[11], 9)
        CC = HH(CC, DD, AA, BB, X[7], 11)
        BB = HH(BB, CC, DD, AA, X[15], 15)

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return struct.pack("<IIII", A, B, C, D)


class _MD4:
    def __init__(self, data: bytes = b""):
        self._buf = bytearray(data)

    def update(self, data: bytes) -> None:
        self._buf.extend(data)

    def digest(self) -> bytes:
        return _md4_raw(bytes(self._buf))

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self):
        c = _MD4()
        c._buf = bytearray(self._buf)
        return c


def _md4_func(data: bytes = b"") -> _MD4:
    return _MD4(data)


# Only patch if MD4 is genuinely missing from hashlib
try:
    hashlib.new("md4", b"")
except Exception:
    _orig_new = hashlib.new

    def _new(name, data=b"", *args, **kwargs):
        if isinstance(name, str) and name.lower() == "md4":
            return _MD4(data)
        return _orig_new(name, data, *args, **kwargs)

    hashlib.new = _new
    if not hasattr(hashlib, "md4"):
        hashlib.md4 = _md4_func
