"""Pure-Python Ed25519 signatures (RFC 8032), zero dependencies.

Implements Ed25519 signing and verification from the RFC 8032
specification using only hashlib (SHA-512) and Python big integers.
Validated against the RFC 8032 section 7.1 test vectors in
tests/test_ed25519.py.

This is used to sign ApprovalGuard scan reports so that anyone can
verify a report was produced by this agent's keypair. It is a plain
Ed25519 signature -- NOT a zero-knowledge proof. The competition's
"proofs decide" theme is echoed honestly: reports are authentically
signed and independently verifiable, and no zk claim is made.

Security note: this is a straightforward, non-constant-time
implementation. It is fine for signing public scan reports with a
dedicated agent keypair that holds no funds and no secrets. Do not
reuse this keypair for anything of value.
"""

import hashlib

_Q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)  # sqrt(-1) mod q


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    """Recover the x coordinate for a given y on Edwards25519."""
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
_BASE = (_BX, _BY)  # base point


def _edwards_add(p, q):
    (x1, y1), (x2, y2) = p, q
    denom = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = (x1 * y2 + x2 * y1) * denom % _Q
    denom2 = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    y3 = (y1 * y2 + x1 * x2) * denom2 % _Q
    return (x3, y3)


def _scalarmult(point, e: int):
    if e == 0:
        return (0, 1)
    q = _scalarmult(point, e // 2)
    q = _edwards_add(q, q)
    if e & 1:
        q = _edwards_add(q, point)
    return q


def _encode_point(point) -> bytes:
    x, y = point
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _is_on_curve(point) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decode_point(data: bytes):
    if len(data) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("non-canonical y coordinate")
    x = _xrecover(y)
    if (x & 1) != (data[31] >> 7):
        x = _Q - x
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("point is not on the curve")
    return point


def _clamp(digest32: bytes) -> bytes:
    h = bytearray(digest32)
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(_clamp(h[:32]), "little")
    return _encode_point(_scalarmult(_BASE, a))


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign a message with the 32-byte seed. Returns a 64-byte signature."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(_clamp(h[:32]), "little")
    public_key = _encode_point(_scalarmult(_BASE, a))
    r = int.from_bytes(_sha512(h[32:] + message), "little") % _L
    big_r = _scalarmult(_BASE, r)
    encoded_r = _encode_point(big_r)
    k = int.from_bytes(_sha512(encoded_r + public_key + message), "little")
    s = (r + k * a) % _L
    return encoded_r + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte Ed25519 signature. Returns False on any failure."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        big_r = _decode_point(signature[:32])
        big_a = _decode_point(public_key)
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(signature[:32] + public_key + message), "little") % _L
    return _scalarmult(_BASE, s) == _edwards_add(big_r, _scalarmult(big_a, k))
