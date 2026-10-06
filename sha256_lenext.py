#!/usr/bin/env python3
"""
Lab: Hashing & MAC  --  Part 3
Length-extension attack on a secret-prefix MAC, and why HMAC stops it.

No third-party packages. Run:
    python3 sha256_lenext.py --first ada
    python3 sha256_lenext.py --first ada --hmac

The attacker code below NEVER reads Server.secret. It only sees the
(message, tag) pair the server hands out and the tag length. That is enough
to forge a brand-new message ending in "&role=admin" with a valid tag --
unless the server uses HMAC.
"""

import argparse
import hashlib
import hmac
import os
import struct

# --------------------------------------------------------------------------
# A pure-Python SHA-256 whose compression function we can resume from an
# arbitrary state. This is the primitive a length-extension attack needs and
# the reason it is written out here instead of using hashlib.
# --------------------------------------------------------------------------

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

_MASK = 0xffffffff


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & _MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK
        h, g, f, e = g, f, e, (d + t1) & _MASK
        d, c, b, a = c, b, a, (t1 + t2) & _MASK

    return [(x + y) & _MASK for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def _md_padding(msg_len):
    """Merkle-Damgard padding for a message of `msg_len` bytes."""
    zeros = (56 - (msg_len + 1)) % 64
    return b"\x80" + b"\x00" * zeros + struct.pack(">Q", msg_len * 8)


def sha256(data):
    state = list(_H0)
    padded = data + _md_padding(len(data))
    for i in range(0, len(padded), 64):
        state = _compress(state, padded[i:i + 64])
    return b"".join(struct.pack(">I", x) for x in state)


def sha256_extend(orig_digest, orig_len, suffix):
    """
    Given orig_digest = SHA256(prefix) and orig_len = len(prefix) in bytes,
    return (new_digest, glue) such that
        new_digest == SHA256(prefix || glue || suffix)
    without knowing `prefix`. `glue` is the Merkle-Damgard padding that the
    original hash appended internally and that we must now make explicit.
    """
    state = list(struct.unpack(">8I", orig_digest))
    glue = _md_padding(orig_len)
    already_consumed = orig_len + len(glue)          # multiple of 64
    new_total_len = already_consumed + len(suffix)
    tail = suffix + _md_padding(new_total_len)
    for i in range(0, len(tail), 64):
        state = _compress(state, tail[i:i + 64])
    return b"".join(struct.pack(">I", x) for x in state), glue


# --------------------------------------------------------------------------
# The service under attack.
# --------------------------------------------------------------------------

class Server:
    def __init__(self, use_hmac):
        # 8-20 random bytes; neither the length nor the value is given out.
        self._secret = os.urandom(os.urandom(1)[0] % 13 + 8)
        self._use_hmac = use_hmac

    def _tag(self, message):
        if self._use_hmac:
            return hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        return sha256(self._secret + message).hex()

    def issue_guest_token(self, first):
        message = f"user={first}&role=guest".encode()
        return message, self._tag(message)

    def verify(self, message, tag):
        return hmac.compare_digest(self._tag(message), tag)

    # For grading transparency and the CyberChef cross-check only --
    # the attack code never calls these.
    def _debug_secret_len(self):
        return len(self._secret)

    def _debug_secret_hex(self):
        return self._secret.hex()


# --------------------------------------------------------------------------
# The attacker. Sees only (message, tag). Wants role=admin.
# --------------------------------------------------------------------------

def attack(server, message, tag):
    suffix = b"&role=admin"
    orig_digest = bytes.fromhex(tag)

    for guess in range(1, 65):                       # unknown secret length
        orig_len = guess + len(message)
        new_digest, glue = sha256_extend(orig_digest, orig_len, suffix)
        forged_message = message + glue + suffix
        if server.verify(forged_message, new_digest.hex()):
            return guess, forged_message, new_digest.hex()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--first", default="student", help="your FIRST (SIP) value")
    ap.add_argument("--hmac", action="store_true",
                    help="server uses HMAC-SHA256 instead of SHA256(secret||m)")
    args = ap.parse_args()

    # Sanity: our hand-rolled SHA-256 must match the real one.
    assert sha256(b"abc").hex() == hashlib.sha256(b"abc").hexdigest()
    assert sha256(b"x" * 200).hex() == hashlib.sha256(b"x" * 200).hexdigest()
    print("[*] pure-Python SHA-256 verified against hashlib\n")

    mode = "HMAC-SHA256(secret, m)" if args.hmac else "SHA256(secret || m)"
    print(f"[*] server MAC construction : {mode}")

    server = Server(use_hmac=args.hmac)
    message, tag = server.issue_guest_token(args.first)
    print(f"[*] legit message           : {message!r}")
    print(f"[*] legit tag               : {tag}")
    print(f"[*] server verifies legit   : {server.verify(message, tag)}")
    print(f"    (secret is {server._debug_secret_len()} bytes, hidden from the attacker code;")
    print(f"     hex = {server._debug_secret_hex()}  <-- for your CyberChef cross-check only)\n")

    result = attack(server, message, tag)
    if result is None:
        print("[-] FORGERY FAILED - server rejected every extension attempt.")
        print("    The nested HMAC construction never exposes a hash state the")
        print("    attacker can resume, so length extension does not apply.")
        print()
        print("    CyberChef cross-check: Recipe = HMAC (hashing: SHA256), key type Hex,")
        print(f"    key = {server._debug_secret_hex()}")
        print(f"    input = {message.decode()}")
        print(f"    should reproduce the legit tag above: {tag}")
        return

    guess, forged_message, forged_tag = result
    print(f"[+] recovered secret length : {guess} bytes  (brute-forced, no secret needed)")
    print(f"[+] forged message          : {forged_message!r}")
    print(f"[+] forged tag              : {forged_tag}")
    print(f"[+] server response         : ACCEPTED  <-- privilege escalation to role=admin")
    print()
    print("    Note the raw glue padding (\\x80, zero run, 64-bit length field)")
    print("    sitting between role=guest and role=admin. A query-string parser")
    print("    keeps the LAST role= value, so the request is read as role=admin.")


if __name__ == "__main__":
    main()
