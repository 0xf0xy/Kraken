import hashlib
import hmac


def prf512(key: bytes, a: bytes, b: bytes) -> bytes:
    blen = 64
    result = bytearray()

    for i in range((blen * 8 + 159) // 160 + 1):
        digest = hmac.new(key, a + b"\x00" + b + bytes([i]), hashlib.sha1).digest()
        result.extend(digest)

    return bytes(result[:blen])


def check_password(
    password: str,
    ssid: bytes,
    ap: bytes,
    client: bytes,
    anonce: bytes,
    snonce: bytes,
    mic: bytes,
    eapol: bytes,
) -> bool:
    pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), ssid, 4096, 32)

    label = b"Pairwise key expansion"
    context = (
        min(ap, client) + max(ap, client) + min(anonce, snonce) + max(anonce, snonce)
    )

    ptk = prf512(pmk, label, context)
    mic_key = ptk[:16]

    eapol_zeroed = bytearray(eapol)
    eapol_zeroed[81:97] = b"\x00" * 16

    calculated_mic = hmac.new(mic_key, eapol_zeroed, hashlib.sha1).digest()[:16]

    return calculated_mic == mic
