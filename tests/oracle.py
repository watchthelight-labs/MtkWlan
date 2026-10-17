# <wtl> project: mtkwlan | file: tests/oracle.py | author: watchthelight </wtl>
# Independent oracle for the MtkCrypto tests: the same values computed with Python's hashlib / hmac, so the C
# implementation is checked against a second implementation as well as against the published vectors.
# Run: python3 -I tests/oracle.py   (prints name hexvalue lines; tests/run.sh compares them with the C output)
import hashlib
import hmac


def prf(k, label, data, nbytes):
    out = b''
    i = 0
    while len(out) < nbytes:
        out += hmac.new(k, label + b'\0' + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


print("prf1", prf(b'\x0b' * 20, b'prefix', b'Hi There', 24).hex())
print("prf2", prf(b'Jefe', b'prefix-2', b'what do ya want for nothing?', 32).hex())
print("prf3", prf(b'\xaa' * 80, b'prefix-3', b'Test Using Larger Than Block-Size Key - Hash Key First', 48).hex())
print("psk1", hashlib.pbkdf2_hmac('sha1', b'password', b'IEEE', 4096, 32).hex())
print("psk2", hashlib.pbkdf2_hmac('sha1', b'ThisIsAPassword', b'ThisIsASSID', 4096, 32).hex())
pmk = bytes(range(32))
aa = bytes.fromhex('020000000001')
spa = bytes.fromhex('020000000002')
an = bytes((i * 7) & 255 for i in range(32))
sn = bytes((i * 13 + 5) & 255 for i in range(32))
d = min(aa, spa) + max(aa, spa) + min(an, sn) + max(an, sn)
print("ptk", prf(pmk, b'Pairwise key expansion', d, 48).hex())
f = bytearray((i * 3 + 1) & 255 for i in range(121))
f[81:97] = b'\0' * 16
print("mic", hmac.new(bytes(range(16)), bytes(f), hashlib.sha1).digest()[:16].hex())
