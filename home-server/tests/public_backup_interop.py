"""Independent LAB2 interoperability check. Synthetic test keys only."""
import base64
import pathlib
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

ROOT = pathlib.Path(__file__).resolve().parents[2]
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def b64(data):
    return base64.b64encode(data).decode("ascii")

def fixture():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    key, iv = os.urandom(32), os.urandom(12)
    plain = b"Python independent LAB2 interoperability test"
    wrapped = private.public_key().encrypt(key, OAEP)
    header = b"LAB2" + len(wrapped).to_bytes(2, "big") + wrapped + iv
    blob = header + AESGCM(key).encrypt(iv, plain, header)
    fields = {
        "public": b64(private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
        "private": b64(private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        "plain": b64(plain), "blob": b64(blob),
    }
    path = ROOT / "app/src/test/resources/public-backup-python.properties"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Synthetic test keys, never use for real accounts\n" + "\n".join(f"{k}={v}" for k, v in fields.items()) + "\n", encoding="ascii")
    print("Independent Python fixture generated.")

def verify():
    path = ROOT / "app/build/public-backup-jca.properties"
    fields = dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))
    # Java Properties escapes '=' in values; Base64 padding must be restored.
    fields = {k: v.replace("\\=", "=") for k, v in fields.items()}
    blob = base64.b64decode(fields["blob"])
    private = serialization.load_der_private_key(base64.b64decode(fields["private"]), password=None)
    assert blob[:4] == b"LAB2" and int.from_bytes(blob[4:6], "big") == 384
    key = private.decrypt(blob[6:390], OAEP)
    plain = AESGCM(key).decrypt(blob[390:402], blob[402:], blob[:402])
    assert plain == base64.b64decode(fields["plain"])
    print("Python independently decrypted the JCA LAB2 backup: PASS.")

if __name__ == "__main__":
    fixture() if "--fixture" in sys.argv else verify()
