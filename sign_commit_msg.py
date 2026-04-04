#!/usr/bin/env python3
import sys, base64, oqs

with open("private_key.pem", "rb") as f:
    priv = f.read()

msg = sys.argv[1].encode()
sig = oqs.Signature("ML-DSA-65", priv).sign(msg)
sig_b64 = base64.b64encode(sig).decode()

print(f"{msg.decode()}\n\n-----BEGIN PGP SIGNATURE-----\n{sig_b64}\n-----END PGP SIGNATURE-----")
