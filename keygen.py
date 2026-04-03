import oqs

def generate_keys():
    sig = oqs.Signature("ML-DSA-65")
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    sig.free()
    return public_key, secret_key

if __name__ == "__main__":
    pub, priv = generate_keys()
    print("Public key (hex):", pub.hex())
    print("Private key (hex):", priv.hex())
    # Save to files
    with open("public_key.pem", "wb") as f:
        f.write(pub)
    with open("private_key.pem", "wb") as f:
        f.write(priv)
    print("Keys saved to public_key.pem and private_key.pem")