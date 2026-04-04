<<<<<<< HEAD
import oqs
import hashlib

# Step 1: Generate keys
sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()
secret_key = sig.export_secret_key()
print(f"✅ Keys generated. Public key size: {len(public_key)} bytes")

# Step 2: Simulate commit data and hash it
commit_data = b"tree abc123\nauthor Alice\nmessage Fix bug"
commit_hash = hashlib.sha256(commit_data).digest()
print(f"📝 Commit hash: {commit_hash.hex()[:16]}...")

# Step 3: Sign
signature = sig.sign(commit_hash, secret_key)
print(f"✍️ Signature created. Size: {len(signature)} bytes")

# Step 4: Verify
is_valid = sig.verify(commit_hash, signature, public_key)
print(f"🔍 Verification: {'✅ PASS' if is_valid else '❌ FAIL'}")

=======
import oqs
import hashlib

# Step 1: Generate keys
sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()
secret_key = sig.export_secret_key()
print(f"✅ Keys generated. Public key size: {len(public_key)} bytes")

# Step 2: Simulate commit data and hash it
commit_data = b"tree abc123\nauthor Alice\nmessage Fix bug"
commit_hash = hashlib.sha256(commit_data).digest()
print(f"📝 Commit hash: {commit_hash.hex()[:16]}...")

# Step 3: Sign
signature = sig.sign(commit_hash, secret_key)
print(f"✍️ Signature created. Size: {len(signature)} bytes")

# Step 4: Verify
is_valid = sig.verify(commit_hash, signature, public_key)
print(f"🔍 Verification: {'✅ PASS' if is_valid else '❌ FAIL'}")

>>>>>>> a411c3e475eeeee2ee3279afa143dab5350fae0d
sig.free()