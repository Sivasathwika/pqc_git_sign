import hashlib
import oqs
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

with open("public_key.pem", "rb") as f:
    PUBLIC_KEY = f.read()
with open("private_key.pem", "rb") as f:
    SECRET_KEY = f.read()

def sign_commit(commit_hash: bytes) -> bytes:
    with oqs.Signature("ML-DSA-65", SECRET_KEY) as signer:
        return signer.sign(commit_hash)

def verify_commit(commit_hash: bytes, signature: bytes) -> bool:
    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(commit_hash, signature, PUBLIC_KEY)

commits = []
local_commits = []
attacker_mode = False   # global toggle

def compute_commit_hash(msg: str, files: str, parent_hash: str, timestamp: str) -> str:
    content = f"message:{msg}\nfiles:{files}\nparent:{parent_hash}\ntime:{timestamp}"
    return hashlib.sha256(content.encode()).hexdigest()

def create_commit_object(msg: str, files: str, author: str = "You", tamper: bool = False) -> dict:
    all_commits = commits + local_commits
    parent = all_commits[-1]["full_hash"] if all_commits else ""
    timestamp = datetime.now().isoformat()
    full_hash = compute_commit_hash(msg, files, parent, timestamp)
    short_id = full_hash[:7]
    sig = sign_commit(bytes.fromhex(full_hash))
    verified = verify_commit(bytes.fromhex(full_hash), sig)
    commit = {
        "id": short_id,
        "full_hash": full_hash,
        "msg": msg,
        "files": files,
        "author": author,
        "date": "just now",
        "timestamp": timestamp,
        "parent": parent,
        "signature": sig.hex(),
        "verified": verified
    }
    # If attacker mode is on, tamper the commit after signing (simulate MITM)
    if tamper:
        commit['msg'] = commit['msg'] + " [TAMPERED BY ATTACKER]"
        commit['files'] = commit['files'] + "\n# malicious change"
        # Do NOT change full_hash or signature – this mimics an external attack
    return commit

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/attacker-mode', methods=['POST'])
def set_attacker_mode():
    global attacker_mode
    data = request.json
    attacker_mode = data.get('enabled', False)
    print(f"[*] Attacker mode: {'ON' if attacker_mode else 'OFF'}")
    return jsonify({"attacker_mode": attacker_mode}), 200

@app.route('/commits', methods=['GET'])
def get_commits():
    all_commits = commits + local_commits
    for c in all_commits:
        sig = bytes.fromhex(c["signature"])
        crypto_valid = verify_commit(bytes.fromhex(c["full_hash"]), sig)
        recomputed = compute_commit_hash(c['msg'], c['files'], c.get('parent', ''), c['timestamp'])
        content_matches = (recomputed == c["full_hash"])
        c["verified"] = crypto_valid and content_matches
    return jsonify(all_commits)

@app.route('/commit-details/<commit_id>', methods=['GET'])
def commit_details(commit_id):
    all_commits = commits + local_commits
    for c in all_commits:
        if c['id'] == commit_id:
            sig = bytes.fromhex(c["signature"])
            crypto_valid = verify_commit(bytes.fromhex(c["full_hash"]), sig)
            recomputed = compute_commit_hash(c['msg'], c['files'], c.get('parent', ''), c['timestamp'])
            content_matches = (recomputed == c["full_hash"])
            is_verified = crypto_valid and content_matches
            return jsonify({
                "id": c['id'],
                "msg": c['msg'],
                "files": c['files'],
                "author": c['author'],
                "date": c['date'],
                "full_hash": c['full_hash'],
                "recomputed_hash": recomputed,
                "crypto_valid": crypto_valid,
                "content_matches": content_matches,
                "verified": is_verified,
                "signature_hex": c['signature'][:64] + "..."
            })
    return jsonify({"error": "Commit not found"}), 404

@app.route('/commit', methods=['POST'])
def commit():
    data = request.json
    msg = data.get('message', '').strip()
    files = data.get('files', '').strip()
    if not msg:
        return jsonify({"error": "Message required"}), 400
    new = create_commit_object(msg, files, tamper=attacker_mode)
    local_commits.append(new)
    print(f"[*] New commit created: {new['id']} - {msg} (Attacker: {attacker_mode})")
    return jsonify(new), 201

@app.route('/push', methods=['POST'])
def push():
    global commits, local_commits
    if not local_commits:
        return jsonify({"message": "No local commits"}), 200
    for c in local_commits:
        sig = bytes.fromhex(c["signature"])
        if not verify_commit(bytes.fromhex(c["full_hash"]), sig):
            return jsonify({"error": f"Invalid signature in {c['id']}"}), 400
    commits.extend(local_commits)
    local_commits = []
    print(f"[*] Pushed {len(commits)} commits to remote")
    return jsonify({"message": f"Pushed {len(commits)} commits"}), 200

@app.route('/pull', methods=['POST'])
def pull():
    for c in commits:
        sig = bytes.fromhex(c["signature"])
        c["verified"] = verify_commit(bytes.fromhex(c["full_hash"]), sig)
    print("[*] Pulled commits from remote")
    return jsonify({"message": f"Pulled {len(commits)} commits"}), 200

@app.route('/merge', methods=['POST'])
def merge():
    data = request.json
    branch = data.get('source_branch', '').strip()
    if not branch:
        return jsonify({"error": "Branch required"}), 400
    merge_commit = create_commit_object(f"Merge branch '{branch}'", "Merge commit", "Merger", tamper=attacker_mode)
    local_commits.append(merge_commit)
    print(f"[*] Merged branch '{branch}' -> new commit {merge_commit['id']}")
    return jsonify({"message": f"Merged '{branch}'", "commit": merge_commit}), 200

if __name__ == '__main__':
    if not commits:
        # Create three clean, verified commits (no tampering)
        c1 = create_commit_object("Initial commit", "README.md", "Alice", tamper=False)
        c1["date"] = "2 days ago"
        c2 = create_commit_object("Add PQC signing logic", "sign.py", "Bob", tamper=False)
        c2["date"] = "1 day ago"
        c3 = create_commit_object("Integrate ML-DSA-65", "verify.py", "Alice", tamper=False)
        c3["date"] = "12 hours ago"
        commits.extend([c1, c2, c3])
        print("[*] Loaded 3 verified demo commits (attacker mode OFF)")
    app.run(debug=True, host='0.0.0.0', port=5000)
