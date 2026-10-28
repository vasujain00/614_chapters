import hmac, hashlib, json, os, time

WINDOW_S = 60

def seal(payload: dict, caller_spiffe_id: str, delegation_token_id: str, key: bytes) -> dict:
    env = {"caller": caller_spiffe_id, "scope": delegation_token_id,
           "ts": int(time.time()), "nonce": os.urandom(16).hex(),
           "payload_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}
    body = json.dumps(env, sort_keys=True, separators=(",", ":")).encode()
    env["sig"] = hmac.new(key, body, hashlib.sha256).hexdigest()   # Ed25519 in production
    return env

def verify(env: dict, payload: dict, key: bytes, seen_nonces: dict) -> None:
    sig = env.pop("sig")
    body = json.dumps(env, sort_keys=True, separators=(",", ":")).encode()
    if not hmac.compare_digest(sig, hmac.new(key, body, hashlib.sha256).hexdigest()):
        raise PermissionError("bad signature")
    now = int(time.time())
    if abs(now - env["ts"]) > WINDOW_S:
        raise PermissionError("outside timestamp window")
    if env["nonce"] in seen_nonces:
        raise PermissionError("replay")
    seen_nonces[env["nonce"]] = now        # entries older than WINDOW_S can be evicted
    if hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest() != env["payload_sha256"]:
        raise PermissionError("payload does not match envelope")
