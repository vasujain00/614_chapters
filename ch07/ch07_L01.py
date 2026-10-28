# Full implementation: github.com/mastering-agentic-security/ch7

from dataclasses import dataclass, field, asdict
from typing import List, Optional
import time, hashlib, hmac, json

class DelegationError(Exception):
    """Raised on any attenuation or verification failure. Never use assert for
    security checks: `python -O` strips assertions entirely."""

@dataclass(frozen=True)
class DelegationToken:
    issuer_id: str           # identity of delegating agent
    subject_id: str          # identity of receiving agent
    capabilities: tuple      # scoped subset of issuer's caps (immutable)
    resource_scope: str      # specific resource this covers
    issued_at: float
    expires_at: float        # never exceeds parent token's expiry
    parent_token_hash: Optional[str] = None  # chain linkage
    depth_remaining: int = 3  # max further delegation hops
    signature: str = ""      # HMAC-SHA256 over every field above

    # --- canonical form: every field, sorted keys, no signature ---
    def _canonical(self) -> bytes:
        body = asdict(self); body.pop("signature")
        body["capabilities"] = sorted(body["capabilities"])
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def _hash(self) -> str:
        # Full 256-bit digest over the full canonical body. Truncating to 64
        # bits, or hashing only three fields, lets a child token forge scope,
        # expiry or depth without breaking the chain.
        return hashlib.sha256(self._canonical()).hexdigest()

    @classmethod
    def mint(cls, key: bytes, **fields) -> "DelegationToken":
        unsigned = cls(**fields)
        sig = hmac.new(key, unsigned._canonical(), hashlib.sha256).hexdigest()
        return cls(**{**fields, "signature": sig})

    def verify(self, key: bytes, parent: Optional["DelegationToken"] = None,
               now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        expected = hmac.new(key, self._canonical(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, self.signature):
            raise DelegationError("bad signature")
        if now >= self.expires_at:
            raise DelegationError("expired")
        if parent is not None:
            parent.verify(key, now=now)                 # walk the chain up
            if self.parent_token_hash != parent._hash():
                raise DelegationError("chain broken")
            if self.issuer_id != parent.subject_id:
                raise DelegationError("issuer is not parent subject")
            if not set(self.capabilities) <= set(parent.capabilities):
                raise DelegationError("capabilities not attenuated")
            if not self._scope_within(self.resource_scope, parent.resource_scope):
                raise DelegationError("resource scope not attenuated")
            if self.expires_at > parent.expires_at:
                raise DelegationError("expiry exceeds parent")
            if self.depth_remaining != parent.depth_remaining - 1:
                raise DelegationError("depth not decremented")

    @staticmethod
    def _scope_within(child: str, parent: str) -> bool:
        # Scopes are path-like: "orders/*" covers "orders/123", not "refunds/*".
        if parent.endswith("/*"):
            return child == parent or child.startswith(parent[:-1])
        return child == parent

    def attenuate(self, key: bytes, receiver_id: str, caps_subset: List[str],
                  resource: str, ttl_seconds: int = 300) -> "DelegationToken":
        now = time.time()
        if not set(caps_subset) <= set(self.capabilities):
            raise DelegationError("cannot grant capabilities the issuer lacks")
        if not self._scope_within(resource, self.resource_scope):
            raise DelegationError("cannot widen resource scope")
        if self.depth_remaining <= 0:
            raise DelegationError("delegation depth exhausted")
        expires = min(now + ttl_seconds, self.expires_at)
        return DelegationToken.mint(
            key,
            issuer_id=self.subject_id, subject_id=receiver_id,
            capabilities=tuple(sorted(caps_subset)), resource_scope=resource,
            issued_at=now, expires_at=expires,
            parent_token_hash=self._hash(),
            depth_remaining=self.depth_remaining - 1,
        )
