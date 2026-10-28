import hashlib, hmac, json

class ToolRegistry:
    def __init__(self, approved: dict[str, str]):
        # tool name -> SHA-256 of the canonical description recorded at approval time
        self.approved = dict(approved)
        self.live = {}                   # tool name -> current description from the MCP server

    @staticmethod
    def canonical(desc: dict) -> str:
        # Only the fields the model reads: name, description text, input schema.
        return hashlib.sha256(json.dumps(
            {"name": desc["name"], "description": desc["description"],
             "inputSchema": desc.get("inputSchema", {})},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def verify_hash(self, tool_name: str) -> bool:
        pinned = self.approved.get(tool_name)
        current = self.live.get(tool_name)
        if pinned is None or current is None:
            return False                 # unknown tool: never approved, or not served
        return hmac.compare_digest(pinned, self.canonical(current))
