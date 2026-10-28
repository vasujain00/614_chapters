import re, urllib.parse
ALLOWED_HOSTS = {"docs.example.com", "help.example.com"}
LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)\)")          # markdown [text](url)

def rewrite_links(markdown: str, trace_id: str) -> str:
    def repl(m):
        text, url = m.group(1), m.group(2)
        host = urllib.parse.urlparse(url).hostname or ""
        if host not in ALLOWED_HOSTS:
            return f"{text} [link removed: {host or 'invalid'}]"
        safe = "https://r.example.com/go?" + urllib.parse.urlencode({"u": url, "t": trace_id})
        return f"[{canonical_form(text)}]({safe})"                 # link text goes through Layer 1 too
    return LINK.sub(repl, markdown)
