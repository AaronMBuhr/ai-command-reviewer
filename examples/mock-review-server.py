#!/usr/bin/env python3
"""Tiny HTTP reviewer for local testing.

A reference implementation of the `reviewer.url` contract: read the review JSON
from the request body, return a decision. Use it to develop your own reviewer
service without spending API calls.

Run:
    python examples/mock-review-server.py

Then point the hook at it and feed in a sample payload:
    export CC_AI_REVIEW_URL=http://127.0.0.1:8765/review
    python .claude/hooks/safe-command-review-hook.py < examples/hook-input-python-c.json
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

ADDRESS = ("127.0.0.1", 8765)


def review(payload: dict) -> dict:
    """Decide on one command.

    The response contract is `decision` plus a one-sentence `headline` and a list
    of specific `particulars`. A flat `reason` string is still accepted for
    backwards compatibility, but new reviewers should return the structured form
    -- the hook renders particulars as bullets under the headline.
    """
    command = str(payload.get("command", "")).lower()
    flags = list(payload.get("local_flags") or [])

    if "rm -rf /" in command or "git clean -fdx" in command:
        return {
            "decision": "deny",
            "headline": "Destructive command that would remove data irrecoverably.",
            "particulars": ["Mock reviewer: matched a known-destructive shape."],
            "dont_ask_again_safe": False,
            "flags": flags + ["mock-deny"],
        }

    if "python -c" in command or "node -e" in command:
        return {
            "decision": "ask",
            "headline": "Inline interpreter code whose effect is not visible from the command.",
            "particulars": [
                "Mock reviewer: approve this exact command only.",
                "A wildcard approval would cover arbitrary future code.",
            ],
            "dont_ask_again_safe": False,
            "flags": flags + ["mock-inline-code"],
        }

    return {
        "decision": "allow",
        "headline": "Command appears low-risk.",
        "particulars": [],
        "dont_ask_again_safe": True,
        "flags": flags + ["mock-allow"],
    }


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {
                "decision": "deny",
                "headline": "Reviewer could not parse the request body as JSON.",
            })
            return
        self._respond(200, review(payload))

    def _respond(self, status: int, result: dict) -> None:
        encoded = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        # Quieter than the default one-line-per-request access log.
        pass


def main() -> None:
    server = HTTPServer(ADDRESS, Handler)
    print(f"Mock reviewer listening on http://{ADDRESS[0]}:{ADDRESS[1]}/review")
    server.serve_forever()


if __name__ == "__main__":
    main()
