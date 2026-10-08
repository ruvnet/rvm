"""Reusable read-only Strands tools for the RVM HTTPS context gateway.

Credentials and endpoint configuration belong to the host, never tool arguments.
The server's capability scope is authoritative. This adapter is not a sandbox.
"""
import json
import ssl
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    """Never forward the gateway credential to a redirect destination."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ContextClient:
    """Pinned HTTPS origin and bounded read-only gateway requests."""
    def __init__(self, endpoint, token_file, ca_file=None):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("endpoint must be a plain HTTPS origin")
        self.endpoint = endpoint.rstrip("/")
        self.token = Path(token_file).read_bytes().strip()
        if len(self.token) < 32 or any(c < 33 or c > 126 for c in self.token):
            raise ValueError("token must contain at least 32 printable ASCII bytes")
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=context))

    def call(self, operation, **arguments):
        if operation not in ("search", "read", "verify"):
            raise ValueError("operation is not in the read-only tool surface")
        body = json.dumps(arguments).encode()
        if len(body) > 64 * 1024:
            raise ValueError("request exceeds 64 KiB")
        request = Request(self.endpoint + "/v1/" + operation, data=body,
                          headers={"Content-Type": "application/json",
                                   "Authorization": "Bearer " + self.token.decode("ascii")})
        try:
            with self.opener.open(request, timeout=30) as response:
                payload = response.read(32 * 1024 * 1024 + 1)
            if len(payload) > 32 * 1024 * 1024:
                raise ValueError("response exceeds 32 MiB")
            return json.loads(payload)
        except HTTPError as error:
            # Do not return server error bodies or credentials to the model.
            raise RuntimeError("RVM gateway refused request: HTTP " + str(error.code)) from None


def context_tools(client):
    """Create tools with the real Strands decorator; no model invocation required."""
    from strands import tool

    @tool
    def rvm_search(uri: str, query: str, limit: int = 5) -> dict:
        """Search capability-governed RVM context and return revision-pinned hits.

        Args:
            uri: Canonical ruv:// scope allowed by the gateway.
            query: Search text.
            limit: Number of results, from 1 to 20.
        """
        if not 1 <= limit <= 20:
            raise ValueError("limit must be between 1 and 20")
        return client.call("search", uri=uri, query=query, limit=limit)

    @tool
    def rvm_read(uri: str) -> dict:
        """Read an RVM context object; prefer a revision-pinned ruv:// URI.

        Args:
            uri: Canonical ruv:// URI, including revision for reproducibility.
        """
        return client.call("read", uri=uri)

    @tool
    def rvm_verify(uri: str) -> dict:
        """Verify the RVF object behind a capability-governed ruv:// URI.

        Args:
            uri: Canonical ruv:// URI of the object to verify.
        """
        return client.call("verify", uri=uri)

    return [rvm_search, rvm_read, rvm_verify]
