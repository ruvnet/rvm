"""Contract tests use real Strands registration and a local TLS HTTP server."""
import hashlib
import json
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from rvm_strands import ContextClient, context_tools
from run_box import plan


class IntegrationTests(unittest.TestCase):
    def test_real_strands_tools_preserve_uri_and_do_not_expose_credentials(self):
        class Client:
            def call(self, operation, **args):
                return {"operation": operation, **args}
        tools = context_tools(Client())
        self.assertEqual([t.tool_name for t in tools], ["rvm_search", "rvm_read", "rvm_verify"])
        uri = "ruv://context.example/acme/agent/test/memory?rev=sha256:" + "a" * 64
        self.assertEqual(tools[1](uri=uri)["uri"], uri)
        self.assertEqual(tools[0](uri=uri, query="hello", limit=5)["operation"], "search")
        for t in tools:
            self.assertNotIn("token", json.dumps(t.tool_spec))
        with self.assertRaises(ValueError):
            tools[0](uri=uri, query="hello", limit=21)

    def test_box_plan_pins_inputs_and_refuses_unsupported_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "box"; binary.write_bytes(b"pinned binary")
            policy = root / "policy.dw"; policy.write_text("forbid(principal, action, resource);")
            config = root / "box.toml"
            config.write_text('policy = "policy.dw"\n[agent]\ncommand = ["/bin/echo"]\n')
            hashes = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (binary, config, policy)]
            with patch("run_box.platform.system", return_value="Darwin"):
                self.assertEqual(plan(binary, config, *hashes), [str(binary), "run", "--config", str(config)])
                policy.write_text("changed")
                with self.assertRaises(ValueError): plan(binary, config, *hashes)
            with patch("run_box.platform.system", return_value="Linux"):
                with self.assertRaises(RuntimeError): plan(binary, config, *hashes)

    def test_https_auth_scope_errors_and_redirect_refusal(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key, token = [root / n for n in ("cert.pem", "key.pem", "token")]
            token.write_text("x" * 32)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
            observed = []
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def do_POST(self):
                    observed.append((self.path, self.headers.get("Authorization")))
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    if body["uri"] == "redirect":
                        self.send_response(302); self.send_header("Location", "/stolen")
                        self.end_headers(); return
                    if body["uri"] == "foreign":
                        self.send_response(403); self.end_headers(); return
                    result = json.dumps({"resolved": {"uri": body["uri"]}}).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(result)))
                    self.end_headers(); self.wfile.write(result)
            server = HTTPServer(("localhost", 0), Handler)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert, key)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                client = ContextClient("https://localhost:" + str(server.server_port), token, str(cert))
                self.assertEqual(client.call("read", uri="allowed")["resolved"]["uri"], "allowed")
                for uri in ("foreign", "redirect"):
                    with self.assertRaises(RuntimeError): client.call("read", uri=uri)
                self.assertEqual(len(observed), 3)
                self.assertTrue(all(auth == "Bearer " + "x" * 32 for _, auth in observed))
                with self.assertRaises(ValueError): client.call("put", uri="allowed")
                for origin in ("http://localhost", "https://user@localhost", "https://localhost/path"):
                    with self.assertRaises(ValueError): ContextClient(origin, token)
            finally:
                server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__": unittest.main()
