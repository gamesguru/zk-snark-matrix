import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# ruma-zk HTTP Wrapper Template
# Allows Synapse or Continuum servers to communicate with the ZK Prover over HTTP.


class BinaryHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the raw JSON body from the incoming request
        content_length = int(self.headers.get("Content-Length", 0))
        input_json = self.rfile.read(content_length)

        # Spawn the ruma-zk binary
        # It defaults to reading from STDIN if no --input is provided
        process = subprocess.run(
            ["ruma-zk", "demo"], input=input_json, capture_output=True
        )

        # Return the result as an HTTP response
        self.send_response(200 if process.returncode == 0 else 500)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(process.stdout)


if __name__ == "__main__":
    # Listen on localhost by default for security (reverse proxy should handle TLS)
    port = 8080
    print(f"Starting ZK Prover Wrapper on port {port}...")
    HTTPServer(("127.0.0.1", port), BinaryHandler).serve_forever()
