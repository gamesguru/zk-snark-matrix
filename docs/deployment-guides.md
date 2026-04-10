# Deployment Guides: Bridging NGINX to ruma-zk

NGINX does not natively spawn processes or write raw HTTP bodies directly to a binary's `stdin`/`stdout`. It acts as a reverse proxy that speaks network protocols (HTTP, FastCGI, uWSGI).

To bridge NGINX to the `ruma-zk` binary over `stdin`/`stdout`, you need a translation layer. Here are the two standard ways to do it.

---

### Method 1: `fcgiwrap` (The CGI Approach)

If you can slightly modify the binary to output a single HTTP header, `fcgiwrap` is the most direct UNIX approach. It acts as a FastCGI server that spawns your binary, pipes the HTTP request body to `stdin`, and routes `stdout` back to NGINX.

**1. Install fcgiwrap:**

```bash
sudo pacman -S fcgiwrap # Arch
sudo apt install fcgiwrap # Ubuntu
```

**2. NGINX Configuration:**

```nginx
server {
    listen 80;
    server_name api.example.com;

    location /api {
        fastcgi_pass unix:/run/fcgiwrap.socket;
        include fastcgi_params;

        # Point directly to your binary
        fastcgi_param SCRIPT_FILENAME /path/to/your/binary;

        # Optional: Restrict to POST requests (since you are sending JSON)
        limit_except POST { deny all; }
    }
}
```

**The Catch (Header Requirement):**
Your binary will receive the pure JSON on `stdin`. However, because it is operating as a CGI script, its `stdout` **must** begin with a `Content-Type` header followed by two newlines before printing the JSON. If it only outputs pure JSON, NGINX will throw a `502 Bad Gateway`.

Your binary's output logic must look like this:

```rust
println!("Content-Type: application/json\r\n\r\n");
println!("{}", json_payload);
```

---

### Method 2: HTTP Wrapper Daemon (Recommended)

If the binary is strictly a black box that takes pure JSON in and pushes pure JSON out, you must wrap it in a lightweight HTTP server.

This tiny Python daemon listens on a local port, buffers the request, pipes it to the binary, and wraps the output in a proper HTTP response.

**1. The Python Wrapper (`scripts/http_wrapper.py`):**

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import sys

class BinaryHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        input_json = self.rfile.read(content_length)

        # Spawn the binary, pipe stdin/stdout
        # It defaults to reading from STDIN if no --input is provided
        process = subprocess.run(
            ['ruma-zk', 'demo'],
            input=input_json,
            capture_output=True
        )

        self.send_response(200 if process.returncode == 0 else 500)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(process.stdout)

if __name__ == '__main__':
    port = 8080
    print(f"Starting wrapper on port {port}...")
    HTTPServer(('127.0.0.1', port), BinaryHandler).serve_forever()
```

**2. NGINX Configuration:**
You then configure NGINX as a standard reverse proxy pointing to the wrapper daemon.

```nginx
server {
    listen 80;
    server_name api.example.com;

    location /api {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Content-Type application/json;
    }
}
```

---

### Which should you choose?

- Use **Method 1 (`fcgiwrap`)** if you want the absolute lowest overhead and don't mind modifying the binary's output to include `Content-Type: application/json\r\n\r\n`.
- Use **Method 2 (Wrapper)** if the binary cannot be modified, or if you need to maintain a persistent pool of binary processes (spawning a new process for every single HTTP request via `fcgiwrap` is expensive under high load).
