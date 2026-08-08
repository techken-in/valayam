import http.server
import socketserver
import time
import argparse

PORT = 8081

class MassTargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Generate thousands of links if on the root
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            # Write 5000 links
            content = "<html><body><h1>Mass Target</h1>\n"
            for i in range(5000):
                content += f"<a href='/endpoint/{i}'>Link {i}</a><br>\n"
            content += "</body></html>"
            
            self.wfile.write(content.encode())
            
        elif self.path.startswith("/endpoint/"):
            # Each endpoint returns a small JSON or text
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "message": "hello world"}')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def log_message(self, format, *args):
        # Mute logging to avoid I/O bottleneck
        pass

def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("", PORT), MassTargetHandler) as httpd:
        print(f"Serving MASS TARGET on port {PORT} with 5000 endpoints")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
