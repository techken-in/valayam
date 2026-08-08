import http.server
import socketserver
import time
import json

PORT = 8080

class MockVulnerableHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Welcome to Mock Target</h1><a href='/admin'>Admin</a> <a href='/api/v1/users'>Users API</a></body></html>")
            
        elif self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Admin Panel</h1><!-- Admin password is 'admin123' --></body></html>")
            
        elif self.path == "/api/v1/users":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([{"id": 1, "name": "Admin", "email": "admin@example.com"}]).encode())
            
        elif self.path.startswith("/slow"):
            time.sleep(2)
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Slow response")
            
        elif self.path.startswith("/loadtest"):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Load test endpoint")
            
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def log_message(self, format, *args):
        pass

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("", PORT), MockVulnerableHandler) as httpd:
        print(f"Serving mock target on port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
