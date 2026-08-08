from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

class CorsHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "https://evil.com")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "https://evil.com")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8111), CorsHandler)
    server.serve_forever()
