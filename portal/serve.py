#!/usr/bin/env python3
"""
Simple local HTTP server to host the Executive Leadership Portal.
Usage:
    python portal/serve.py [port]
"""

import http.server
import socketserver
import os
import sys
import webbrowser

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8080
portal_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(portal_dir)

Handler = http.server.SimpleHTTPRequestHandler

print(f"================================================================================")
print(f" AWS Security & Compliance Executive Portal")
print(f" Local Web Server running at: http://localhost:{PORT}")
print(f" Press Ctrl+C to stop the server.")
print(f"================================================================================")

# Automatically open browser
webbrowser.open(f"http://localhost:{PORT}")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
