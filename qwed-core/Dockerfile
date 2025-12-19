FROM python:3.11-slim

LABEL maintainer="QWED-AI"
LABEL description="QWED Core - Reference Implementation"
LABEL version="1.0.0"

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir sympy z3-solver sqlglot

# Copy source
COPY src/ src/
COPY README.md .

# Install package
RUN pip install --no-cache-dir -e .

# Create simple HTTP server for API mode
COPY <<EOF server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from qwed_core import verify, verify_math, verify_logic, verify_code, verify_sql

class QWEDHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "version": "1.0.0"}).encode())
        else:
            self.send_error(404)
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(content_length))
        
        query = body.get('query', '')
        engine = body.get('engine')
        
        if self.path == '/verify':
            result = verify(query, engine=engine)
        elif self.path == '/verify/math':
            result = verify_math(query)
        elif self.path == '/verify/logic':
            result = verify_logic(query)
        elif self.path == '/verify/code':
            result = verify_code(query, body.get('language', 'python'))
        elif self.path == '/verify/sql':
            result = verify_sql(query, body.get('schema'))
        else:
            self.send_error(404)
            return
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(result.to_dict()).encode())

if __name__ == '__main__':
    print("QWED Core starting on port 8080...")
    HTTPServer(('0.0.0.0', 8080), QWEDHandler).serve_forever()
EOF

EXPOSE 8080

CMD ["python", "server.py"]
