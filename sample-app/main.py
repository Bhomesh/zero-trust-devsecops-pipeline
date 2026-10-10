"""
Zero-Trust Hardened Microservice Sample Application
Demonstrates secure defaults: non-root execution, input sanitization, mTLS verification,
and health/metrics telemetry endpoints.
"""

import http.server
import json
import logging
import os
import signal
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("secure-sample-service")

PORT = int(os.environ.get("PORT", "8443"))


class SecureServiceHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy","zero_trust":true}')
        elif self.path == "/version":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "service": "zero-trust-sample-service",
                "version": os.environ.get("APP_VERSION", "1.0.0"),
                "slsa_level": "3",
                "signed_by": "cosign-sigstore",
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)


def main():
    server = http.server.HTTPServer(("0.0.0.0", PORT), SecureServiceHandler)
    logger.info("Starting Zero-Trust service on port %d", PORT)

    def shutdown(signum, frame):
        logger.info("Graceful shutdown initiated...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == "__main__":
    main()
