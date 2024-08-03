import http.server
import ssl

server_address = ('localhost', 8000)
print(f"Serving on https://{server_address[0]}:{server_address[1]}")

httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

tls_cipher_suites = (
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
)

httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True,
                               certfile="cert.pem",
                               keyfile="key.pem",
                               ssl_version=ssl.PROTOCOL_TLS,
                               ciphers=":".join(tls_cipher_suites))
httpd.serve_forever()
