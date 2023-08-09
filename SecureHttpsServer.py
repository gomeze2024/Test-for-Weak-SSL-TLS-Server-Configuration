import http.server
import ssl

server_address = ('localhost', 8000)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

tls_cipher_suites = (
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
)

httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True,
                               certfile="server.pem",
                               keyfile="key.pem",
                               ciphers=":".join(tls_cipher_suites))
httpd.serve_forever()