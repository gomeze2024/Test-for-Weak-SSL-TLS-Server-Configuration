import http.server
import ssl

server_address = ('localhost', 8000)
print(f"Serving on https://{server_address[0]}:{server_address[1]}")

httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, server_side = True, certfile="cert.pem", keyfile="key.pem", ssl_version=ssl.PROTOCOL_TLS)
httpd.serve_forever()