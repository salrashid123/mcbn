
import ssl

from flask import Flask
import os

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.set_ciphers('PSK')

psk_table = { 'Client1': bytes.fromhex('6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4') }

def callback(identity):
    print(identity)
    return psk_table.get(identity, b'')

context.set_psk_server_callback(callback, 'Client1')

app = Flask(__name__)

@app.route('/')
def index():
    return 'ok'

if __name__ == '__main__':
    app.run(debug=True, ssl_context=context, port=8081)