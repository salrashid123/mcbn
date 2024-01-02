import ssl
import http.client

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.set_ciphers('PSK')

def callback(hint):
    return 'Client1', bytes.fromhex('6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4') 

context.set_psk_client_callback(callback)

connection = http.client.HTTPSConnection('127.0.0.1', 8081, context = context)
headers = {}
connection.request('GET', '/', None, headers)
response = connection.getresponse()
print(response.read().decode())