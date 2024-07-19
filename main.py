from mitmproxy import http

import rsa
from rsa import *
from aes import *

aes_cbc_pkcs7_key = '7Y6MJwziQwHmfRGck6xEZw=='

class AutoDecoderClass(object):

    def request(self, flow: http.HTTPFlow):
        pass

    def response(self, flow: http.HTTPFlow):
        if flow.response.headers.get("ASE-IV") != "":
            iv = flow.response.headers.get("ASE-IV")
            div = rsa_decrypt(iv, rsa.private_key)
            print(div)
            content = decrypt_cbc_pkcs7(flow.response.content.decode('utf-8'),aes_cbc_pkcs7_key, div)
            print(content)
            flow.request.content = content.encode('utf-8')

addons = [
    AutoDecoderClass()
]
