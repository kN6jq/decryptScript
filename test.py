from des3 import *

if __name__ == '__main__':
    plain_text = """{
  "code" : 0,
  "msg" : "success",
  "data" : [ ]
}"""
    aes_cbc_pkcs7_key = "123456789012345678901234"
    aes_cbc_pkcs7_iv = "87654321"
    data = encrypt_3des_cbc_pkcs7(plain_text,aes_cbc_pkcs7_key,aes_cbc_pkcs7_iv)
    print(data)
    data = decrypt_3des_cbc_pkcs7(data,aes_cbc_pkcs7_key,aes_cbc_pkcs7_iv)
    print(data)
