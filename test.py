from aes import encrypt_cbc_pkcs7, encrypt_cbc_pkcs5,encrypt_cbc_zero

from aes import decrypt_cbc_pkcs7,decrypt_cbc_pkcs5,decrypt_cbc_zero

if __name__ == '__main__':
    plain_text = """{
  "code" : 0,
  "msg" : "success",
  "data" : [ ]
}"""
    aes_cbc_pkcs7_key = "7Y6MJwziQwHmfRGck6xEZw=="
    aes_cbc_pkcs7_iv = "^S&mm@w5^#C2008J"
    data = encrypt_cbc_zero(plain_text,aes_cbc_pkcs7_key,aes_cbc_pkcs7_iv)
    print(data)
    data = decrypt_cbc_zero(data,aes_cbc_pkcs7_key,aes_cbc_pkcs7_iv)
    print(data)
