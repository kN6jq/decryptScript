from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad,pad
from base64 import b64encode
import base64

# PKCS5 和 PKCS7 填充在大多数情况下是相同的，但 pycryptodome 使用 pkcs7。
# plain_text = "Hello, World!"
# key = "12345678"  # 8字节密钥
# iv = "87654321"  # 8字节IV
#
# # 加密
# encrypted_text = encrypt_des_cbc_pkcs5(plain_text, key, iv)
# print(f"Encrypted: {encrypted_text}")
#
# # 解密
# decrypted_text = decrypt_des_cbc_pkcs5(encrypted_text, key, iv)
# print(f"Decrypted: {decrypted_text}")

def encrypt_des_cbc_pkcs5(plain_text: str, des_cbc_pkcs5_key: str, des_cbc_pkcs5_iv: str) -> str:
    '''
    :param plain_text: 需要加密的明文
    :param des_cbc_pkcs5_key: DES密钥（必须为8字节）
    :param des_cbc_pkcs5_iv: DES初始向量（必须为8字节）
    :return: 加密后的密文（base64编码）
    '''
    # 将密钥和 IV 转换为字节串
    key = des_cbc_pkcs5_key.encode('utf-8')
    iv = des_cbc_pkcs5_iv.encode('utf-8')

    # 检查密钥和 IV 的长度
    if len(key) != 8:
        raise ValueError("密钥长度必须为8字节")
    if len(iv) != 8:
        raise ValueError("IV 长度必须为8字节")

    # 创建 DES 加密器对象
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # 对数据进行 PKCS5 填充
    padded_data = pad(plain_text.encode('utf-8'), DES.block_size, style='pkcs7')

    # 加密数据
    cipher_text = cipher.encrypt(padded_data)

    # 将加密后的数据进行 Base64 编码
    encoded_cipher_text = base64.b64encode(cipher_text)

    return encoded_cipher_text.decode('utf-8')

def decrypt_des_cbc_pkcs5(encoded_text: str, des_cbc_pkcs5_key: str, des_cbc_pkcs5_iv: str) -> str:
    '''
    :param encoded_text: 需要解密的密文（base64编码）
    :param des_cbc_pkcs5_key: DES密钥（必须为8字节）
    :param des_cbc_pkcs5_iv: DES初始向量（必须为8字节）
    :return: 解密后的明文
    '''
    # 将密钥和 IV 转换为字节串
    key = des_cbc_pkcs5_key.encode('utf-8')
    iv = des_cbc_pkcs5_iv.encode('utf-8')

    # 检查密钥和 IV 的长度
    if len(key) != 8:
        raise ValueError("密钥长度必须为8字节")
    if len(iv) != 8:
        raise ValueError("IV 长度必须为8字节")

    # 解码 Base64 编码的密文
    cipher_text = base64.b64decode(encoded_text)

    # 创建 DES 解密器对象
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # 解密数据
    decrypted_data = cipher.decrypt(cipher_text)

    # 去掉 PKCS5 填充
    plain_text = unpad(decrypted_data, DES.block_size, style='pkcs7')

    return plain_text.decode('utf-8')