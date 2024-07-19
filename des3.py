from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64

# plain_text = "Hello, World!"
# key = "123456789012345678901234"  # 24字节密钥
# iv = "87654321"  # 8字节IV
#
# # 加密
# encrypted_text = encrypt_3des_cbc_pkcs7(plain_text, key, iv)
# print(f"Encrypted: {encrypted_text}")
#
# # 解密
# decrypted_text = decrypt_3des_cbc_pkcs7(encrypted_text, key, iv)
# print(f"Decrypted: {decrypted_text}")
def encrypt_3des_cbc_pkcs7(plain_text: str, des3_key: str, des3_iv: str) -> str:
    '''
    :param plain_text: 需要加密的明文
    :param des3_key: 3DES密钥（必须为24字节）
    :param des3_iv: 3DES初始向量（必须为8字节）
    :return: 加密后的密文（base64编码）
    '''
    # 将密钥和 IV 转换为字节串
    key = des3_key.encode('utf-8')
    iv = des3_iv.encode('utf-8')

    # 检查密钥和 IV 的长度
    if len(key) != 24:
        raise ValueError("密钥长度必须为24字节")
    if len(iv) != 8:
        raise ValueError("IV 长度必须为8字节")

    # 创建 3DES 加密器对象
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    # 对数据进行 PKCS7 填充
    padded_data = pad(plain_text.encode('utf-8'), DES3.block_size, style='pkcs7')

    # 加密数据
    cipher_text = cipher.encrypt(padded_data)

    # 将加密后的数据进行 Base64 编码
    encoded_cipher_text = base64.b64encode(cipher_text)

    return encoded_cipher_text.decode('utf-8')

def decrypt_3des_cbc_pkcs7(encoded_text: str, des3_key: str, des3_iv: str) -> str:
    '''
    :param encoded_text: 需要解密的密文（base64编码）
    :param des3_key: 3DES密钥（必须为24字节）
    :param des3_iv: 3DES初始向量（必须为8字节）
    :return: 解密后的明文
    '''
    # 将密钥和 IV 转换为字节串
    key = des3_key.encode('utf-8')
    iv = des3_iv.encode('utf-8')

    # 检查密钥和 IV 的长度
    if len(key) != 24:
        raise ValueError("密钥长度必须为24字节")
    if len(iv) != 8:
        raise ValueError("IV 长度必须为8字节")

    # 解码 Base64 编码的密文
    cipher_text = base64.b64decode(encoded_text)

    # 创建 3DES 解密器对象
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    # 解密数据
    decrypted_data = cipher.decrypt(cipher_text)

    # 去掉 PKCS7 填充
    plain_text = unpad(decrypted_data, DES3.block_size, style='pkcs7')

    return plain_text.decode('utf-8')
