import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# aes cbc pkcs7 解密数据
def decrypt_aes_cbc_pkcs7(encoded_text: str, aes_cbc_pkcs7_key: str, aes_cbc_pkcs7_iv: str) -> str:
    '''
    :param encoded_text: 需要解密的密文（base64编码）
    :param aes_cbc_pkcs7_key: AES密钥
    :param aes_cbc_pkcs7_iv: AES初始向量
    :return: 解密后的明文
    '''
    # 将密钥和 IV 转换为字节串
    key = aes_cbc_pkcs7_key.encode('utf-8')
    iv = aes_cbc_pkcs7_iv.encode('utf-8')

    # 解码 Base64 编码的密文
    cipher_text = base64.b64decode(encoded_text)

    # 创建 AES 解密器对象
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 解密数据
    decrypted_data = cipher.decrypt(cipher_text)

    # 去掉 PKCS7 填充
    plain_text = unpad(decrypted_data, AES.block_size)

    return plain_text.decode('utf-8')


# aes cbc pkcs7 加密数据
def encrypt_aes_cbc_pkcs7(plain_text: str, aes_cbc_pkcs7_key: str, aes_cbc_pkcs7_iv: str) -> str:
    '''
    :param plain_text: 需要加密的明文
    :param aes_cbc_pkcs7_key: AES密钥
    :param aes_cbc_pkcs7_iv: AES初始向量
    :return: Base64编码的密文
    '''
    # 将密钥和 IV 转换为字节串
    key = aes_cbc_pkcs7_key.encode('utf-8')
    iv = aes_cbc_pkcs7_iv.encode('utf-8')

    # 创建 AES 加密器对象
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 明文填充
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)

    # 加密数据
    cipher_text = cipher.encrypt(padded_text)

    # 编码为 Base64
    encoded_text = base64.b64encode(cipher_text).decode('utf-8')

    return encoded_text


# aes cbc pkcs5 解密数据
def encrypt_aes_cbc_pkcs5(plaintext: str, aes_cbc_pkcs5_key: str, aes_cbc_pkcs5_iv: str) -> str:
    '''
    :param plaintext: 需要加密的明文
    :param key: AES密钥
    :param iv: AES初始向量
    :return: 加密后的密文（base64编码）
    '''
    key_bytes = aes_cbc_pkcs5_key.encode()
    iv_bytes = aes_cbc_pkcs5_iv.encode()
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_text = pad(plaintext.encode(), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode('utf-8')


# aes cbc pkcs5 加密数据
def decrypt_aes_cbc_pkcs5(encoded_text: str, aes_cbc_pkcs5_key: str, aes_cbc_pkcs5_iv: str) -> str:
    '''
    :param encoded_text: 需要解密的密文（base64编码）
    :param key: AES密钥
    :param iv: AES初始向量
    :return: 解密后的明文
    '''
    key_bytes = aes_cbc_pkcs5_key.encode()
    iv_bytes = aes_cbc_pkcs5_iv.encode()
    encrypted_text = base64.b64decode(encoded_text)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    decrypted_text = cipher.decrypt(encrypted_text)
    return unpad(decrypted_text, AES.block_size).decode('utf-8')


def zero_pad(data: bytes, block_size: int) -> bytes:
    """
    使用零填充填充数据
    :param data: 需要填充的数据
    :param block_size: 块大小
    :return: 填充后的数据
    """
    padding_len = (block_size - len(data) % block_size) % block_size
    return data + bytes([0] * padding_len)


def zero_unpad(data: bytes, block_size: int) -> bytes:
    """
    去除零填充
    :param data: 需要去除填充的数据
    :param block_size: 块大小
    :return: 去除填充后的数据
    """
    return data.rstrip(b'\x00')


def encrypt_aes_cbc_zero(plain_text: str, aes_cbc_key: str, aes_cbc_iv: str) -> str:
    '''
    :param plain_text: 需要加密的明文
    :param aes_cbc_key: AES密钥
    :param aes_cbc_iv: AES初始向量
    :return: Base64编码的密文
    '''
    # 将密钥和 IV 转换为字节串
    key = aes_cbc_key.encode('utf-8')
    iv = aes_cbc_iv.encode('utf-8')

    # 创建 AES 加密器对象
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 明文填充
    padded_text = zero_pad(plain_text.encode('utf-8'), AES.block_size)

    # 加密数据
    cipher_text = cipher.encrypt(padded_text)

    # 编码为 Base64
    encoded_text = base64.b64encode(cipher_text).decode('utf-8')

    return encoded_text


def decrypt_aes_cbc_zero(encoded_text: str, aes_cbc_key: str, aes_cbc_iv: str) -> str:
    '''
    :param encoded_text: 需要解密的密文（Base64编码）
    :param aes_cbc_key: AES密钥
    :param aes_cbc_iv: AES初始向量
    :return: 解密后的明文
    '''
    # 将密钥和 IV 转换为字节串
    key = aes_cbc_key.encode('utf-8')
    iv = aes_cbc_iv.encode('utf-8')

    # 解码 Base64 编码的密文
    cipher_text = base64.b64decode(encoded_text)

    # 创建 AES 解密器对象
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 解密数据
    decrypted_data = cipher.decrypt(cipher_text)

    # 去掉零填充
    plain_text = zero_unpad(decrypted_data, AES.block_size)

    return plain_text.decode('utf-8')
