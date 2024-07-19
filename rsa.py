# rsa部分
# 加载 RSA 私钥
import base64
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

private_key = 'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIyd02MFuELdMEbKJ498JZLiRK37PY2CycdrpyzNKVYHatEbhW0ddFIMDjwCBDFkbP0ZQPmu00iLb+4u1dE722rjdStxgXoGB2dl8XazVwr2X0uJLCP9UqoLyWGy/ZUAxY0B8zOil39UUBFFKNvkdhVDmuraUtugHlMzRZaZn5XHAgMBAAECgYAtRj+ieVv7g1Yg5MPaCgHbCilMz0DhSEQJhlrcLO5rOZYl37OVD0+9fw4yOf/5mzkQQMpP2f9DM0oFqWTEqn4ZrYzJuQo6C27zWaFreof1wGqteVWaILy7MVnkdmVft31rNCUSzfj2k9HBXUXHtGitIextGvcSLknJd+9Q6/oeCQJBAPE8/B8VMU/RjLHdkEkmbmoeWbkEMTb4TPBrwSBTXZSX6y2UP2ZRy+BG1H9VB/y6yUnUM4zqRWK2eLKcq2SFqCUCQQCVOJgSpR88c9DSIb3SQQK+jFv0+eOhOvqOf6LHB3ZwQMSqjFER5ccZCoVrasakeodnWMlWjdSq3LNz4AyEyNx7AkA/oPxHHonhKb5Yc75I7RAWgWbc/BQXEasJhwJrilGWjfOEFCQc0tpZj5Ug+MagjIvnI0dtlaUzgjmXsucqHm7ZAkBCt7kWrQlYSBgXu8pZVYPamnsK/yeNkQcx61NmVanY6ryD3JTqwafRRGj+7BDAvaAIzyPGNUfe1SrPJl+yhvQ9AkEAsAXdsFH9tB5vIRueK21FpMpSAUTT3EwsXY3F5qEhlb5aasGt16sE4i2bSB2yz7lZbSOuIm34LfVDuAuNS9h6rg=='
public_key = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMndNjBbhC3TBGyiePfCWS4kSt+z2NgsnHa6cszSlWB2rRG4VtHXRSDA48AgQxZGz9GUD5rtNIi2/uLtXRO9tq43UrcYF6BgdnZfF2s1cK9l9LiSwj/VKqC8lhsv2VAMWNAfMzopd/VFARRSjb5HYVQ5rq2lLboB5TM0WWmZ+VxwIDAQAB'


# 解密数据
def rsa_decrypt(text_encrypted_base64: str, private_key: str) -> str:
    '''
    :param text_encrypted_base64: 使用公钥加密后的密文
    :param private_key: 私钥
    :return: 解密后的明文
    '''
    private_key = [private_key[64 * _: 64 * _ + 64] for _ in range(0, len(private_key) // 64 + 1)]
    private_key = [_ for _ in private_key if _]
    private_key = '''-----BEGIN PRIVATE KEY-----\n''' + '\n'.join(private_key) + '''\n-----END PRIVATE KEY-----'''
    private_key = private_key.encode()
    # 字符串指定编码（转为bytes）
    text_encrypted_base64 = text_encrypted_base64.encode('utf-8')
    # base64解码
    text_encrypted = base64.b64decode(text_encrypted_base64)
    # 构建私钥对象
    cipher_private = PKCS1_v1_5.new(RSA.importKey(private_key))
    # 解密（bytes）
    text_decrypted = cipher_private.decrypt(text_encrypted, Random.new().read)
    # 解码为字符串
    text_decrypted = text_decrypted.decode()
    return text_decrypted


# 加密数据
def rsa_encrypt(text: str, public_key: str) -> str:
    '''
    :param text: 需要加密的明文
    :param public_key: 公钥
    :return: 加密后的密文（base64编码）
    '''
    # 将公钥字符串分割成多个64字符的块
    public_key = [public_key[64 * _: 64 * _ + 64] for _ in range(0, len(public_key) // 64 + 1)]
    public_key = [_ for _ in public_key if _]
    public_key = '''-----BEGIN PUBLIC KEY-----\n''' + '\n'.join(public_key) + '''\n-----END PUBLIC KEY-----'''
    public_key = public_key.encode()
    # 字符串指定编码（转为bytes）
    text = text.encode('utf-8')
    # 创建RSA公钥对象
    key = RSA.importKey(public_key)
    # 创建加密对象
    cipher_public = PKCS1_v1_5.new(key)
    # 加密（bytes）
    text_encrypted = cipher_public.encrypt(text)
    # base64编码
    text_encrypted_base64 = base64.b64encode(text_encrypted)
    # 转换为字符串
    text_encrypted_base64 = text_encrypted_base64.decode()
    return text_encrypted_base64
