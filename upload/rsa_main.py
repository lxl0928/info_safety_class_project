#!/usr/bin/env python3
# coding=utf-8

import rsa


def encrypt(data):
    """
    静态方法,data是要加密的数据,为bytes类型
    返回依次为: 公钥,私钥,签名证书,均为bytes类型
    """
    if not isinstance(data, bytes):
        raise TypeError("data type must bytes")

    pub_key, pri_key = rsa.newkeys(1024)
    signature = rsa.sign(data, pri_key, 'SHA-1')
    return pub_key.save_pkcs1(), pri_key.save_pkcs1(), signature


def decode(data, sign, pub_key):
    """
    静态方法,data是源数据,即要验证签名的内容,类型为bytes
    sign为签名文件,类型为bytes,pub_key为公钥bytes

    返回:验证成功为True,否则为False
    """
    if not isinstance(data, bytes):
        raise TypeError("data type must bytes")
    if not isinstance(sign, bytes):
        raise TypeError("sing type must bytes")
    if not isinstance(pub_key, bytes):
        raise TypeError("pub_key type must bytes")
    try:
        pub_key = rsa.PublicKey.load_pkcs1(pub_key)
        rsa.verify(data, sign, pub_key)
    except:
        return False
    else:
        return True
