#!/bin/env python2
#coding:utf-8
from random import randint
__DEBUG__ = True 

def random_string(length):
    import M2Crypto.Rand
    return M2Crypto.Rand.rand_bytes(length)

##############################################
#能直接用 m2crypto 调用 rc4, rsa,des之类的解密

#@profile
def crypt(buf, key):
    buf = list(buf)
    keylen = len(key)
    for i in xrange(len(buf)):
        buf[i] = chr(ord(buf[i]) ^ ord(key[i % keylen]))
    #if __DEBUG__:
    #    print out
    return ''.join(buf)

def decrypt(buf, key):
    if not isinstance(buf, str) or not isinstance(key, str):
        return False
    return crypt(buf, key)

def encrypt(buf, key):
    if not isinstance(buf, str) or not isinstance(key, str):
        return False
    return crypt(buf, key)
##############################################
if __name__ == "__main__":
    datas = encrypt("Plaintext", 'key')
    rnd_str = random_string(2000)
    print rnd_str == decrypt(encrypt(rnd_str, key="this is tes"), key='this is tes')
    #rnd_str = random_string(3)
    #print rnd_str == decrypt(encrypt(rnd_str, key="this is test"), key='this is test')
    #rnd_str = random_string(2000)
    #print rnd_str == decrypt(encrypt(rnd_str, key="this is test"), key='this is test')
    print decrypt(datas, 'key')
