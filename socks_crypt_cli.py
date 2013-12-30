#!/usr/bin/env python2
#coding:utf-8

import encrypt
import socketlib
from socketlib import *
#import logger

import socket,select
import threading,traceback

def random_string(length):
    import M2Crypto.Rand
    return M2Crypto.Rand.rand_bytes(length)

__DEBUG__ = True
__DEBUG_DEEP__ = False
config = {
        'lport' : 1080,
        'dst_host' : '58.64.129.115',
        #'dst_host' : '192.168.92.129',
        'dst_port' : 53,
        }

def listen_socket():
    lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsk.bind(('0.0.0.0', int(config['lport'])))
    lsk.listen(2000)
    print "connect to %s:%s ,local listen to %s" % (config['dst_host'], config['dst_port'], config['lport'])
    while True:
        cli, addrinfo = lsk.accept()
        dsk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            dsk.connect((config['dst_host'], config['dst_port']))
        except:
            print "[X]can't connect to proxy host..."
            raw_input("type C-c to end this ")

        if __DEBUG_DEEP__:
            print "[*] dsk local port %s:%s" % (dsk.getsockname())
        if __DEBUG__:
            p = threading.Thread(target=trans_data, args=(cli, dsk, addrinfo))
        else:
            p = threading.Thread(target=trans_data, args=(cli, dsk, None))
        p.setDaemon(True)
        p.start()
        #import time;time.sleep(10)

#@profile
def trans_data(cli_socket, dst_socket, dst_data=None):
    # 为了调试方便，看什么类型的地址会触发 cli socket close
    sock_list = (cli_socket, dst_socket)
    #encrypt = rc4.rc4()
    sec_key = random_string(4)
    #sec_key = "testky"
    if not raw_send_all(dst_socket, sec_key):
        print "[-] (sec_key send): warning! send len != data len.."
        dst_socket.close();return

    socketlib.trans_data(dst_socket, cli_socket, sec_key, )
    #print "rc4 key is %s, len is %d" % (repr(sec_key),len(sec_key))
    #print "success , start to trans data"

if __name__ == '__main__':
    listen_socket()
