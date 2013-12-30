#!/bin/env python2
#coding:utf-8

import encrypt
#import socketlib
from socketlib import *

import struct
import socket,os
import select
import traceback
import threading
import time

__DEBUG__ = True
__DEBUG_DEEP__ = False

#encrypt = rc4.rc4()
#logger = logger
class socks5server:
    def __init__(self, ip='public_ip', port=53):

        self.bind_ip = ip
        self.bind_port = port
        self.server_for_ever(ip, port)

    def server_for_ever(self, ip, port):
        ser_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ser_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #if __DEBUG__:
        print "[*] init success: binding %s:%s" % (ip, port)
        print "if client can't connect,u better check socket /proc/%s/fd/" % os.getpid()
        ser_sock.bind((ip, port))
        ser_sock.listen(2000)
        while True:
            cli, addrinfo = ser_sock.accept()
            #if __DEBUG__:
            #    print "[*] get connect from %s:%s" % (addrinfo[0], addrinfo[1])
            p = threading.Thread(target=self.handler_cli, args=(cli,))
            p.setDaemon(True)
            p.start()
        # nerver reach here
    #@profile
    def handler_cli(self, cli_socket):
        dst_addr = dst_port = 0
        try:
            rc4_key = raw_recv_all(cli_socket,4) #!!!FIXME,改为 assert 4个byte, is_socks_request 也一样
            if len(rc4_key) != 4:
                print "rc4_key len != 4"
                raise Exception
            #if  __DEBUG_DEEP__:
            #    print "rc4_key is %s, len is %d" % (repr(rc4_key), len(rc4_key))
            # handshake one
            if not self.is_socks_request(cli_socket, rc4_key):
                raise Exception
            # ack handshake one success
            req = '\x05\x00'
            #print ""
            if not send_all(cli_socket, encrypt.encrypt(req, key=rc4_key)):
                raise Exception
            # handshake two
            addrs = self.get_remote_addr(cli_socket, rc4_key)
            if not addrs:
                raise Exception
            (dst_addr, dst_port) = addrs
        except:
            if __DEBUG__:
                print traceback.format_exc()
            cli_socket.close()
            return
        #if __DEBUG__:
            #print " got foreign %s:%s" % (dst_addr, dst_port)
        dst_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        #import IPython;IPython.embed()
        try:
            dst_socket.connect((dst_addr, dst_port))
            data = '\x05\x00\x00\x01'+socket.inet_aton(self.bind_ip) \
                                    +struct.pack('>H', int(self.bind_port))
            # cli_socket.send(encrypt.encrypt(data, key=rc4_key))
            send_all(cli_socket, encrypt.encrypt(data, key=rc4_key))
        except:
            #cli_socket.send('\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')  # 失败
            print "false to connect to target %s:%s" % (dst_addr, dst_port)
            dst_socket.close(); cli_socket.close()
            return
        # socketlib.trans_data()
        trans_data(cli_socket, dst_socket, rc4_key)

    #@profile
    def is_socks_request(self, cli_socket, rc4_key):
        #为了 rc4,硬编码
        data = raw_recv_all(cli_socket, 5)[2:]
        #data = cli_socket.recv(5)[2:]
        #print "debug: data is %s" % repr(data)
        plain_data = encrypt.decrypt(data, key=rc4_key)
        #if __DEBUG_DEEP__:
        #    print "handshake one: recv data (decrypt): %s" % repr(plain_data)
        if plain_data[0] != '\x05':
            #cli_socket.send('HTTP/1.1 404 Not Found\r\nETag: "6t7yu7"\r\n\r\n')
            cli_socket.close()
            if __DEBUG__:
                print "[*] protocol mismatch.. check client"

            raise Exception('protocol mismatch')                # 是否会 raise 到最外
            return False
        if plain_data[1] != '\x01' and plain_data[2] != '\x00':
            if __DEBUG__:
                print "[*] not support auth.. check client"
            cli_socket.close()
            raise Exception('not support auth..')
            return False
        return True

    #@profile
    def get_remote_addr(self, cli_socket, rc4_key):
        # 由于使用了 socketlib, 第一个字符为数据长度，但这与socks的冲突了，所以这里硬编码下
        crypt_data = raw_recv_all(cli_socket, 6)
        if len(crypt_data) != 6:
            return
        crypt_data = crypt_data(6)[2:]
        #crypt_data = cli_socket.recv(6)[2:]
        #print "crypt_data : %s" % repr(crypt_data)
        data = encrypt.decrypt(crypt_data, key=rc4_key)
        #if __DEBUG_DEEP__:
        #    print "debug: get_remote_addr recv len:%s, (decrypt): %s" % (repr(data), len(data))
        if data[0:3] != '\x05\x01\x00':
            cli_socket.close()
            print 'protocol mismatch'
            return False
        #print "here?"
        if data[3] == '\x01':  # inet_ntoa ,ntohs
            crypt_data += cli_socket.recv(4 + 2)
            data = encrypt.decrypt(crypt_data, rc4_key)
            dst_addr = socket.inet_ntoa(data[-6:-2])
            #dst_port = int(socket.ntohs(data[-2:]))
            dst_port = int(struct.unpack('>H', data[-2:])[0])
        elif data[3] == '\x03':
            crypt_data += cli_socket.recv(1)
            data = encrypt.decrypt(crypt_data, key=rc4_key)
            addr_len = ord(data[4])
            crypt_data += cli_socket.recv(addr_len + 2)   # domain + port
            data = encrypt.decrypt(crypt_data, key=rc4_key)

            dst_addr = socket.gethostbyname(data[5:-2]) # 保证
            dst_port = int(struct.unpack('>H', data[-2:])[0])
            if __DEBUG_DEEP__:
                print "data : (%s)%s:%s " % (data[5:-2], dst_addr, dst_port)
        else:
            if __DEBUG__:
                raise Exception('-,- no addr? ')
            return False
        #somedata = cli_socket.recv(10)
        #if len(somedata) >0:
        #    print "still some data?? %s" % somedata
        return dst_addr, dst_port

# test
if __name__ == '__main__':
    c = socks5server(ip='192.168.92.129')
    #c = socks5server(ip='58.64.129.115')

