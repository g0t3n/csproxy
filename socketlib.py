#!/usr/bin/env python2
#coding:utf-8
import encrypt

from struct import unpack
import traceback
import socket,select
# 注意，由于仅用两字节表示data长度，
# send_all ,recv_all 最大接受data长度是 65534,
__DEBUG__ = True

#encrypt = rc4.rc4()
def raw_send_all(sock, data):
    # 再实际情况往往出现发送栈太小，一次send不完全，so写个简单的 raw_send_all
    # 来再次发送
    bytes_sent = 0
    while True:
        try:
            r = sock.send(data[bytes_sent:])
        except:
            return False
        if r < 0:
            print "can't send all data?"
            return False
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent
    #print "datas : %s" % (repr(data) if len(data) < 20 else repr(data[0:20]))

def raw_recv_all(sock, length):
    data = sock.recv(length)
    if len(data) != length:
        # try again and in case block socket
        data += sock.recv(length - len(data))
    return data

def recv_all(sk, debug=None):
    data_recv = ''
    try:
        datalen = sk.recv(2)
        if len(datalen) == 0:
            # socket close...
            #print "datalen len is %d but not 2" % repr(datalen)
            return None
        datalen = unpack(">H", datalen)[0]
    except TypeError:
        print "socketlib::struct.unpack error, datalen is %s" % repr(datalen)
        #raise Exception,"socketlib::recv_all error"
        return None
    except socket.error:
        #print traceback.format_exc()
        #raise Exception,"socketlib: recv_all error"
        print "socket recv error"#: %s:%s" % sk.getpeername()
        return None
    while datalen > 0:
        try:
            tmp_data = sk.recv(datalen)
            if len(tmp_data) == 0:
                print "recv all error: broken pipe, local %s:%s, peer %s:%s" \
                        % (sk.getsockname(),sk.getpeername())
                return None
            data_recv +=  tmp_data
        except:
            print "recv all error, connect reset by peer,plz check me"
            return None
        datalen -= len(data_recv)
        #data_recv += data_recv
    return data_recv

def send_all(sk, data, debug=None):
    if len(data) > 65534:
        print "shit, send_all only support data len less then 65535"
        print "出现这情况的话，就要继续改包结构了。。"
    datalen = "%04x" % len(data)
    #sk.send(str(datalen))
    try:
        if not raw_send_all(sk, datalen.decode('hex') + data):
            return None
    except:
        print "[-] oop,send all error,this may remote socket close..check me "
        return None
    return True

def trans_data(cli_socket, dst_socket, sec_key, timeout=1200, \
                                            maxtimeout=36000, tick=1):
        timecnt = timeout
        while True:
            timecnt -= tick
            (rlist, wlist, e) = select.select((cli_socket, dst_socket), [], [], timecnt)
            #for i in rlist:
            if e or (timecnt == 0):
                if e:
                    print "e is %s" % e
                else:
                    print "connect timeout"
                break
            if cli_socket in rlist:
                data = recv_all(cli_socket, debug=True)
                if data == None:
                    # 可能情况
                    # recv len 0 : socks close
                    # connect reset by peer
                    break
                data = encrypt.decrypt(data, key=sec_key)
                #print "cli send this data: %s" % repr(data)
                if not raw_send_all(dst_socket, data):
                    break
                timcnt = maxtimeout
            if dst_socket in rlist:
                try:
                    data = dst_socket.recv(1024)   # wait to modify
                except:
                    print "recv reset by peer without getpeername"#": %s" % dst_socket.getpeername()
                    break
                if not data:
                    break
                data = encrypt.encrypt(data, key=sec_key)
                if not send_all(cli_socket, data):
                    print "[X] cli_socket send all error"
                    break
                #sendlen = cli_socket.send(data)
                #if sendlen != len(data):
                #    raise Exception, "cli_socket fail send all data"
                timcnt = timeout
        cli_socket.close()
        dst_socket.close()

