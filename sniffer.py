
# import modules
import socket
import struct
import binascii
import os
import pkgFuncts

# print author details on terminal

# if operating system is windows
if os.name == "nt":
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("15.152.90.188",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

# create loop
while True:

    # Capture packets from network
    pkt=s.recvfrom(65565)

    # extract packets with the help of pye.unpack class
    unpack=pkgFuncts.unpack()

    print ("\n\n===&gt;&gt; [+] ------------ Ethernet Header----- [+]")

    # print data on terminal
    for i in unpack.eth_header(pkt[0][0:14]).items():
        a,b=i
        print ("{} : {} | ".format(a,b),)
    print ("\n===&gt;&gt; [+] ------------ IP Header ------------[+]")
    for i in unpack.ip_header(pkt[0][14:34]).items():
        a,b=i
        print ("{} : {} | ".format(a,b),)
    print ("\n===&gt;&gt; [+] ------------ Tcp Header ----------- [+]")
    for  i in unpack.tcp_header(pkt[0][34:54]).items():
        a,b=i
        print ("{} : {} | ".format(a,b),)
