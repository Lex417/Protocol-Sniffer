
# Se importan los modulos
import socket
import struct
import binascii
import os
import pkgFuncts
import time

#Para Widows se debe asignar el socket de forma más detallada
#se crea el socket con el uso de la libreria socket
#El socket es INET RAW
s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
s.bind(("15.152.90.188",0)) #se le hace un bind al socket con la ip
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1) #Se le asignan configuraciones extra de compatibilidad
s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

# Loop
while True:

    # Con este comando recvfrom se capturan los paquetes que están pasando
    #por la red continuamente 
    pkt=s.recvfrom(65565)

    # La clas se inicia a sí mismo y se almacena como objeto en este scope
    unpack=pkgFuncts.unpack()
    
    time.sleep(3)
    print ("\n\n===>> [+] ------------ Ethernet Header----- [+]")
    #De uno en uno hasta el final de los items en cada protocolo de header
    #Se imprimen los valores, de 0 a 14 y se llama al método por cada protocolo
    for i in unpack.eth_header(pkt[0][0:14]).items():

        a,b=i
        time.sleep(0.4)
        print ("| {} : {} | ".format(a,b)),

    time.sleep(3)
    print ("\n===>> [+] ------------ IP Header ------------[+]")

    for i in unpack.ip_header(pkt[0][14:34]).items():

        a,b=i
        time.sleep(0.4)
        print ("| {} : {} | ".format(a,b)),

    time.sleep(3)
    print ("\n===>> [+] ------------ Tcp Header ----------- [+]")

    for  i in unpack.tcp_header(pkt[0][34:54]).items():

        a,b=i
        time.sleep(0.4)
        print ("| {} : {} | ".format(a,b)),
  
