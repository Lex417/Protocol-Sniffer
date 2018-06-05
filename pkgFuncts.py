# Librerias
import socket, struct, binascii
#################################################

#Clase para iniciarse a sí mismo en la clase sniffer.py
class unpack:
 def __cinit__(self):
  self.data=None

 # Se obtiene el Header Ethernet
 def eth_header(self, data):
  storeobj=data #Se almacena localmente para utilizar la funcion unpack
  storeobj=struct.unpack("!6s6sH",storeobj)#se almacea en array
  destination_mac=binascii.hexlify(storeobj[0])#Funcion para obtener la mac(pos 1)
  source_mac=binascii.hexlify(storeobj[1])#El source se encuentra en la pos 2
  eth_protocol=storeobj[2]   #el protocolo en la posición siguiente
  data={"Destination Mac":destination_mac, 
  "Source Mac":source_mac,      #Python dict con los 3 valores
  "Protocol":eth_protocol}
  return data

 # Se extrae el Header de tipo ICMP
 #El formato ICMP contiene type, code y checksum
 def icmp_header(self, data):
  icmph=struct.unpack('!BBH', data) #Se convierte en estructura para unpack
  icmp_type = icmph[0] #Se obtienen las primeras 3 posiciones del array
  code = icmph[1]
  checksum = icmph[2]
  data={'ICMP Type':icmp_type,
  "Code":code,
  "CheckSum":checksum} #dict con la información
  return data

 # Extracción de Header UDP
 #Protocolo tiene Source Port, Destination port, Length y Checksum
 def udp_header(self, data):
  storeobj=struct.unpack('!HHHH', data) #Estructura para unpack
  source_port = storeobj[0] 
  dest_port = storeobj[1] #Se almacenan en este orde en un array de 4 posiciones
  length = storeobj[2]
  checksum = storeobj[3]
  data={"Source Port":source_port,
  "Destination Port":dest_port, #Se crea el diccionario con la información
  "Length":length,
  "CheckSum":checksum}
  return data

 # Extracción de Header IP
 #Es el mas largo puesto que cuenta con version, traffic class, flow label,
 #Length, Next header, hop limit, source address y destination address
 def ip_header(self, data):
  #Se convierte en struct y se almacenan los 10 valores en un array
  storeobj=struct.unpack("!BBHHHBBH4s4s", data)
  _version=storeobj[0]
  _tos=storeobj[1]
  _total_length =storeobj[2]
  _identification =storeobj[3]
  _fragment_Offset =storeobj[4]
  _ttl =storeobj[5]
  _protocol =storeobj[6]
  _header_checksum =storeobj[7]
  _source_address =socket.inet_ntoa(storeobj[8])
  _destination_address =socket.inet_ntoa(storeobj[9])

  data={'Version':_version,
  "Tos":_tos,
  "Total Length":_total_length,
  "Identification":_identification,  #diccionario de python con toda la información
  "Fragment":_fragment_Offset,
  "TTL":_ttl,
  "Protocol":_protocol,
  "Header CheckSum":_header_checksum,
  "Source Address":_source_address,
  "Destination Address":_destination_address}
  return data

 # Extrae el Header de tipo TCP
 def tcp_header(self, data):
  storeobj=struct.unpack('!HHLLBBHHH',data)
  _source_port =storeobj[0]
  _destination_port  =storeobj[1]
  _sequence_number  =storeobj[2]
  _acknowledge_number  =storeobj[3]
  _offset_reserved  =storeobj[4]
  _tcp_flag  =storeobj[5]
  _window  =storeobj[6]
  _checksum  =storeobj[7]
  _urgent_pointer =storeobj[8]
  data={"Source Port":_source_port,
  "Destination Port":_destination_port,
  "Sequence Number":_sequence_number,
  "Acknowledge Number":_acknowledge_number,
  "Offset & Reserved":_offset_reserved,
  "Tcp Flag":_tcp_flag,
  "Window":_window,
  "CheckSum":_checksum,
  "Urgent Pointer":_urgent_pointer
  }
  return data

# Para formatear las direcciones MAC
def mac_formater(a):
 b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
 return b
#Se obtiene y valida el host
def get_host(q):
 try:
  k=socket.gethostbyaddr(q)
 except:
  k='Unknown'
 return k
